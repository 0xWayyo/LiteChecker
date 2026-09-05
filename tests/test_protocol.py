from collections.abc import Iterable
from datetime import UTC, datetime

import httpx
import pytest

from litechecker.models import AgentReport, ResultStatus
from litechecker.protocol import CollectorClient, DeliveryError


AGENT_TOKEN = "lc_AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"


class RecordingTransport(httpx.AsyncBaseTransport):
    def __init__(self, outcomes: Iterable[httpx.Response | Exception]):
        self.outcomes = iter(outcomes)
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        self.requests.append(request)
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        outcome.request = request
        return outcome


class MustNotReadStream(httpx.AsyncByteStream):
    async def __aiter__(self):
        raise AssertionError("collector response body must not be buffered")
        yield b""  # pragma: no cover


@pytest.fixture
def report() -> AgentReport:
    return AgentReport(
        event_id="agent-1:boot-1:7",
        agent_id="agent-1",
        boot_id="boot-1",
        sequence=7,
        observed_at=datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
        control_status=ResultStatus.UP,
        duration_ms=23,
    )


@pytest.mark.asyncio
async def test_collector_client_sends_agent_bearer_and_same_event_on_retry(report):
    """Re-serializing or rebuilding a retry could change its idempotency payload."""
    transport = RecordingTransport(
        [httpx.ReadTimeout("late"), httpx.Response(202)]
    )
    sleeps: list[float] = []

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    client = CollectorClient(
        "https://collector.example/base",
        AGENT_TOKEN,
        transport=transport,
        sleep=sleep,
        jitter=lambda: 0.125,
    )

    result = await client.send(report)

    assert result.accepted is True
    assert result.duplicate is False
    assert result.attempts == 2
    assert transport.requests[0].headers["authorization"] == f"Bearer {AGENT_TOKEN}"
    assert transport.requests[0].content == transport.requests[1].content
    assert transport.requests[0].url == httpx.URL(
        "https://collector.example/base/v1/reports"
    )
    assert sleeps == [0.125]


@pytest.mark.asyncio
async def test_collector_client_accepts_duplicate_without_retry(report):
    """Treating collector duplicate responses as failures would retain delivered events."""
    transport = RecordingTransport([httpx.Response(200)])

    result = await CollectorClient(
        "https://collector.example", AGENT_TOKEN, transport=transport
    ).send(report)

    assert result.accepted is True
    assert result.duplicate is True
    assert result.attempts == 1
    assert len(transport.requests) == 1


@pytest.mark.asyncio
async def test_collector_client_does_not_buffer_response_body(report):
    """Reading an unbounded collector body would defeat delivery memory bounds."""
    transport = RecordingTransport(
        [httpx.Response(202, stream=MustNotReadStream())]
    )

    result = await CollectorClient(
        "https://collector.example", AGENT_TOKEN, transport=transport
    ).send(report)

    assert result.accepted is True
    assert result.attempts == 1


@pytest.mark.asyncio
async def test_collector_client_does_not_follow_redirects(report):
    """Following a redirect could disclose the bearer token to another origin."""
    transport = RecordingTransport(
        [httpx.Response(307, headers={"location": "https://attacker.invalid/steal"})]
    )

    with pytest.raises(DeliveryError) as raised:
        await CollectorClient(
            "https://collector.example", AGENT_TOKEN, transport=transport
        ).send(report)

    assert raised.value.error_code == "collector-http-307"
    assert len(transport.requests) == 1


def test_collector_client_requires_credential_free_https_base_url():
    """Accepting HTTP or URL credentials would weaken or accidentally expose authentication."""
    for url in (
        "http://collector.example",
        "https://user:pass@collector.example",
        "https://collector.example?token=private",
        "https://collector.example/#fragment",
    ):
        with pytest.raises(ValueError, match="collector URL"):
            CollectorClient(url, AGENT_TOKEN)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("url", "expected"),
    (
        ("http://localhost:8000", "http://localhost:8000/v1/reports"),
        ("http://127.0.0.1:8000/base", "http://127.0.0.1:8000/base/v1/reports"),
        ("http://[::1]:8000", "http://[::1]:8000/v1/reports"),
    ),
)
async def test_collector_client_allows_only_explicit_loopback_http(url, expected, report):
    """The development override must reach local collectors without weakening HTTPS defaults."""
    transport = RecordingTransport([httpx.Response(202)])

    result = await CollectorClient(
        url,
        AGENT_TOKEN,
        allow_insecure_loopback=True,
        transport=transport,
    ).send(report)

    assert result.accepted is True
    assert transport.requests[0].url == httpx.URL(expected)


@pytest.mark.parametrize(
    "url",
    (
        "http://collector.example",
        "http://0.0.0.0:8000",
        "http://[::]:8000",
        "http://localhost.evil:8000",
        "http://127.0.0.1.evil:8000",
        "http://2130706433:8000",
        "http://user@localhost:8000",
        "http://localhost:8000?next=https://example.invalid",
        "http://localhost:8000/#fragment",
    ),
)
def test_collector_client_loopback_override_rejects_host_and_url_tricks(url):
    """Text that merely starts with a loopback spelling must not bypass transport policy."""
    with pytest.raises(ValueError, match="collector URL"):
        CollectorClient(url, AGENT_TOKEN, allow_insecure_loopback=True)


def test_collector_client_https_does_not_require_development_override():
    """The local-development option must not become mandatory for secure production URLs."""
    CollectorClient("https://collector.example", AGENT_TOKEN)


@pytest.mark.parametrize(
    "token",
    ["secret", "lc_" + "a" * 43, "lc_А" + "b" * 42, "lc_short"],
)
def test_collector_client_requires_generated_header_safe_agent_token(token):
    """Agent and collector must enforce one strong bearer-token contract."""
    with pytest.raises(ValueError, match="agent token"):
        CollectorClient("https://collector.example", token)


@pytest.mark.asyncio
async def test_collector_client_rejects_oversized_body_before_network(report):
    """Removing the local cap would permit unexpectedly large reports to leave the agent."""
    transport = RecordingTransport([httpx.Response(202)])
    client = CollectorClient(
        "https://collector.example",
        AGENT_TOKEN,
        max_payload_bytes=32,
        transport=transport,
    )

    with pytest.raises(DeliveryError) as raised:
        await client.send(report)

    assert raised.value.error_code == "collector-payload-too-large"
    assert transport.requests == []


@pytest.mark.asyncio
async def test_collector_client_never_exposes_response_or_network_error_text(report):
    """Returning arbitrary upstream text could leak URLs, tokens, or collector response bodies."""
    response_transport = RecordingTransport(
        [httpx.Response(400, text="private-token and https://secret.example/path")]
    )
    with pytest.raises(DeliveryError) as response_error:
        await CollectorClient(
            "https://collector.example", AGENT_TOKEN, transport=response_transport
        ).send(report)

    request = httpx.Request("POST", "https://collector.example/v1/reports")
    network_transport = RecordingTransport(
        [
            httpx.ConnectError(
                "https://secret.example/?token=private", request=request
            ),
            httpx.ConnectError(
                "https://secret.example/?token=private", request=request
            ),
        ]
    )
    with pytest.raises(DeliveryError) as network_error:
        await CollectorClient(
            "https://collector.example", AGENT_TOKEN, transport=network_transport
        ).send(report)

    assert str(response_error.value) == "collector-http-400"
    assert str(network_error.value) == "collector-network"

    unexpected_transport = RecordingTransport(
        [
            RuntimeError("Bearer private and https://secret.invalid"),
            RuntimeError("Bearer private and https://secret.invalid"),
        ]
    )
    with pytest.raises(DeliveryError) as unexpected_error:
        await CollectorClient(
            "https://collector.example", AGENT_TOKEN, transport=unexpected_transport
        ).send(report)

    assert str(unexpected_error.value) == "collector-network"
