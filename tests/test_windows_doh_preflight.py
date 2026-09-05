"""Windows trial preflight must use the bound DoH/SOCKS path before measuring."""

from __future__ import annotations

import asyncio
import base64
import json
import ssl
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import certifi
import dns.message
import dns.rdatatype
import dns.rrset
import h11
import pytest
import trustme

from litechecker.models import AgentReport, ProbeResult, ProbeStage, ResultStatus
from litechecker.windows_network import WindowsDirectNetwork


_FIXTURE_EXIT = "9.9.9.9"


def _report(agent_id: str) -> AgentReport:
    return AgentReport(
        event_id=f"{agent_id}:fixture:1",
        agent_id=agent_id,
        boot_id="fixture",
        sequence=1,
        observed_at=datetime(2026, 9, 6, tzinfo=UTC),
        duration_ms=1,
        control_status=ResultStatus.UP,
        results=[
            ProbeResult(
                target_id="fixture-target",
                label="Fixture",
                address="example.com",
                port=443,
                status=ResultStatus.UP,
                stage=ProbeStage.E2E,
            )
        ],
    )


@asynccontextmanager
async def _bound_https_fixture(tmp_path, *, confirm_exit: bool):
    authority = trustme.CA()
    certificate = authority.issue_cert("cloudflare-dns.com", "ipinfo.io")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate.configure_cert(server_context)
    ca_file = tmp_path / "fixture-ca.pem"
    authority.cert_pem.write_to_path(ca_file)

    requests: list[tuple[str, str]] = []
    errors: list[BaseException] = []
    handlers: set[asyncio.Task] = set()

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        handlers.add(task)
        connection = h11.Connection(h11.SERVER)
        try:
            request = None
            while True:
                event = connection.next_event()
                if event is h11.NEED_DATA:
                    data = await reader.read(4096)
                    if not data:
                        raise EOFError("fixture request ended before EndOfMessage")
                    connection.receive_data(data)
                    continue
                if isinstance(event, h11.Request):
                    request = event
                    continue
                if isinstance(event, h11.EndOfMessage):
                    break

            assert request is not None
            headers = {key.decode("ascii").lower(): value.decode("ascii") for key, value in request.headers}
            host = headers["host"]
            target = request.target.decode("ascii")
            requests.append((host, target))

            if host == "cloudflare-dns.com":
                encoded = parse_qs(urlsplit(target).query)["dns"][0]
                query = dns.message.from_wire(
                    base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
                )
                assert str(query.question[0].name) == "ipinfo.io."
                answer = dns.message.make_response(query)
                if query.question[0].rdtype == dns.rdatatype.A:
                    answer.answer.append(
                        dns.rrset.from_text("ipinfo.io.", 30, "IN", "A", _FIXTURE_EXIT)
                    )
                body = answer.to_wire()
                media_type = "application/dns-message"
            else:
                assert host == "ipinfo.io" and target == "/json"
                payload = {"ip": _FIXTURE_EXIT} if confirm_exit else {"error": "fixture"}
                body = json.dumps(payload).encode("ascii")
                media_type = "application/json"

            writer.write(
                connection.send(
                    h11.Response(
                        status_code=200,
                        headers=[
                            ("Content-Type", media_type),
                            ("Content-Length", str(len(body))),
                            ("Connection", "close"),
                        ],
                    )
                )
            )
            writer.write(connection.send(h11.Data(data=body)))
            writer.write(connection.send(h11.EndOfMessage()))
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except BaseException as exc:
            errors.append(exc)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError, ssl.SSLError):
                pass
            handlers.discard(task)

    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=server_context)
    port = int(server.sockets[0].getsockname()[1])
    try:
        yield port, ca_file, requests, errors
    finally:
        server.close()
        await server.wait_closed()
        if handlers:
            await asyncio.gather(*handlers, return_exceptions=True)


async def _run_preflight(tmp_path, monkeypatch, *, confirm_exit: bool):
    from litechecker import direct_check
    from litechecker.windows_trial import load_settings, save_configuration

    save_configuration(tmp_path, {"subscription_url": "https://subscription.invalid/test"})
    settings = load_settings(tmp_path, "xray.exe")
    network = WindowsDirectNetwork(
        "Ethernet fixture",
        14,
        ("192.168.50.10",),
        ("192.168.50.1",),
        1,
        "fixture-guid",
        14,
        0,
    )
    events: list[str] = []
    dials: list[tuple[str, int]] = []
    original_lookup_exit = direct_check.lookup_exit

    async with _bound_https_fixture(tmp_path, confirm_exit=confirm_exit) as fixture:
        port, ca_file, requests, server_errors = fixture
        monkeypatch.setattr(certifi, "where", lambda: str(ca_file))
        monkeypatch.setattr(WindowsDirectNetwork, "_validate_interface", lambda self: None)

        async def connect_loopback(self, address, target_port, *, infrastructure=False):
            assert self is network
            assert target_port == 443 and not infrastructure
            dials.append((address, target_port))
            return await asyncio.open_connection("127.0.0.1", port)

        async def isolated_lookup_exit(*, proxy_url=None, transport=None):
            if proxy_url is None:
                return direct_check.ExitObservation("8.8.8.8")
            return await original_lookup_exit(proxy_url=proxy_url, transport=transport)

        async def measured(agent, dependencies):
            assert agent is settings.agent
            assert dependencies.fetcher is not None
            assert [host for host, _ in requests] == [
                "cloudflare-dns.com",
                "cloudflare-dns.com",
                "ipinfo.io",
            ]
            events.append("measure")
            return _report(settings.agent.agent_id)

        monkeypatch.setattr(WindowsDirectNetwork, "_connect_ip", connect_loopback)
        monkeypatch.setattr(direct_check, "lookup_exit", isolated_lookup_exit)
        monkeypatch.setattr(direct_check, "measure_cycle", measured)

        result = await direct_check.run_trial(
            settings,
            network_factory=lambda: asyncio.sleep(0, result=network),
            platform_label="Windows · test",
        )

    return result, settings, events, dials, requests, server_errors


@pytest.mark.asyncio
async def test_unconfirmed_bound_exit_stops_before_measurement_and_observation(tmp_path, monkeypatch):
    result, settings, events, dials, requests, server_errors = await _run_preflight(
        tmp_path, monkeypatch, confirm_exit=False
    )

    assert not result.available
    assert result.report is None
    assert events == []
    assert not (settings.state_dir / "last-observation.json").exists()
    assert dials == [("1.1.1.1", 443), ("1.1.1.1", 443), (_FIXTURE_EXIT, 443)]
    assert [host for host, _ in requests] == [
        "cloudflare-dns.com",
        "cloudflare-dns.com",
        "ipinfo.io",
    ]
    assert server_errors == []


@pytest.mark.asyncio
async def test_confirmed_bound_exit_measures_only_after_real_doh_preflight(tmp_path, monkeypatch):
    result, settings, events, dials, requests, server_errors = await _run_preflight(
        tmp_path, monkeypatch, confirm_exit=True
    )

    assert result.available
    assert result.report is not None
    assert events == ["measure"]
    assert (settings.state_dir / "last-observation.json").exists()
    assert dials == [("1.1.1.1", 443), ("1.1.1.1", 443), (_FIXTURE_EXIT, 443)]
    assert [host for host, _ in requests] == [
        "cloudflare-dns.com",
        "cloudflare-dns.com",
        "ipinfo.io",
    ]
    assert server_errors == []
