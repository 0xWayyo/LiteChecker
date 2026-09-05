"""Network labels come only from a bounded, direct public-IP lookup."""

from __future__ import annotations

import asyncio
import gzip

import httpx
import pytest


@pytest.mark.asyncio
async def test_lookup_keeps_org_evidence_and_sends_only_a_public_metadata_request(monkeypatch):
    from litechecker import network_identity

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={
            "ip": "8.8.8.8",
            "hostname": "dns.google",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.4056,-122.0775",
            "org": "  AS15169 Google LLC  ",
            "timezone": "America/Los_Angeles",
            "readme": "https://ipinfo.io/missingauth",
        })

    identity = await network_identity.lookup_network_identity(
        transport=httpx.MockTransport(handler)
    )

    assert identity == network_identity.NetworkIdentity(
        provider="AS15169 Google LLC", city="Mountain View", country="US"
    )
    assert len(requests) == 1
    request = requests[0]
    assert str(request.url) == "https://ipinfo.io/json"
    assert request.method == "GET"
    assert request.content == b""
    assert request.headers["accept-encoding"] == "identity"
    assert "authorization" not in request.headers
    assert "cookie" not in request.headers


@pytest.mark.asyncio
async def test_lookup_bypasses_environment_proxy(monkeypatch):
    from litechecker import network_identity

    monkeypatch.setenv("HTTPS_PROXY", "http://private-proxy.example:3128")

    def transport_factory(**kwargs):
        if kwargs.get("proxy") is not None:
            raise AssertionError("IP attribution must use the direct route")
        return httpx.MockTransport(lambda request: httpx.Response(
            200, json={"ip": "8.8.8.8", "org": "Direct Network"}
        ))

    monkeypatch.setattr("httpx._client.AsyncHTTPTransport", transport_factory)
    assert await network_identity.lookup_network_identity() == network_identity.NetworkIdentity(
        provider="Direct Network"
    )


@pytest.mark.asyncio
async def test_valid_streamed_response_is_parsed():
    from litechecker import network_identity

    class ValidStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'{"ip": "8.8.8.8", '
            yield b'"org": "Streamed Network"}'

    assert await network_identity.lookup_network_identity(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=ValidStream()))
    ) == network_identity.NetworkIdentity(provider="Streamed Network")


@pytest.mark.asyncio
@pytest.mark.parametrize(("payload", "expected"), [
    ({"ip": "8.8.8.8", "org": 'AS207810 "Virus Net" LLC'}, 'AS207810 "Virus Net" LLC'),
    ({"ip": "8.8.8.8", "org": "Провайдер Грузии"}, "Провайдер Грузии"),
    ({"ip": "8.8.8.8", "org": "A" * 80}, "A" * 39 + "…"),
    ({"ip": "2001:4860:4860::8888", "org": "IPv6 Network"}, "IPv6 Network"),
    ({"ip": "8.8.8.8", "org": "Network", "bogon": False}, "Network"),
    ({"ip": "8.8.8.8", "org": "Network", "bogon": True}, None),
    ({"ip": "8.8.8.8", "org": "Network", "bogon": "false"}, None),
    ({"ip": "8.8.8.8", "org": "Network", "error": {"title": "Rate limit exceeded"}}, None),
    ({"ip": "8.8.8.8", "org": ""}, None),
    ({"ip": "8.8.8.8", "org": None}, None),
    ({"ip": "8.8.8.8", "org": ["Wrong Network"]}, None),
    ({"ip": "8.8.8.8", "org": "Network\nOther"}, None),
    ({"ip": "8.8.8.8", "org": "Network\u202eOther"}, None),
    ({"ip": "8.8.8.8", "org": "A" * 257}, None),
    ({"ip": "8.8.8.8", "org": "   "}, None),
    ({"ip": "8.8.8.8", "org": "---"}, None),
    ({"ip": "8.8.8.8", "org": "unknown"}, None),
    ({"ip": "8.8.8.8", "org": "N/A"}, None),
    ({"ip": "8.8.8.8", "asn": "AS15169"}, None),
    ({"ip": "8.8.8.8"}, None),
    ({"ip": "invalid", "org": "Network"}, None),
    ({"ip": "127.0.0.1", "org": "Network"}, None),
    ({"ip": "192.168.1.1", "org": "Network"}, None),
    ({"ip": "100.64.0.1", "org": "Network"}, None),
    ({"ip": "192.0.2.1", "org": "Network"}, None),
    ({"ip": "224.0.0.1", "org": "Network"}, None),
    ({"ip": "::1", "org": "Network"}, None),
    ({"ip": "ff02::1", "org": "Network"}, None),
    ({"ip": "2001:4860:4860::8888%en0", "org": "Network"}, None),
    ({"ip": 134744072, "org": "Network"}, None),
    ({"ip": ["8.8.8.8"], "org": "Network"}, None),
    ({"org": "Network"}, None),
    ({}, None),
    ([], None),
])
async def test_lookup_validates_provider_data(payload, expected):
    from litechecker import network_identity

    identity = await network_identity.lookup_network_identity(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
    )
    assert (identity.provider if identity else None) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(("payload", "expected"), [
    ({"ip": "8.8.8.8", "city": "Yerevan", "country": "AM"}, (None, "Yerevan", "AM")),
    ({"ip": "8.8.8.8", "org": [], "city": "Tbilisi"}, (None, "Tbilisi", None)),
    ({"ip": "8.8.8.8", "org": "Network", "city": ""}, ("Network", None, None)),
    ({"ip": "8.8.8.8", "org": "Network", "city": ["Wrong City"]}, ("Network", None, None)),
    ({"ip": "8.8.8.8", "org": "Network", "city": "City\nOther"}, ("Network", None, None)),
    ({"ip": "8.8.8.8", "org": "Network", "city": "City\u202eOther"}, ("Network", None, None)),
    ({"ip": "8.8.8.8", "org": "Network", "city": "Unknown"}, ("Network", None, None)),
    ({"ip": "8.8.8.8", "org": "Network", "city": "C" * 257}, ("Network", None, None)),
    ({"ip": "8.8.8.8", "city": "  São Paulo  ", "country": "BR"}, (None, "São Paulo", "BR")),
    ({"ip": "8.8.8.8", "city": "Yerevan", "country": "ARM"}, (None, "Yerevan", None)),
    ({"ip": "8.8.8.8", "city": "Yerevan", "country": ["AM"]}, (None, "Yerevan", None)),
    ({"ip": "8.8.8.8", "city": "Yerevan", "country": "AM\n"}, (None, "Yerevan", None)),
    ({"ip": "127.0.0.1", "city": "Wrong City", "country": "US"}, None),
    ({"ip": "8.8.8.8", "city": "Wrong City", "bogon": True}, None),
])
async def test_city_country_and_provider_are_validated_independently(payload, expected):
    from litechecker import network_identity

    identity = await network_identity.lookup_network_identity(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
    )
    assert ((identity.provider, identity.city, identity.country) if identity else None) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [
    httpx.Response(503),
    httpx.Response(429),
    httpx.Response(200, content=b"not JSON"),
    httpx.Response(200, content=b"\xff"),
    httpx.Response(200, json={"ip": "8.8.8.8", "org": "Network"}, headers={"content-length": "9000"}),
    httpx.Response(200, content=gzip.compress(b'{"ip": "8.8.8.8", "org": "Network"}'), headers={"content-encoding": "gzip"}),
])
async def test_failed_or_unsafe_http_response_omits_network(response):
    from litechecker import network_identity

    assert await network_identity.lookup_network_identity(
        transport=httpx.MockTransport(lambda request: response)
    ) is None


@pytest.mark.asyncio
async def test_lookup_does_not_follow_redirects():
    from litechecker import network_identity

    requests = []

    def handler(request):
        requests.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://redirect.example/"})

    assert await network_identity.lookup_network_identity(
        transport=httpx.MockTransport(handler)
    ) is None
    assert requests == ["https://ipinfo.io/json"]


@pytest.mark.asyncio
async def test_streamed_response_is_bounded_even_without_content_length():
    from litechecker import network_identity

    class OversizedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b" " * 8192
            yield b" "
            raise AssertionError("must stop after exceeding response limit")

    assert await network_identity.lookup_network_identity(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=OversizedStream()))
    ) is None


@pytest.mark.asyncio
async def test_total_lookup_timeout_includes_slow_body(monkeypatch):
    from litechecker import network_identity

    monkeypatch.setattr(network_identity, "_LOOKUP_TIMEOUT_SECONDS", 0.02)

    class StalledStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'{"ip":'
            await asyncio.Event().wait()

    result = await asyncio.wait_for(network_identity.lookup_network_identity(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=StalledStream()))
    ), timeout=1)
    assert result is None


@pytest.mark.asyncio
async def test_transport_failure_does_not_escape_lookup():
    from litechecker import network_identity

    def handler(request):
        raise httpx.ConnectError("network unavailable", request=request)

    assert await network_identity.lookup_network_identity(
        transport=httpx.MockTransport(handler)
    ) is None


@pytest.mark.asyncio
async def test_cancellation_propagates_from_lookup():
    from litechecker import network_identity

    async def handler(request):
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await network_identity.lookup_network_identity(transport=httpx.MockTransport(handler))


def test_display_name_states_egress_evidence_and_has_no_invented_fallback():
    from litechecker import network_identity

    assert network_identity.network_display_name("work-mac (macOS)", "Network") == (
        "work-mac (macOS) · сеть по IP: Network"
    )
    assert network_identity.network_display_name("work-mac (macOS)", None) == "work-mac (macOS)"
    assert network_identity.network_display_name("work-mac (macOS)", "bad\nnetwork") == "work-mac (macOS)"
    assert len(network_identity.network_display_name("a" * 128, "b" * 256)) <= 128


def test_city_display_marks_ip_attribution_and_falls_back_without_guessing():
    from litechecker.network_identity import NetworkIdentity, network_display_city

    fallback = "Город не определён"
    assert network_display_city(fallback, NetworkIdentity(city="Yerevan", country="AM")) == "Yerevan, AM (по IP)"
    assert network_display_city(fallback, NetworkIdentity(city="Yerevan")) == "Yerevan (по IP)"
    assert network_display_city(fallback, NetworkIdentity(provider="Network")) == fallback
    assert network_display_city(fallback, NetworkIdentity(city="bad\ncity")) == fallback
    assert network_display_city(fallback, None) == fallback
    assert len(network_display_city(fallback, NetworkIdentity(city="C" * 256, country="GE"))) <= 128
