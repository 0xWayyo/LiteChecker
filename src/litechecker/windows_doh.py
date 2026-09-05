"""Explicit Windows DoH policy over the existing, strictly bound TCP backend.

No system DNS, HTTP proxy, redirect, alternate interface or plaintext fallback.
Adapter DNS remains a separate diagnostic, not the source of these answers.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import ssl

import certifi
import dns.exception
import dns.message
import dns.rdatatype
import h11

from .direct_network import DirectNetworkUnavailable, _dns_answers, _numeric


_TIMEOUT = 3
_BODY_LIMIT = 65535
_HEADER_LIMIT = 8192
_WIRE_LIMIT = 98304
_DOH_HOST = "cloudflare-dns.com"


def _tls_context():
    context = ssl.create_default_context(cafile=certifi.where())
    context.set_alpn_protocols(["http/1.1"])
    return context


async def request(network, address: str, hostname: str, path: str, *, accept: str) -> bytes:
    """One validated HTTPS GET to a numeric public IP; at most 3s + 0.25s close."""
    address = str(_numeric(address))
    # This is a control-path primitive, not an arbitrary URL fetcher.
    if not (
        (hostname == _DOH_HOST and path.startswith("/dns-query?dns=") and accept == "application/dns-message")
        or (hostname == "ipinfo.io" and path == "/json" and accept == "application/json")
    ):
        raise DirectNetworkUnavailable("direct_doh_invalid_request")
    writer = None
    try:
        async with asyncio.timeout(_TIMEOUT):
            network._validate_interface()
            reader, writer = await network._connect_ip(address, 443)
            await writer.start_tls(_tls_context(), server_hostname=hostname,
                                   ssl_handshake_timeout=_TIMEOUT)
            negotiated = writer.get_extra_info("ssl_object")
            if negotiated is not None and negotiated.selected_alpn_protocol() not in (None, "http/1.1"):
                raise DirectNetworkUnavailable("direct_doh_tls_protocol")
            network._validate_interface()
            connection = h11.Connection(h11.CLIENT, max_incomplete_event_size=_HEADER_LIMIT)
            writer.write(connection.send(h11.Request(method="GET", target=path, headers=[
                ("Host", hostname), ("Accept", accept),
                ("Accept-Encoding", "identity"), ("Connection", "close"),
            ])))
            writer.write(connection.send(h11.EndOfMessage()))
            await writer.drain()
            body = bytearray()
            wire_size = header_size = informational = 0
            received_response = False
            while True:
                event = connection.next_event()
                if event is h11.NEED_DATA:
                    data = await reader.read(4096)
                    wire_size += len(data)
                    if wire_size > _WIRE_LIMIT:
                        raise DirectNetworkUnavailable("direct_doh_response_too_large")
                    connection.receive_data(data)
                elif isinstance(event, (h11.Response, h11.InformationalResponse)):
                    header_size += sum(len(k) + len(v) + 4 for k, v in event.headers) + len(event.reason) + 16
                    if header_size > _HEADER_LIMIT:
                        raise DirectNetworkUnavailable("direct_doh_response_too_large")
                    if isinstance(event, h11.InformationalResponse):
                        informational += 1
                        if informational > 4 or event.status_code == 101:
                            raise DirectNetworkUnavailable("direct_doh_invalid_http")
                        continue
                    if event.status_code != 200:
                        raise DirectNetworkUnavailable("direct_doh_http_failed")
                    content_types = [v for k, v in event.headers if k == b"content-type"]
                    if len(content_types) != 1 or content_types[0].split(b";", 1)[0].strip().lower() != accept.encode():
                        raise DirectNetworkUnavailable("direct_doh_invalid_http")
                    if any(k == b"content-encoding" and v.lower() != b"identity" for k, v in event.headers):
                        raise DirectNetworkUnavailable("direct_doh_invalid_http")
                    if any(k == b"content-length" and int(v) > _BODY_LIMIT for k, v in event.headers):
                        raise DirectNetworkUnavailable("direct_doh_response_too_large")
                    received_response = True
                elif isinstance(event, h11.Data):
                    body.extend(event.data)
                    if len(body) > _BODY_LIMIT:
                        raise DirectNetworkUnavailable("direct_doh_response_too_large")
                elif isinstance(event, h11.EndOfMessage):
                    header_size += sum(len(k) + len(v) + 4 for k, v in event.headers)
                    if not received_response or header_size > _HEADER_LIMIT:
                        raise DirectNetworkUnavailable("direct_doh_invalid_http")
                    network._validate_interface()
                    return bytes(body)
                else:
                    raise DirectNetworkUnavailable("direct_doh_invalid_http")
    except DirectNetworkUnavailable:
        raise
    except ssl.SSLError as exc:
        raise DirectNetworkUnavailable("direct_doh_tls_failed") from exc
    except TimeoutError as exc:
        raise DirectNetworkUnavailable("direct_dns_timeout") from exc
    except (h11.ProtocolError, EOFError, ValueError, UnicodeError) as exc:
        raise DirectNetworkUnavailable("direct_doh_invalid_http") from exc
    except OSError as exc:
        raise DirectNetworkUnavailable("direct_doh_connection_failed") from exc
    finally:
        if writer is not None:
            writer.close()
            try:
                async with asyncio.timeout(0.25):
                    await writer.wait_closed()
            except (OSError, TimeoutError):
                pass


async def query(network, host: str, kind: dns.rdatatype.RdataType) -> list[str]:
    """RFC 8484 wireformat GET with fixed bootstrap and existing DNS safeguards."""
    network._validate_interface()
    families = {ipaddress.ip_address(value).version for value in network.source_addresses}
    if 4 in families:
        bootstrap = "1.1.1.1"
    elif 6 in families:
        bootstrap = "2606:4700:4700::1111"
    else:
        raise DirectNetworkUnavailable("interface_address_family_unavailable")
    if kind not in (dns.rdatatype.A, dns.rdatatype.AAAA):
        raise DirectNetworkUnavailable("direct_doh_invalid_request")
    try:
        question = dns.message.make_query(host.rstrip(".") + ".", kind, use_edns=False, id=0)
        encoded = base64.urlsafe_b64encode(question.to_wire()).rstrip(b"=").decode("ascii")
        wire = await request(network, bootstrap, _DOH_HOST, "/dns-query?dns=" + encoded,
                             accept="application/dns-message")
        answer = dns.message.from_wire(wire, ignore_trailing=False)
        return _dns_answers(question, answer)
    except (dns.exception.DNSException, EOFError, ValueError) as exc:
        raise DirectNetworkUnavailable("direct_dns_invalid_response") from exc
