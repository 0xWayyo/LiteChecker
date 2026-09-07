"""Telegram styling preserves plain reports and survives actual delivery chunking."""

import json
from datetime import UTC, datetime

import pytest

from litechecker.collector.auth import AgentIdentity
from litechecker.collector.reporting import chunk_message, format_report
from litechecker.collector.telegram import TelegramClient
from litechecker.direct_check import ExitObservation
from litechecker.direct_reporting import format_direct, format_unavailable
from litechecker.models import ProbeResult, ProbeStage, ResultStatus
from test_direct_production_reporting import make_report
from test_telegram import FAKE_TOKEN, RecordingTransport, _ok


def styled_ranges(payload):
    """Decode Bot API offsets independently; invalid surrogate boundaries fail."""
    encoded = payload["text"].encode("utf-16-le")
    ranges = []
    end = 0
    for entity in payload.get("entities", []):
        start = entity["offset"] * 2
        stop = start + entity["length"] * 2
        assert end <= start < stop <= len(encoded)
        ranges.append((entity["type"], encoded[start:stop].decode("utf-16-le")))
        end = stop
    return ranges


async def deliver(chunks):
    transport = RecordingTransport([_ok() for _ in chunks])
    await TelegramClient(token=FAKE_TOKEN, chat_id="-1001234567890",
                         topic_id=42, transport=transport).send_chunks(chunks)
    payloads = [json.loads(request.content) for request in transport.requests]
    assert [p["text"] for p in payloads] == chunks
    assert all("parse_mode" not in p and p["message_thread_id"] == 42 for p in payloads)
    return payloads


@pytest.mark.asyncio
async def test_bot_payload_uses_utf16_offsets_after_non_bmp_emoji():
    payload, = await deliver(["🧪 LiteChecker\nID: dev"])
    assert payload.get("entities") == [
        {"type": "bold", "offset": 0, "length": 14},
        {"type": "blockquote", "offset": 15, "length": 7},
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("platform", ["Windows", "macOS", "Linux"])
@pytest.mark.parametrize("state", ["healthy", "failed", "unknown", "unavailable"])
async def test_generated_report_styles_only_title_network_headings_and_identity(platform, state, monkeypatch):
    monkeypatch.setattr("litechecker.direct_reporting.running_version", lambda: "0.6.2")
    agent = AgentIdentity("device-test", "Kemerovo", "PC 🖥 <b>name</b>", 600)
    vpn = ProbeResult(target_id="vpn", address="node.example", port=443,
                      label="🇳🇱 <b>VPN</b> & _label_", status=ResultStatus.UP, stage=ProbeStage.E2E)
    sni = ProbeResult(target_id="sni", address="sni.example", port=443, check_kind="sni",
                      label="SNI", status=ResultStatus.UP, stage=ProbeStage.TLS)
    if state != "healthy":
        status = ResultStatus.UNKNOWN if state == "unknown" else ResultStatus.DOWN
        vpn = vpn.model_copy(update={"status": status, "stage": ProbeStage.VLESS_E2E})
        sni = sni.model_copy(update={"status": status, "stage": ProbeStage.TLS_HANDSHAKE})
        if state == "unknown":
            vpn = vpn.model_copy(update={"stage": ProbeStage.POLICY, "error_code": "probe-error"})
            sni = sni.model_copy(update={"stage": ProbeStage.POLICY, "error_code": "probe-error"})
    report = make_report(results=[vpn, sni], app_version="0.6.2")
    exit_ip = ExitObservation("158.46.97.41", "Kemerovo", "AS39927 E-Light & Co.")
    if state == "unavailable":
        text = format_unavailable(agent, "direct-network-changed", datetime(2026, 9, 7, tzinfo=UTC),
                                  platform_label=platform)
        expected = [("bold", "⚠️ LiteChecker"),
                    ("blockquote", "DIRECT: проверка не выполнена."),
                    ("blockquote", "ID: device-test · v0.6.2")]
    else:
        icon = "✅" if state == "healthy" else "⚠️"
        expected = [("bold", f"{icon} LiteChecker · Kemerovo")]
        if platform == "Linux":
            text = format_report(report, agent, received_at=report.observed_at)
        else:
            text = format_direct(report, agent, "WiFi", exit_ip, exit_ip, platform_label=platform)
            expected.append(("blockquote", "DIRECT: WiFi · 158.46.97.41 · AS39927 · E-Light & Co.\n"
                             "Обычный выход: 158.46.97.41 — совпадает"))
        if state != "healthy":
            expected.extend([("bold", "VPN — проблемы:"),
                             ("bold", "SNI — проблемы:" if platform == "Linux" else "SNI — проблемы через WiFi:")])
        expected.append(("blockquote", "ID: device-test · v0.6.2"))
    payload, = await deliver(chunk_message(text))
    assert styled_ranges(payload) == expected
    # Names containing markup stay literal, not parsed or stripped by Telegram.
    assert "PC 🖥 <b>name</b>" in payload["text"]


@pytest.mark.asyncio
async def test_long_delayed_report_styles_each_chunk_without_losing_or_quoting_failures():
    header = "⚠️ LiteChecker · Kemerovo"
    route = "DIRECT: WiFi · 158.46.97.41\nОбычный выход: 158.46.97.41 — совпадает"
    identity = "ID: device-test · v0.6.2"
    failures = "\n\n".join(f"🔴 🇳🇱 Node {i} · node-{i}.example:443\n│ Порт отвечает, VPN: таймаут" for i in range(150))
    text = f"{header}\nPC 🖥 · Windows\n\n{route}\n\nVPN — проблемы:\n{failures}\n\n{identity}"
    chunks = chunk_message(text)
    assert len(chunks) > 2
    prefix = "🕓 Отложенная доставка — отчёт сформирован ранее.\n\n"
    payloads = await deliver([prefix + part for part in chunks])
    ranges = [span for p in payloads for span in styled_ranges(p)]
    assert ranges == [("bold", header), ("blockquote", route),
                      ("bold", "VPN — проблемы:"), ("blockquote", identity)]
    # Prefixes added by queueing/chunking must not shift ranges onto the wrong text.
    assert "".join(part.partition("\n")[2] for part in chunks) == text


@pytest.mark.asyncio
async def test_plain_notifications_do_not_gain_markup_parsing():
    payload, = await deliver(["Настройка <b>Telegram</b> & **тест**\nНе DIRECT: test\nНе ID: dev"])
    assert "entities" not in payload
