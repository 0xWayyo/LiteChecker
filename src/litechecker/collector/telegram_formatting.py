"""Style known report lines at delivery, keeping console/outbox text unchanged."""

from __future__ import annotations

import re


_HEADING = re.compile(
    r"(?:(?:✅|⚠️|🧪) LiteChecker(?: ·.*)?|(?:VPN|SNI) — проблемы(?: через .+)?):?\Z"
)


def report_entities(text: str) -> list[dict[str, str | int]]:
    """Build non-overlapping Bot API entities for one final, possibly prefixed chunk.

    Offsets count UTF-16 units, not Python characters. Only our line labels select
    styling; names containing HTML/Markdown remain literal because no parse_mode
    is enabled. Recompute after chunking/delayed-delivery prefixes, never before.
    """
    entities: list[dict[str, str | int]] = []
    offset = 0
    previous = ""
    for raw in text.splitlines(keepends=True):
        line = raw.rstrip("\r\n")
        length = _utf16_length(line)
        if _HEADING.fullmatch(line):
            entities.append({"type": "bold", "offset": offset, "length": length})
        elif line.startswith(("DIRECT: ", "Обычный выход: ", "ID: ")):
            if line.startswith("Обычный выход: ") and previous.startswith("DIRECT: "):
                # These two adjacent lines are ONE quote, not two separate boxes.
                entities[-1]["length"] = offset + length - entities[-1]["offset"]
            else:
                entities.append({"type": "blockquote", "offset": offset, "length": length})
        offset += _utf16_length(raw)
        previous = line
    return entities


def _utf16_length(text: str) -> int:
    return len(text.encode("utf-16-le", errors="surrogatepass")) // 2
