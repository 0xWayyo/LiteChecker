"""Validate Telegram-only proxy URLs without putting credentials in errors."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote_to_bytes, urlsplit


_SCHEMES = frozenset({"http", "https", "socks5", "socks5h"})
_LABEL = re.compile(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z")
_USERINFO = re.compile(r"[A-Za-z0-9._~!$&'()*+,;=:%-]+\Z")
_BAD_ESCAPE = re.compile(r"%(?![0-9a-fA-F]{2})")


def validate_telegram_proxy_url(value: str) -> str:
    """Return a supported URL unchanged; all invalid inputs raise a closed ValueError.

    Userinfo is kept encoded so reserved characters survive transport parsing.
    Authentication is optional, but supplied credentials must contain both fields.
    """
    try:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 4096
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
            or any(char in value for char in ("\\", "?", "#"))
        ):
            raise ValueError
        parsed = urlsplit(value)
        if parsed.scheme not in _SCHEMES or not parsed.hostname or parsed.path not in ("", "/"):
            raise ValueError
        authority = parsed.netloc
        if "@" in authority:
            if authority.count("@") != 1:
                raise ValueError
            userinfo, authority = authority.split("@")
            username, separator, password = userinfo.partition(":")
            if not separator or not username or not password:
                raise ValueError
            for credential in (username, password):
                if not _USERINFO.fullmatch(credential) or _BAD_ESCAPE.search(credential):
                    raise ValueError
                decoded = unquote_to_bytes(credential)
                if any(byte < 32 or byte == 127 for byte in decoded):
                    raise ValueError
                if parsed.scheme.startswith("socks5") and len(decoded) > 255:
                    raise ValueError
        if authority.startswith("["):
            host, suffix = authority[1:].split("]", 1)
            if ipaddress.ip_address(host).version != 6 or (suffix and not suffix.startswith(":")):
                raise ValueError
            port_text = suffix[1:] if suffix else None
        else:
            if ":" in authority:
                host, port_text = authority.rsplit(":", 1)
            else:
                host, port_text = authority, None
            ascii_host = host.encode("idna").decode("ascii").removesuffix(".")
            if len(ascii_host) > 253 or not all(_LABEL.fullmatch(label) for label in ascii_host.split(".")):
                raise ValueError
        if port_text is not None and (
            not re.fullmatch(r"[0-9]+", port_text) or not 1 <= int(port_text) <= 65535
        ):
            raise ValueError
        # Also exercise the standard parser's port validation before handing off.
        parsed.port
    except (ValueError, TypeError):
        raise ValueError("Telegram proxy URL is invalid") from None
    return value
