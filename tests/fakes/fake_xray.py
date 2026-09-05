#!/usr/bin/env python3
"""Tiny process fixture that captures stdin and exposes the configured SOCKS port."""

import json
import os
import select
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path


if sys.argv[1:] == ["--fixture-ready"]:
    print("fake-xray-ready", flush=True)
    raise SystemExit(0)


capture = Path(os.environ["FAKE_XRAY_CAPTURE"])
payload = sys.stdin.buffer.read()
capture.write_bytes(payload)
Path(os.environ["FAKE_XRAY_ARGS"]).write_text(json.dumps(sys.argv[1:]), encoding="utf-8")
Path(os.environ["FAKE_XRAY_PID"]).write_text(str(os.getpid()), encoding="utf-8")

mode = os.environ.get("FAKE_XRAY_MODE", "listen")
if mode == "exit":
    sys.stderr.write("private stderr " * 10_000)
    raise SystemExit(23)
if mode == "ignore-term":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

config = json.loads(payload)
inbound = config["inbounds"][0]
port = inbound["port"]
accounts = inbound["settings"].get("accounts", [])
account = accounts[0] if accounts else None
expected_user = account["user"].encode("utf-8") if account else None
expected_password = account["pass"].encode("utf-8") if account else None
if mode == "no-listen":
    while True:
        time.sleep(1)
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", port))
listener.listen()
listener.settimeout(0.1)


def read_exact(connection, length):
    received = bytearray()
    while len(received) < length:
        chunk = connection.recv(length - len(received))
        if not chunk:
            raise ConnectionError
        received.extend(chunk)
    return bytes(received)


def relay(left, right):
    sockets = [left, right]
    while True:
        readable, _, _ = select.select(sockets, [], [], 1)
        if not readable:
            continue
        for source in readable:
            data = source.recv(65_536)
            if not data:
                return
            destination = right if source is left else left
            destination.sendall(data)


def handle(connection):
    upstream = None
    try:
        version, count = read_exact(connection, 2)
        methods = read_exact(connection, count)
        required_method = 2 if account else 0
        if version != 5 or required_method not in methods:
            connection.sendall(b"\x05\xff")
            return
        connection.sendall(bytes((5, required_method)))

        if account:
            auth_version, user_length = read_exact(connection, 2)
            user = read_exact(connection, user_length)
            password_length = read_exact(connection, 1)[0]
            password = read_exact(connection, password_length)
            if (
                auth_version != 1
                or user != expected_user
                or password != expected_password
            ):
                connection.sendall(b"\x01\xff")
                return
            connection.sendall(b"\x01\x00")

        version, command, _, address_type = read_exact(connection, 4)
        if version != 5 or command != 1:
            return
        if address_type == 1:
            address = socket.inet_ntop(socket.AF_INET, read_exact(connection, 4))
        elif address_type == 3:
            address = read_exact(connection, read_exact(connection, 1)[0]).decode("ascii")
        elif address_type == 4:
            address = socket.inet_ntop(socket.AF_INET6, read_exact(connection, 16))
        else:
            return
        destination_port = struct.unpack("!H", read_exact(connection, 2))[0]
        upstream = socket.create_connection((address, destination_port), timeout=2)
        connection.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        marker = os.environ.get("FAKE_XRAY_CONNECTS")
        if marker:
            with open(marker, "ab") as stream:
                stream.write(b"1")
        relay(connection, upstream)
    except (ConnectionError, OSError, UnicodeError):
        return
    finally:
        connection.close()
        if upstream is not None:
            upstream.close()


exit_delay = os.environ.get("FAKE_XRAY_EXIT_DELAY")
if exit_delay:
    def delayed_exit():
        time.sleep(float(exit_delay))
        os._exit(24)

    threading.Thread(target=delayed_exit, daemon=True).start()


while True:
    try:
        connection, _ = listener.accept()
    except socket.timeout:
        time.sleep(0.01)
        continue
    threading.Thread(target=handle, args=(connection,), daemon=True).start()
