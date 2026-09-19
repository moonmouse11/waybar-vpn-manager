#!/usr/bin/env python3
"""Dev tool: transparent proxy between the Happ GUI and happd that records
the length-prefixed JSON protocol. NOT part of the waybar plugin.

Frame format (both directions): 4-byte big-endian length + UTF-8 JSON payload.
Log: /tmp/happd-sniff.log
"""

import os
import socket
import struct
import threading
import time
from pathlib import Path

LISTEN = "/tmp/happd.sock"
UPSTREAM = "/tmp/happd-real.sock"
LOG = Path("/tmp/happd-sniff.log")


def log(direction: str, payload: bytes) -> None:
    try:
        with LOG.open("ab") as f:
            header = f"=== {time.strftime('%H:%M:%S')} {direction} ({len(payload)}b) ===\n"
            f.write(header.encode())
            f.write(payload + b"\n")
    except OSError:
        pass


def pipe(src: socket.socket, dst: socket.socket, direction: str) -> None:
    try:
        while True:
            hdr = b""
            while len(hdr) < 4:
                chunk = src.recv(4 - len(hdr))
                if not chunk:
                    return
                hdr += chunk
            (length,) = struct.unpack(">I", hdr)
            body = b""
            while len(body) < length:
                chunk = src.recv(length - len(body))
                if not chunk:
                    return
                body += chunk
            log(direction, body)
            dst.sendall(hdr + body)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main() -> None:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(LISTEN)
    # the ctl script runs under umask 077, which would make the socket 0700
    # root and deny the unprivileged Happ GUI — it must stay world-writable
    os.chmod(LISTEN, 0o666)
    server.listen(8)
    print("happd-sniff: proxy listening", flush=True)
    while True:
        client, _ = server.accept()
        try:
            upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            upstream.connect(UPSTREAM)
        except OSError as e:
            log("error", str(e).encode())
            client.close()
            continue
        threading.Thread(
            target=pipe, args=(client, upstream, "gui->daemon"), daemon=True
        ).start()
        threading.Thread(
            target=pipe, args=(upstream, client, "daemon->gui"), daemon=True
        ).start()


if __name__ == "__main__":
    main()
