#!/usr/bin/env python3
"""Dev tool: local TLS capture server for the Happ subscription request.

Serves a certificate for <domain> (signed by the local CA the user trusted),
records the full HTTP request (method, path, headers, body) to
/tmp/happ-intercept/request.txt and answers 502.

Usage:
  sudo python3 scripts/sub-intercept-serve.py xskx.artemida.live
"""

import os
import socket
import ssl
import sys
from pathlib import Path

WORKDIR = Path("/tmp/happ-intercept")


def main() -> None:
    domain = sys.argv[1] if len(sys.argv) > 1 else "xskx.artemida.live"

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(WORKDIR / "server.crt"), str(WORKDIR / "server.key"))
    ctx.set_alpn_protocols(["http/1.1"])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 443))
    sock.listen(4)
    print(f"listening on 127.0.0.1:443 for https://{domain} — press Ctrl+C to stop")

    while True:
        conn, addr = sock.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                request_line = b""
                while b"\r\n" not in request_line:
                    chunk = tls.recv(1)
                    if not chunk:
                        break
                    request_line += chunk
                headers = b""
                while b"\r\n\r\n" not in headers:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    headers += chunk
                head, _, body = headers.partition(b"\r\n\r\n")
                content_length = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        content_length = int(line.split(b":")[1])
                while len(body) < content_length:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    body += chunk
                captured = request_line + head + b"\r\n\r\n" + body
                (WORKDIR / "request.txt").write_bytes(captured)
                os.chmod(WORKDIR / "request.txt", 0o600)  # carries auth tokens
                print("\n=== captured request ===")
                print(captured.decode("utf-8", errors="replace"))
                print("========================")
                tls.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
        except (ssl.SSLError, OSError) as e:
            print("connection error:", e)
        finally:
            try:
                conn.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()
