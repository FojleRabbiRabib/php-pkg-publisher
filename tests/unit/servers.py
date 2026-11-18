# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Loopback servers for testing the HTTPS clients over plain http."""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


@contextmanager
def raw_server(payload: bytes) -> Iterator[str]:
    """Answer one connection with raw bytes, to produce malformed HTTP."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)

    def serve() -> None:
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        with connection:
            connection.recv(65536)
            connection.sendall(payload)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    finally:
        listener.close()
        thread.join()


@contextmanager
def local_server(
    handler: Callable[[BaseHTTPRequestHandler], None],
) -> Iterator[tuple[str, list[dict[str, str]]]]:
    """Serve GET and POST with `handler`; yield the base URL and the requests seen so far.

    A POST entry also holds the request path (`:path`) and body (`:body`)."""
    seen: list[dict[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen.append({key.lower(): value for key, value in self.headers.items()})
            handler(self)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            entry = {key.lower(): value for key, value in self.headers.items()}
            entry[":path"] = self.path
            entry[":body"] = self.rfile.read(length).decode("utf-8", errors="replace")
            seen.append(entry)
            handler(self)

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def reply(
    status: int, body: bytes = b"", **headers: str
) -> Callable[[BaseHTTPRequestHandler], None]:
    """Build a handler that answers `status`; `_` in a keyword name becomes `-` in the header."""

    def respond(request: BaseHTTPRequestHandler) -> None:
        request.send_response(status)
        for key, value in headers.items():
            request.send_header(key.replace("_", "-"), value)
        request.send_header("Content-Length", str(len(body)))
        request.end_headers()
        request.wfile.write(body)

    return respond
