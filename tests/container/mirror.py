# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Fojle Rabbi (Rabib)
"""Serve a published tree the way the site does, and GitHub's release downloads behind it.

The redirect is the shipped `web/docroot.htaccess` rule, read by `htaccess.redirect`; only the
host in its `Location` is swapped for this server, because a client in a container cannot reach
github.com for a fake release. Everything else is a plain file under `current/`. `tamper` names
tree paths whose middle byte is flipped on the way out, to show a client refuses them.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from types import TracebackType
from urllib.parse import unquote, urlsplit

from htaccess import REDIRECT_STATUS, redirect
from rig import Rig

GITHUB = "https://github.com/"


class Mirror:
    def __init__(self, rig: Rig) -> None:
        self.tamper: set[str] = set()
        self.redirects: list[str] = []
        self._rig = rig
        mirror = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                mirror._serve(self, send_body=True)

            def do_HEAD(self) -> None:
                mirror._serve(self, send_body=False)

            def log_message(self, format: str, *args: object) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )

    @property
    def port(self) -> int:
        return int(self._server.server_port)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> Mirror:
        self._thread.start()
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join()

    def _serve(self, request: BaseHTTPRequestHandler, *, send_body: bool) -> None:
        path = unquote(urlsplit(request.path).path)
        location = redirect(path)
        if location is not None:
            self.redirects.append(location)
            request.send_response(REDIRECT_STATUS)
            if 300 <= REDIRECT_STATUS < 400:
                request.send_header("Location", self.base + "/" + location.removeprefix(GITHUB))
            request.send_header("Content-Length", "0")
            request.end_headers()
            return
        body = self._body(path)
        if body is None:
            request.send_response(404)
            request.send_header("Content-Length", "0")
            request.end_headers()
            return
        request.send_response(200)
        request.send_header("Content-Length", str(len(body)))
        request.end_headers()
        if send_body:
            request.wfile.write(body)

    def _body(self, path: str) -> bytes | None:
        relative = PurePosixPath(path.removeprefix("/"))
        if relative.is_absolute() or ".." in relative.parts:
            return None
        asset = self._rig.feed.asset(GITHUB + relative.as_posix())
        if asset is not None:
            return asset
        file = Path(self._rig.current / relative)
        if not file.is_file():
            return None
        data = file.read_bytes()
        if relative.as_posix() in self.tamper and data:
            middle = len(data) // 2
            data = data[:middle] + bytes([data[middle] ^ 0x01]) + data[middle + 1 :]
        return data
