# SPDX-License-Identifier: AGPL-3.0-only
"""Test helper: run the FastAPI app under uvicorn in a background thread and
give tests a base URL. Stdlib-only client (urllib) — the environment doesn't
carry httpx, so starlette's TestClient is out of reach and Order 13 forbids
adding a second dependency."""
from __future__ import annotations
import contextlib
import json as _json
import socket
import ssl
import threading
import time
from urllib import request as _urequest, error as _uerror

import uvicorn


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close()
    return p


class _Server(uvicorn.Server):
    def install_signal_handlers(self):  # noqa: D401 — stop uvicorn from grabbing signals
        pass


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def _req(self, method: str, path: str, *, headers=None, json=None):
        url = self.base + path
        data = None
        h = {"Accept": "application/json"}
        if json is not None:
            data = _json.dumps(json).encode()
            h["Content-Type"] = "application/json"
        if headers:
            h.update(headers)
        req = _urequest.Request(url, data=data, method=method, headers=h)
        try:
            with _urequest.urlopen(req, timeout=60) as r:
                body = r.read()
                return _Resp(r.status, body, dict(r.headers))
        except _uerror.HTTPError as e:
            body = e.read()
            return _Resp(e.code, body, dict(e.headers))

    def get(self, path, headers=None):
        return self._req("GET", path, headers=headers)

    def post(self, path, json=None, headers=None):
        return self._req("POST", path, headers=headers, json=json)


class _Resp:
    def __init__(self, status_code, body, headers):
        self.status_code = status_code
        self._body = body
        self.headers = headers

    @property
    def text(self):
        return self._body.decode("utf-8", errors="replace")

    def json(self):
        return _json.loads(self._body.decode("utf-8"))


@contextlib.contextmanager
def serve(app):
    port = _free_port()
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)
    server = _Server(cfg)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    # wait for socket to accept
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                break
        except OSError:
            time.sleep(0.05)
    try:
        yield Client(f"http://127.0.0.1:{port}")
    finally:
        server.should_exit = True
        thread.join(timeout=5)
