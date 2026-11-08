# SPDX-License-Identifier: AGPL-3.0-only
"""Pi-hole v6 REST API client.

Talks to the local FTL REST API (https://127.0.0.1/api) using app-password
session auth. Holds a session (sid + csrf), re-auths on expiry/401, and sends
the CSRF token on write operations. Self-signed cert on localhost -> verify off.

v0.2 uses only the read methods (`available`, `summary`) for the overview
card; the write methods are kept intact so later releases can wire them up
without reintroducing a second client.
"""
from __future__ import annotations
import threading
import time
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PiholeError(Exception):
    pass


class PiholeClient:
    def __init__(self, base: str, app_password: str, timeout: float = 6.0):
        self.base = base.rstrip("/")
        self._pw = app_password
        self.timeout = timeout
        self._sid = None
        self._csrf = None
        self._exp = 0.0
        self._lock = threading.Lock()
        self._s = requests.Session()
        self._s.verify = False

    # ---- session ----
    def _login(self):
        r = self._s.post(f"{self.base}/auth", json={"password": self._pw}, timeout=self.timeout)
        if r.status_code != 200:
            raise PiholeError(f"auth failed: HTTP {r.status_code}")
        sess = (r.json() or {}).get("session", {})
        if not sess.get("valid"):
            raise PiholeError("auth failed: invalid password")
        self._sid = sess["sid"]
        self._csrf = sess.get("csrf")
        # validity is seconds; refresh a little early
        self._exp = time.time() + max(60, int(sess.get("validity", 1800)) - 60)

    def _ensure(self):
        if not self._sid or time.time() >= self._exp:
            self._login()

    def _headers(self, write=False):
        h = {"X-FTL-SID": self._sid}
        if write and self._csrf:
            h["X-FTL-CSRF"] = self._csrf
        return h

    def _req(self, method, path, *, json=None, params=None, _retry=True):
        with self._lock:
            self._ensure()
            write = method.upper() in ("POST", "PUT", "DELETE", "PATCH")
            r = self._s.request(method, f"{self.base}{path}", json=json, params=params,
                                 headers=self._headers(write), timeout=self.timeout)
        if r.status_code == 401 and _retry:
            with self._lock:
                self._sid = None
            return self._req(method, path, json=json, params=params, _retry=False)
        if r.status_code >= 400:
            try:
                err = r.json().get("error", {})
                raise PiholeError(err.get("message") or f"HTTP {r.status_code}")
            except ValueError:
                raise PiholeError(f"HTTP {r.status_code}")
        if r.status_code == 204 or not r.content:
            return {}
        return r.json()

    # ---- health ----
    def available(self) -> bool:
        try:
            self._req("GET", "/dns/blocking")
            return True
        except Exception:
            return False

    # ---- blocking ----
    def get_blocking(self) -> dict:
        return self._req("GET", "/dns/blocking")

    def set_blocking(self, enabled: bool, timer: int | None = None) -> dict:
        body = {"blocking": bool(enabled)}
        if timer:
            body["timer"] = int(timer)
        return self._req("POST", "/dns/blocking", json=body)

    # ---- domains (allow/deny, exact/regex) ----
    def list_domains(self) -> list:
        return (self._req("GET", "/domains") or {}).get("domains", [])

    def add_domain(self, domain: str, dtype: str, kind: str, comment: str | None = None) -> dict:
        # dtype: allow|deny   kind: exact|regex
        return self._req("POST", f"/domains/{dtype}/{kind}",
                         json={"domain": domain, "comment": comment, "enabled": True})

    def delete_domain(self, domain: str, dtype: str, kind: str) -> dict:
        return self._req("DELETE", f"/domains/{dtype}/{kind}/{domain}")

    # ---- lists (blocklists / gravity adlists) ----
    def list_lists(self) -> list:
        return (self._req("GET", "/lists") or {}).get("lists", [])

    def add_list(self, address: str, ltype: str = "block", comment: str | None = None) -> dict:
        return self._req("POST", "/lists",
                         json={"address": address, "type": ltype, "comment": comment, "enabled": True})

    def delete_list(self, address: str, ltype: str = "block") -> dict:
        return self._req("DELETE", "/lists", params={"address": address, "type": ltype})

    def run_gravity(self) -> dict:
        # gravity update can be slow; caller should background it
        return self._req("POST", "/action/gravity")

    # ---- groups & clients ----
    def list_groups(self) -> list:
        return (self._req("GET", "/groups") or {}).get("groups", [])

    def list_clients(self) -> list:
        return (self._req("GET", "/clients") or {}).get("clients", [])

    def add_client(self, client: str, comment: str | None = None, groups: list | None = None) -> dict:
        return self._req("POST", "/clients",
                         json={"client": client, "comment": comment, "groups": groups or [0]})

    def delete_client(self, client: str) -> dict:
        return self._req("DELETE", f"/clients/{client}")
