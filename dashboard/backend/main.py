# SPDX-License-Identifier: AGPL-3.0-only
"""Pinga53 dashboard backend — app factory plus the small admin CLI.

Serves the built SPA (`dashboard/frontend/dist`) and the JSON API. Fails closed
on a missing or short `PINGA53_SECRET_KEY`. First-start refuses to serve until
an administrator has been provisioned via the CLI.

Run:
    pinga53d                   # serve
    pinga53d bootstrap         # provision the initial administrator
    pinga53d audit-verify      # verify the audit hash-chain
    pinga53d ftl-probe         # probe the Pi-hole FTL database
    pinga53d scamwall-probe    # probe the ScamWall reader (fixtures or live)
"""
from __future__ import annotations
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.middleware.cors import CORSMiddleware

from backend import db
from backend.config import load, Config
from backend.audit.hash_chain import AuditLog
from backend.security.auth import make_current_user_dep
from backend.security.headers import SecurityHeaders, LoginRateLimit
from backend.security.flow_gate import ForcedFlowGate
from backend.branding import BRAND, TAGLINE

DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


def create_app(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or load()
    db.init(cfg.db_url)
    audit = AuditLog(cfg.audit_log)
    current_user = make_current_user_dep(cfg.secret_key)

    app = FastAPI(title=BRAND, description=TAGLINE, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SecurityHeaders)
    app.add_middleware(LoginRateLimit)
    app.add_middleware(ForcedFlowGate, secret_key=cfg.secret_key, require_mfa=cfg.require_mfa)
    if cfg.cors_origins:
        app.add_middleware(
            CORSMiddleware, allow_origins=cfg.cors_origins,
            allow_credentials=True, allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
        )

    from backend.api.auth import build_router as auth_router
    app.include_router(auth_router(cfg, audit, current_user))
    from backend.api.account import build_router as account_router
    app.include_router(account_router(cfg, audit, current_user))
    from backend.api.setup import build_router as setup_router
    app.include_router(setup_router(cfg, audit, current_user))
    from backend.api.admin import build_router as admin_router
    app.include_router(admin_router(cfg, audit, current_user))

    from backend.modules.pihole.adapter import FtlAdapter
    from backend.modules.pihole.client import PiholeClient
    ftl = FtlAdapter(cfg.pihole_ftl_db)
    pi_client = PiholeClient(cfg.pihole_api, cfg.pihole_app_password)

    from backend.api.pihole import build_pihole_router
    app.include_router(build_pihole_router(cfg, current_user, ftl, pi_client))

    from backend.api.scamwall import build_scamwall_router
    app.include_router(build_scamwall_router(cfg, current_user, audit))

    from backend.api.system import build_system_router
    app.include_router(build_system_router(cfg, current_user, audit))

    @app.get("/api/health")
    def health():
        return {"brand": BRAND, "status": "ok"}

    if DIST.exists():
        app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

        @app.get("/{full_path:path}")
        def spa(full_path: str):
            target = DIST / full_path
            if full_path and target.is_file():
                return FileResponse(target)
            return FileResponse(DIST / "index.html")
    else:
        @app.get("/")
        def no_dist():
            return {"detail": "frontend not built — run `./dashboard/frontend/build.sh`"}

    audit.record("pinga53d.start", actor="system", data={"bind": f"{cfg.bind_host}:{cfg.bind_port}"})
    return app


def _refuse_if_no_users(cfg) -> None:
    db.init(cfg.db_url)
    from backend.db.models import User
    s = db.session()
    try:
        n = s.query(User).count()
    finally:
        s.close()
    if n == 0:
        sys.exit(
            "FATAL: no users provisioned. Run `sudo pinga53d bootstrap` "
            "to create the initial administrator, then start the service."
        )


def run() -> None:
    import uvicorn
    cfg = load()
    _refuse_if_no_users(cfg)
    kw = dict(host=cfg.bind_host, port=cfg.bind_port, server_header=False)
    if cfg.tls_cert and cfg.tls_key:
        kw["ssl_certfile"] = cfg.tls_cert
        kw["ssl_keyfile"] = cfg.tls_key
    uvicorn.run(create_app(cfg), **kw)


def _audit_verify() -> None:
    cfg = load()
    intact, n = AuditLog(cfg.audit_log).verify()
    print(f"audit chain: {'INTACT' if intact else 'BROKEN'}  ({n} records)")
    sys.exit(0 if intact else 1)


def _bootstrap(argv: list[str]) -> None:
    from backend.security.bootstrap import create_bootstrap_admin, BootstrapError
    cfg = load()
    db.init(cfg.db_url)
    audit = AuditLog(cfg.audit_log)
    try:
        pw = create_bootstrap_admin(audit)
    except BootstrapError as e:
        sys.exit(str(e))
    print("administrator")
    print(pw)
    print("Change this password on first login. It will not be shown again.", file=sys.stderr)


def _admin_dispatch(sub: str, argv: list[str]) -> int:
    from backend import cli as _cli
    try:
        return _cli.DISPATCH[sub](argv)
    except _cli.CliError as e:
        sys.exit(str(e))


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in {
        "create-admin", "set-password", "reset-mfa",
        "disable-user", "enable-user", "list-users",
    }:
        sys.exit(_admin_dispatch(sys.argv[1], sys.argv[2:]))
    elif len(sys.argv) > 1 and sys.argv[1] == "bootstrap":
        _bootstrap(sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == "audit-verify":
        _audit_verify()
    elif len(sys.argv) > 1 and sys.argv[1] == "ftl-probe":
        from backend.modules.pihole.adapter import FtlAdapter
        print(FtlAdapter(load().pihole_ftl_db).probe())
    elif len(sys.argv) > 1 and sys.argv[1] == "scamwall-probe":
        from backend.modules.scamwall.reader import ScamWallReader
        cfg = load()
        print(ScamWallReader.from_config(cfg).probe())
    else:
        run()


if __name__ == "__main__":
    main()
