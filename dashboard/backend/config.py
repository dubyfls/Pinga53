# SPDX-License-Identifier: AGPL-3.0-only
"""Pinga53 dashboard config — env-driven, fail-closed.

Every tunable is centralised here so nothing is hardcoded across the codebase.
See `dashboard/.env.example`. Refuses to start on a missing or short secret.
"""
from __future__ import annotations
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    bind_host: str
    bind_port: int
    config_dir: str
    state_dir: str
    db_url: str
    audit_log: str
    secret_key: str
    cors_origins: list[str]
    pihole_ftl_db: str
    pihole_api: str
    pihole_app_password: str
    pihole_admin_url: str
    require_mfa: bool
    tls_cert: str = ""
    tls_key: str = ""
    jwt_ttl_min: int = 60 * 8
    unbound_conf: str = "/etc/unbound/unbound.conf.d/pinga53.conf"
    scamwall_zone: str = "/etc/unbound/rpz/scamwall.zone"
    scamwall_state: str = "/var/lib/scamwall"
    scamwall_stop_flag: str = "/var/lib/scamwall/STOP-AUTOMATIC"
    scamwall_install_log: str = "/var/log/pinga53/scamwall-install.log"
    helper_bin: str = "/usr/local/sbin/pinga53-helper"
    use_sudo_helper: bool = True


def _env(key: str, default: str | None = None) -> str | None:
    val = os.environ.get(f"PINGA53_{key}")
    if val is not None:
        return val
    return default


def _bool(key: str, default: bool) -> bool:
    v = _env(key, None)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def load() -> Config:
    secret = _env("SECRET_KEY", "") or ""
    if len(secret) < 32:
        raise SystemExit(
            "FATAL: PINGA53_SECRET_KEY missing or too short (need >=32 chars).\n"
            "Generate one:  openssl rand -hex 32   (fail closed — refusing to start)"
        )
    cfgdir = _env("CONFIG_DIR", "/etc/pinga53/dashboard")
    statedir = _env("STATE_DIR", "/var/lib/pinga53")
    return Config(
        bind_host=_env("BIND", "0.0.0.0"),
        bind_port=int(_env("PORT", "8053")),
        tls_cert=_env("TLS_CERT", "") or "",
        tls_key=_env("TLS_KEY", "") or "",
        config_dir=cfgdir,
        state_dir=statedir,
        db_url=_env("DB_URL", f"sqlite:///{statedir}/dashboard.db"),
        audit_log=_env("AUDIT_LOG", f"{statedir}/audit/audit.jsonl"),
        secret_key=secret,
        cors_origins=[o.strip() for o in (_env("CORS_ORIGINS", "") or "").split(",") if o.strip()],
        pihole_ftl_db=_env("PIHOLE_FTL_DB", "/etc/pihole/pihole-FTL.db"),
        pihole_api=_env("PIHOLE_API", "https://127.0.0.1/api"),
        pihole_app_password=_env("PIHOLE_APP_PASSWORD", "") or "",
        pihole_admin_url=_env("PIHOLE_ADMIN_URL", "/admin"),
        require_mfa=_bool("REQUIRE_MFA", True),
        unbound_conf=_env("UNBOUND_CONF", "/etc/unbound/unbound.conf.d/pinga53.conf"),
        scamwall_zone=_env("SCAMWALL_ZONE", "/etc/unbound/rpz/scamwall.zone"),
        scamwall_state=_env("SCAMWALL_STATE", "/var/lib/scamwall"),
        scamwall_stop_flag=_env("SCAMWALL_STOP_FLAG", "/var/lib/scamwall/STOP-AUTOMATIC"),
        scamwall_install_log=_env("SCAMWALL_INSTALL_LOG", "/var/log/pinga53/scamwall-install.log"),
        helper_bin=_env("HELPER_BIN", "/usr/local/sbin/pinga53-helper"),
        use_sudo_helper=_bool("USE_SUDO_HELPER", True),
    )
