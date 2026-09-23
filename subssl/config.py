from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

APP = "subssl"
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / APP
CONFIG_PATH = CONFIG_DIR / "config.json"
SECRETS_PATH = CONFIG_DIR / "secrets.json"
HOSTS_PATH = STATE_DIR / "hosts.json"
REPORTS_DIR = STATE_DIR / "reports"
LOGS_DIR = STATE_DIR / "logs"

DEFAULT_FALLBACK_DNS = ["1.1.1.1", "8.8.8.8"]


@dataclass
class Config:
    domain: str = ""
    nic_service: str = ""
    local_dns: list[str] = field(default_factory=list)
    fallback_dns: list[str] = field(default_factory=lambda: list(DEFAULT_FALLBACK_DNS))
    local_overrides: dict[str, list[str]] = field(default_factory=dict)
    ports: list[int] = field(default_factory=lambda: [443])
    dns_timeout: float = 2.0
    tls_timeout: float = 4.0
    concurrency: int = 100
    ignore_prefixes: list[str] = field(default_factory=lambda: ["www."])
    # Prometheus Pushgateway base URL. Prometheus itself scrapes the gateway.
    prometheus_url: str = ""
    prometheus_job: str = "subssl"
    prometheus_timeout: float = 10.0

    @classmethod
    def load(cls) -> "Config":
        if not CONFIG_PATH.exists():
            return cls()
        try:
            raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            known = {k: raw[k] for k in cls.__dataclass_fields__ if k in raw}
            obj = cls(**known)
            # Fallback DNS are intentionally fixed to Cloudflare + Google.
            obj.fallback_dns = list(DEFAULT_FALLBACK_DNS)
            return obj
        except Exception:
            return cls()

    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(CONFIG_PATH, 0o600)


@dataclass
class Secrets:
    client_id: str = ""
    client_secret: str = ""
    username: str = ""
    password: str = ""
    refresh_token: str = ""

    @classmethod
    def load(cls) -> "Secrets":
        if not SECRETS_PATH.exists():
            return cls()
        try:
            raw = json.loads(SECRETS_PATH.read_text(encoding="utf-8"))
            return cls(**{k: raw.get(k, "") for k in cls.__dataclass_fields__})
        except Exception:
            return cls()

    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        tmp = SECRETS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(SECRETS_PATH)
        os.chmod(SECRETS_PATH, 0o600)
