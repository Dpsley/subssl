from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .config import HOSTS_PATH


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class HostRegistry:
    def __init__(self, domain: str, ignore_prefixes: list[str], path: Path = HOSTS_PATH):
        self.domain = domain
        self.ignore_prefixes = ignore_prefixes
        self.path = path
        self.data = {"version": 2, "domains": {}}
        self.load()
        self.data.setdefault("domains", {}).setdefault(domain, {})

    @property
    def hosts(self) -> dict:
        return self.data["domains"][self.domain]

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("domains"), dict):
                self.data = raw
        except Exception:
            pass

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def default_enabled(self, hostname: str) -> bool:
        if hostname == self.domain:
            return True
        return not any(hostname.startswith(p) for p in self.ignore_prefixes)

    def sync_zone(self, names: dict[str, set[str]]) -> None:
        stamp = now_iso()
        current = set(names)
        for host, types in names.items():
            entry = self.hosts.get(host)
            if entry is None:
                entry = {
                    "enabled": self.default_enabled(host),
                    "first_seen": stamp,
                    "last_seen": stamp,
                    "in_zone": True,
                    "record_types": sorted(types),
                }
                self.hosts[host] = entry
            else:
                entry["last_seen"] = stamp
                entry["in_zone"] = True
                entry["record_types"] = sorted(types)
        for host, entry in self.hosts.items():
            if host not in current:
                entry["in_zone"] = False

    def is_enabled(self, host: str) -> bool:
        entry = self.hosts.get(host)
        return bool(entry.get("enabled", True)) if entry else self.default_enabled(host)

    def set_enabled(self, host: str, enabled: bool) -> None:
        entry = self.hosts.setdefault(host, {
            "enabled": self.default_enabled(host),
            "first_seen": now_iso(),
            "last_seen": now_iso(),
            "in_zone": False,
            "record_types": [],
        })
        entry["enabled"] = bool(enabled)

    def entries(self):
        for host in sorted(self.hosts):
            yield host, self.hosts[host]
