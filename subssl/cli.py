from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from . import __version__
from .config import Config, Secrets, CONFIG_PATH, SECRETS_PATH
from .nicru import NicRuError
from .scanner import run_scan
from .scheduler import describe_schedule
from .tui import launch_gui
from .update import update_application


def build_parser():
    p = argparse.ArgumentParser(prog="subssl", description="NIC.RU zone based subdomain + TLS inventory")
    p.add_argument("--version", action="version", version=f"subssl {__version__}")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("gui", help="open shell GUI")
    scan = sub.add_parser("scan", help="run scan using saved configuration")
    scan.add_argument("-v", "--verbose", action="store_true")
    scan.add_argument("-o", "--output", type=Path, help="output basename (without .json/.csv)")
    scan.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("status", help="show configuration/status without secrets")
    sub.add_parser("update", help="download and install the latest Debian package")
    return p


def cmd_status():
    cfg = Config.load(); sec = Secrets.load()
    print(f"version: {__version__}")
    print(f"domain: {cfg.domain or '-'}")
    print(f"nic_service: {cfg.nic_service or 'auto'}")
    print(f"NIC OAuth app: {'configured' if sec.client_id and sec.client_secret else 'not configured'}")
    print(f"NIC account: {'configured' if sec.username and (sec.password or sec.refresh_token) else 'not configured'}")
    print(f"local DNS: {', '.join(cfg.local_dns) or '-'}")
    print(f"fallback DNS: {', '.join(cfg.fallback_dns)}")
    print(f"local overrides: {sum(len(v) for v in cfg.local_overrides.values())}")
    print(f"ports: {', '.join(map(str, cfg.ports))}")
    print(f"Prometheus Pushgateway: {cfg.prometheus_url or '-'}")
    print(f"Prometheus job: {cfg.prometheus_job or 'subssl'}")
    print(f"schedule: {describe_schedule()}")
    print(f"config: {CONFIG_PATH}")
    print(f"secrets: {SECRETS_PATH}")
    return 0


def main():
    # Explicit requirement: plain `subssl` opens GUI.
    if len(sys.argv) == 1:
        return launch_gui()
    args = build_parser().parse_args()
    if args.command == "gui":
        return launch_gui()
    if args.command == "status":
        return cmd_status()
    if args.command == "update":
        return update_application()
    if args.command == "scan":
        cfg, sec = Config.load(), Secrets.load()
        try:
            hosts, j, c, pushed_to, publish_error = asyncio.run(run_scan(cfg, sec, verbose=args.verbose, output_base=args.output))
        except (NicRuError, RuntimeError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        ok = sum(1 for h in hosts for t in h.tls if t.ok)
        bad = sum(1 for h in hosts for t in h.tls if not t.ok)
        expired = sum(1 for h in hosts for t in h.tls if t.expired is True)
        mismatch = sum(1 for h in hosts for t in h.tls if t.host_matches_cert is False)
        print(f"Hosts scanned: {len(hosts)}")
        print(f"TLS OK: {ok}; TLS errors: {bad}; expired: {expired}; hostname mismatch: {mismatch}")
        print(f"JSON: {j}")
        print(f"CSV:  {c}")
        if pushed_to:
            print(f"Prometheus: published to {pushed_to}")
        if publish_error:
            print(f"WARNING: reports were saved, but Prometheus publishing failed: {publish_error}", file=sys.stderr)
            return 3
        return 0
    return launch_gui()


if __name__ == "__main__":
    raise SystemExit(main())
