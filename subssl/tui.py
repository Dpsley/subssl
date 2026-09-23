from __future__ import annotations

import curses
import ipaddress
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

from .config import Config, Secrets
from .scheduler import PRESETS, describe_schedule, set_schedule
from .state import HostRegistry


def init_theme():
    """Use color when available, while keeping the interface usable over SSH."""
    if not curses.has_colors():
        return
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)    # title
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)  # selected item
    curses.init_pair(3, curses.COLOR_BLUE, -1)    # section label
    curses.init_pair(4, curses.COLOR_GREEN, -1)   # healthy/configured


def color(pair: int) -> int:
    return curses.color_pair(pair) if curses.has_colors() else 0


def prompt(stdscr, label: str, default: str = "", secret: bool = False, allow_empty: bool = False) -> str:
    h, w = stdscr.getmaxyx()
    stdscr.move(h - 2, 0)
    stdscr.clrtoeol()
    shown = f"{label}" + (f" [{default}]" if default and not secret else "") + ": "
    stdscr.addnstr(h - 2, 0, shown, max(1, w - 1))
    stdscr.refresh()
    curses.curs_set(1)
    if secret:
        curses.noecho()
    else:
        curses.echo()
    try:
        raw = stdscr.getstr(h - 2, min(len(shown), w - 2), max(1, w - len(shown) - 2))
        value = raw.decode("utf-8", errors="ignore").strip()
    finally:
        curses.noecho()
        curses.curs_set(0)
    return value if (value or allow_empty) else default


def message(stdscr, text: str):
    h, w = stdscr.getmaxyx()
    stdscr.erase()
    lines = text.splitlines() or [""]
    for i, line in enumerate(lines[: max(1, h - 2)]):
        stdscr.addnstr(i, 0, line, max(1, w - 1))
    stdscr.addnstr(h - 1, 0, "Press any key to continue", max(1, w - 1), curses.A_BOLD | color(1))
    stdscr.refresh()
    stdscr.getch()


def choose(stdscr, title: str, items: list[str]) -> int | None:
    idx = 0
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        stdscr.addnstr(0, 0, " subssl  |  " + title, max(1, w - 1), curses.A_BOLD | color(1))
        stdscr.hline(1, 0, curses.ACS_HLINE, max(1, w - 1))
        for row, item in enumerate(items[: h - 3], 2):
            selected = row - 2 == idx
            attr = (curses.A_BOLD | color(2)) if selected else curses.A_NORMAL
            prefix = "› " if selected else "  "
            stdscr.addnstr(row, 0, prefix + item, max(1, w - 1), attr)
        stdscr.addnstr(h - 1, 0, "↑/↓ move   Enter select   Esc back", max(1, w - 1), color(3))
        stdscr.refresh()
        k = stdscr.getch()
        if k in (curses.KEY_DOWN, ord("j")):
            idx = min(idx + 1, len(items) - 1)
        elif k in (curses.KEY_UP, ord("k")):
            idx = max(idx - 1, 0)
        elif k in (10, 13, curses.KEY_ENTER):
            return idx
        elif k in (27, ord("q")):
            return None


def choose_main(stdscr, status: str) -> int | None:
    """Main navigation with short grouped sections instead of a flat settings list."""
    entries: list[tuple[int | None, str]] = [
        (None, "SCAN"),
        (0, "Run scan now"),
        (None, "CONNECTIONS & INVENTORY"),
        (1, "NIC.RU / DNS zone settings"),
        (2, "Local DNS servers"),
        (3, "Local DNS override records"),
        (4, "Known subdomains / enable-disable"),
        (6, "TLS ports"),
        (None, "AUTOMATION & MONITORING"),
        (5, "Scan schedule"),
        (7, "Prometheus / Grafana delivery"),
        (None, ""),
        (8, "Exit"),
    ]
    active = [action for action, _ in entries if action is not None]
    idx = 0
    while True:
        stdscr.erase(); h, w = stdscr.getmaxyx()
        stdscr.addnstr(0, 0, " subssl 2.1  ·  TLS inventory", max(1, w - 1), curses.A_BOLD | color(1))
        stdscr.addnstr(1, 0, " " + status, max(1, w - 1), color(4))
        stdscr.hline(2, 0, curses.ACS_HLINE, max(1, w - 1))
        current = active[idx]
        row = 4
        for action, label in entries:
            if row >= h - 2:
                break
            if action is None:
                if label:
                    stdscr.addnstr(row, 1, label, max(1, w - 2), curses.A_BOLD | color(3))
                row += 1
                continue
            selected = action == current
            attr = (curses.A_BOLD | color(2)) if selected else curses.A_NORMAL
            stdscr.addnstr(row, 1, ("› " if selected else "  ") + label, max(1, w - 2), attr)
            row += 1
        stdscr.addnstr(h - 1, 0, "↑/↓ move   Enter open   q quit", max(1, w - 1), color(3))
        stdscr.refresh(); key = stdscr.getch()
        if key in (curses.KEY_DOWN, ord("j")):
            idx = min(idx + 1, len(active) - 1)
        elif key in (curses.KEY_UP, ord("k")):
            idx = max(idx - 1, 0)
        elif key in (10, 13, curses.KEY_ENTER):
            return current
        elif key in (27, ord("q")):
            return 8


def edit_nic(stdscr, cfg: Config, sec: Secrets):
    cfg.domain = prompt(stdscr, "DNS zone", cfg.domain)
    sec.client_id = prompt(stdscr, "OAuth app client_id/login", sec.client_id)
    sec.client_secret = prompt(stdscr, "OAuth app client_secret/password", sec.client_secret, secret=True)
    sec.username = prompt(stdscr, "RU-CENTER account username (e.g. 12345/NIC-D)", sec.username)
    sec.password = prompt(stdscr, "RU-CENTER account password", sec.password, secret=True)
    # New credentials invalidate an old refresh token.
    sec.refresh_token = ""
    cfg.nic_service = ""
    cfg.save(); sec.save()
    message(stdscr, "NIC.RU settings saved.\nSecrets are stored in ~/.config/subssl/secrets.json with mode 0600.")


def edit_list(stdscr, title: str, values: list[str], validate_ip: bool = False):
    while True:
        items = [f"{x}" for x in values] + ["+ Add new"]
        choice = choose(stdscr, title + " (Enter on existing = delete)", items)
        if choice is None:
            return
        if choice == len(values):
            value = prompt(stdscr, "Value")
            if not value:
                continue
            if validate_ip:
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    message(stdscr, "Invalid IP address")
                    continue
            if value not in values:
                values.append(value)
        else:
            del values[choice]


def edit_overrides(stdscr, cfg: Config):
    while True:
        pairs = [(h, ip) for h in sorted(cfg.local_overrides) for ip in cfg.local_overrides[h]]
        labels = [f"{h:<50} -> {ip}" for h, ip in pairs] + ["+ Add hostname -> IP"]
        choice = choose(stdscr, "Local DNS overrides (app-local; Enter existing = delete)", labels)
        if choice is None:
            cfg.save(); return
        if choice == len(pairs):
            host = prompt(stdscr, "Hostname").lower().rstrip(".")
            ip = prompt(stdscr, "IP")
            if not host or not ip:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                message(stdscr, "Invalid IP address")
                continue
            cfg.local_overrides.setdefault(host, [])
            if ip not in cfg.local_overrides[host]:
                cfg.local_overrides[host].append(ip)
        else:
            host, ip = pairs[choice]
            cfg.local_overrides[host].remove(ip)
            if not cfg.local_overrides[host]:
                del cfg.local_overrides[host]


def manage_hosts(stdscr, cfg: Config):
    if not cfg.domain:
        message(stdscr, "Configure the DNS zone first.")
        return
    store = HostRegistry(cfg.domain, cfg.ignore_prefixes)
    idx = 0
    while True:
        items = list(store.entries())
        stdscr.erase(); h, w = stdscr.getmaxyx()
        stdscr.addnstr(0, 0, f"Known zone names: {cfg.domain}", max(1, w - 1), curses.A_BOLD)
        stdscr.addnstr(1, 0, "SPACE enable/disable | q save+back | stale = no longer in NIC.RU zone", max(1, w - 1))
        body = max(1, h - 4)
        if items:
            idx = max(0, min(idx, len(items) - 1))
            top = max(0, min(idx - body // 2, max(0, len(items) - body)))
            for row, (host, e) in enumerate(items[top:top+body], 3):
                real = top + row - 3
                mark = "[x]" if e.get("enabled", True) else "[ ]"
                stale = " stale" if not e.get("in_zone", True) else ""
                types = ",".join(e.get("record_types") or [])
                attr = curses.A_REVERSE if real == idx else curses.A_NORMAL
                stdscr.addnstr(row, 0, f"{mark} {host:<55} {types}{stale}", max(1, w - 1), attr)
        else:
            stdscr.addnstr(3, 0, "No names yet. Run a scan to import NIC.RU zone records.", max(1, w - 1))
        stdscr.refresh(); k = stdscr.getch()
        if k in (curses.KEY_DOWN, ord("j")) and items: idx = min(idx + 1, len(items) - 1)
        elif k in (curses.KEY_UP, ord("k")) and items: idx = max(idx - 1, 0)
        elif k == ord(" ") and items:
            host, e = items[idx]; store.set_enabled(host, not e.get("enabled", True))
        elif k in (ord("q"), 27):
            store.save(); return


def edit_schedule(stdscr):
    labels = [
        "Disabled",
        "Every hour",
        "Every 6 hours",
        "Daily at 09:00",
        "Daily at 18:00",
        "Custom cron expression",
    ]
    idx = choose(stdscr, "Scan schedule | current: " + describe_schedule(), labels)
    if idx is None:
        return
    exprs = ["", PRESETS["hourly"], PRESETS["every_6_hours"], PRESETS["daily_09"], PRESETS["daily_18"]]
    try:
        expr = exprs[idx] if idx < 5 else prompt(stdscr, "Cron expression", "0 */6 * * *")
        set_schedule(expr)
        message(stdscr, "Schedule updated:\n" + describe_schedule())
    except Exception as exc:
        message(stdscr, "Schedule error:\n" + str(exc))


def edit_prometheus(stdscr, cfg: Config):
    message(
        stdscr,
        "subssl sends one metrics snapshot after each scan.\n\n"
        "Enter your Prometheus Pushgateway base URL, for example:\n"
        "http://pushgateway.internal:9091\n\n"
        "Prometheus must scrape that Pushgateway. Leave the URL empty to disable publishing.",
    )
    url = prompt(stdscr, "Pushgateway URL (empty disables)", cfg.prometheus_url, allow_empty=True)
    if url and (not urlparse(url).scheme or not urlparse(url).netloc):
        message(stdscr, "Use a complete URL, for example http://pushgateway:9091")
        return
    job = prompt(stdscr, "Prometheus job name", cfg.prometheus_job or "subssl")
    timeout = prompt(stdscr, "Publish timeout in seconds", str(cfg.prometheus_timeout))
    try:
        timeout_value = float(timeout)
        if timeout_value <= 0:
            raise ValueError
    except ValueError:
        message(stdscr, "Timeout must be a positive number")
        return
    cfg.prometheus_url = url.rstrip("/")
    cfg.prometheus_job = job.strip() or "subssl"
    cfg.prometheus_timeout = timeout_value
    cfg.save()
    message(stdscr, "Prometheus delivery settings saved.\n\nUse the supplied Grafana dashboard JSON after Prometheus starts scraping Pushgateway.")


def run_scan_screen(stdscr):
    curses.def_prog_mode(); curses.endwin()
    try:
        cmd = [sys.executable, "-m", "subssl.cli", "scan", "-v"]
        rc = subprocess.call(cmd)
        input(f"\nScan finished with code {rc}. Press Enter to return to GUI...")
    finally:
        curses.reset_prog_mode(); curses.curs_set(0); stdscr.refresh()


def _main(stdscr):
    init_theme()
    curses.curs_set(0); stdscr.keypad(True)
    cfg, sec = Config.load(), Secrets.load()
    while True:
        prom = "enabled" if cfg.prometheus_url else "off"
        status = f"Zone: {cfg.domain or 'not configured'}   ·   Prometheus: {prom}"
        idx = choose_main(stdscr, status)
        if idx is None or idx == 8:
            cfg.save(); sec.save(); return
        if idx == 0: run_scan_screen(stdscr)
        elif idx == 1: edit_nic(stdscr, cfg, sec)
        elif idx == 2:
            edit_list(stdscr, "Local DNS servers", cfg.local_dns, validate_ip=True); cfg.save()
        elif idx == 3: edit_overrides(stdscr, cfg)
        elif idx == 4: manage_hosts(stdscr, cfg)
        elif idx == 5: edit_schedule(stdscr)
        elif idx == 6:
            raw = prompt(stdscr, "TLS ports comma-separated", ",".join(map(str, cfg.ports)))
            try:
                ports = sorted({int(x.strip()) for x in raw.split(",") if x.strip()})
                if not ports or any(x < 1 or x > 65535 for x in ports): raise ValueError
                cfg.ports = ports; cfg.save()
            except ValueError: message(stdscr, "Invalid port list")
        elif idx == 7:
            edit_prometheus(stdscr, cfg)
        cfg, sec = Config.load(), Secrets.load()


def launch_gui():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("subssl GUI requires a TTY. Use: subssl scan", file=sys.stderr)
        return 2
    curses.wrapper(_main)
    return 0
