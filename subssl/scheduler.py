from __future__ import annotations

import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from .config import LOGS_DIR

MARKER = "# subssl-managed"
PRESETS = {
    "disabled": "",
    "hourly": "0 * * * *",
    "every_6_hours": "0 */6 * * *",
    "daily_09": "0 9 * * *",
    "daily_18": "0 18 * * *",
}


def executable_command() -> str:
    found = shutil.which("subssl")
    if found:
        return shlex.quote(found)
    return f"{shlex.quote(sys.executable)} -m subssl.cli"


def current_crontab() -> str:
    if not shutil.which("crontab"):
        return ""
    p = subprocess.run(["crontab", "-l"], text=True, capture_output=True)
    return p.stdout if p.returncode == 0 else ""


def get_schedule() -> str:
    for line in current_crontab().splitlines():
        if MARKER in line:
            return line.split(MARKER, 1)[0].strip().rsplit(executable_command(), 1)[0].strip() if executable_command() in line else "custom"
    return ""


def set_schedule(cron_expr: str) -> None:
    if not shutil.which("crontab"):
        raise RuntimeError("crontab command is not installed")
    lines = [x for x in current_crontab().splitlines() if MARKER not in x]
    if cron_expr.strip():
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        log = LOGS_DIR / "scheduled.log"
        cmd = f"{executable_command()} scan --scheduled >> {shlex.quote(str(log))} 2>&1"
        lines.append(f"{cron_expr.strip()} {cmd} {MARKER}")
    content = "\n".join(lines).rstrip() + ("\n" if lines else "")
    p = subprocess.run(["crontab", "-"], input=content, text=True, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "failed to update crontab")


def describe_schedule() -> str:
    for line in current_crontab().splitlines():
        if MARKER in line:
            return line
    return "disabled"
