"""Download and reinstall the latest published Debian package."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPOSITORY = "Dpsley/subssl"
RELEASE_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
MAX_PACKAGE_SIZE = 100 * 1024 * 1024


def _request(url: str, accept: str) -> bytes:
    request = Request(
        url,
        headers={"Accept": accept, "User-Agent": "subssl-updater"},
    )
    with urlopen(request, timeout=30) as response:
        return response.read(MAX_PACKAGE_SIZE + 1)


def _latest_package_url() -> tuple[str, str]:
    payload = json.loads(_request(RELEASE_API, "application/vnd.github+json"))
    tag = str(payload.get("tag_name") or "latest")
    for asset in payload.get("assets") or []:
        name = str(asset.get("name") or "")
        url = str(asset.get("browser_download_url") or "")
        if name.startswith("subssl_") and name.endswith("_all.deb"):
            if not url.startswith(f"https://github.com/{REPOSITORY}/releases/download/"):
                raise ValueError("GitHub release returned an unexpected package URL")
            return tag, url
    raise ValueError("The latest GitHub Release does not contain a subssl Debian package")


def update_application() -> int:
    """Install the latest release using apt, retaining normal package semantics."""
    apt = shutil.which("apt")
    if not apt:
        print("ERROR: 'subssl update' requires a Debian or Ubuntu system with apt.", file=sys.stderr)
        return 2

    sudo = []
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sudo_path = shutil.which("sudo")
        if not sudo_path:
            print("ERROR: install updates as root or install sudo and run 'sudo subssl update'.", file=sys.stderr)
            return 2
        sudo = [sudo_path]

    try:
        tag, package_url = _latest_package_url()
        package_data = _request(package_url, "application/octet-stream")
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: could not find the latest subssl release: {exc}", file=sys.stderr)
        return 2

    if len(package_data) > MAX_PACKAGE_SIZE:
        print("ERROR: downloaded package exceeds the 100 MiB safety limit.", file=sys.stderr)
        return 2
    if not package_data.startswith(b"!<arch>\n"):
        print("ERROR: GitHub download was not a valid Debian package archive.", file=sys.stderr)
        return 2

    package_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="subssl-update-", suffix=".deb", delete=False) as package_file:
            package_file.write(package_data)
            package_path = Path(package_file.name)

        print(f"Installing subssl release {tag}...")
        result = subprocess.run(
            [*sudo, apt, "install", "--reinstall", "--yes", str(package_path)],
            check=False,
        )
        if result.returncode == 0:
            print(f"subssl {tag} installed successfully.")
        return result.returncode
    except OSError as exc:
        print(f"ERROR: could not run apt: {exc}", file=sys.stderr)
        return 2
    finally:
        if package_path is not None:
            package_path.unlink(missing_ok=True)
