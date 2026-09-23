"""Prometheus Pushgateway publishing for subssl scan results.

Prometheus intentionally does not accept the text exposition format on its own
HTTP port.  Pushgateway is the small, official bridge for short-lived jobs such
as this scanner; it is scraped by Prometheus in the usual pull model.
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import quote

import aiohttp

from .config import Config
from .scanner import ScanHost


class PrometheusPushError(RuntimeError):
    """The scan completed, but its metrics could not be published."""


def _escape_label(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(**values: object) -> str:
    return "{" + ",".join(f'{key}="{_escape_label(value)}"' for key, value in values.items()) + "}"


def _timestamp_seconds(iso_value: str) -> float:
    return datetime.fromisoformat(iso_value.replace("Z", "+00:00")).timestamp()


def _date_label(iso_value: str) -> str:
    """Return a compact, human-readable certificate date for Grafana tables."""
    return datetime.fromisoformat(iso_value.replace("Z", "+00:00")).strftime("%d.%m.%Y") if iso_value else ""


def certificate_type(subject_cn: str, issuer: str, sans: list[str]) -> str:
    """Describe the actual certificate in a compact, useful Grafana label."""
    issuer_lower = issuer.lower()
    if "let's encrypt" in issuer_lower or "letsencrypt" in issuer_lower:
        authority = "Let's Encrypt"
    else:
        # X.509 issuer text normally begins with CN=<issuer name>. Keep that
        # concise identifier instead of the entire distinguished name.
        authority = next((part[3:] for part in issuer.split(",") if part.startswith("CN=")), issuer or "Unknown issuer")
    wildcard = subject_cn.startswith("*.") or any(name.startswith("*.") for name in sans)
    return f"Wildcard · {authority}" if wildcard else authority


def render_metrics(cfg: Config, hosts: list[ScanHost], scanned_at: datetime) -> str:
    """Return a complete Prometheus text payload for one scan.

    A PUT replaces the previous payload for the gateway grouping key, so hosts
    removed from a DNS zone do not leave stale certificate alerts behind.
    """
    domain = cfg.domain
    lines = [
        "# HELP subssl_scan_timestamp_seconds Unix timestamp of the completed SSL scan.",
        "# TYPE subssl_scan_timestamp_seconds gauge",
        f"subssl_scan_timestamp_seconds{_labels(domain=domain)} {scanned_at.timestamp():.3f}",
        "# HELP subssl_tls_probe_success Whether the TLS connection and certificate read succeeded (1=yes).",
        "# TYPE subssl_tls_probe_success gauge",
        "# HELP subssl_tls_certificate_expiry_timestamp_seconds Certificate expiry as a Unix timestamp.",
        "# TYPE subssl_tls_certificate_expiry_timestamp_seconds gauge",
        "# HELP subssl_tls_certificate_days_remaining Whole days until certificate expiry.",
        "# TYPE subssl_tls_certificate_days_remaining gauge",
        "# HELP subssl_tls_certificate_expired Whether the certificate has expired (1=yes).",
        "# TYPE subssl_tls_certificate_expired gauge",
        "# HELP subssl_tls_certificate_hostname_match Whether the certificate covers the scanned hostname (1=yes).",
        "# TYPE subssl_tls_certificate_hostname_match gauge",
        "# HELP subssl_tls_certificate_info Certificate identity details; value is always 1.",
        "# TYPE subssl_tls_certificate_info gauge",
        "# HELP subssl_tls_certificate_present Whether an endpoint has a readable TLS certificate (1=yes).",
        "# TYPE subssl_tls_certificate_present gauge",
    ]
    for host in hosts:
        # Export a row even when DNS produced no endpoint, so Grafana can render
        # a visible cross instead of silently omitting the hostname.
        if not host.tls:
            lines.append(
                "subssl_tls_certificate_present"
                + _labels(
                    domain=domain,
                    hostname=host.hostname,
                    endpoint="",
                    not_before="",
                    not_after="",
                    certificate_type="",
                    tls_error="No resolved IP / no TLS endpoint",
                )
                + " 0"
            )
        for tls in host.tls:
            base = dict(
                domain=domain,
                hostname=host.hostname,
                ip=tls.ip,
                port=tls.port,
                tls_error=tls.error if not tls.ok else "",
            )
            status_labels = dict(
                domain=domain,
                hostname=host.hostname,
                endpoint=f"{tls.ip}:{tls.port}",
                not_before=_date_label(tls.not_before) if tls.ok else "",
                not_after=_date_label(tls.not_after) if tls.ok else "",
                certificate_type=certificate_type(tls.subject_cn, tls.issuer, tls.sans) if tls.ok else "",
                tls_error=tls.error if not tls.ok else "",
            )
            lines.append(f"subssl_tls_certificate_present{_labels(**status_labels)} {1 if tls.ok else 0}")
            lines.append(f"subssl_tls_probe_success{_labels(**base)} {1 if tls.ok else 0}")
            if not tls.ok:
                continue
            if tls.not_after:
                lines.append(
                    f"subssl_tls_certificate_expiry_timestamp_seconds{_labels(**base)} {_timestamp_seconds(tls.not_after):.3f}"
                )
            if tls.days_left is not None:
                lines.append(f"subssl_tls_certificate_days_remaining{_labels(**base)} {tls.days_left}")
            if tls.expired is not None:
                lines.append(f"subssl_tls_certificate_expired{_labels(**base)} {1 if tls.expired else 0}")
            if tls.host_matches_cert is not None:
                lines.append(
                    f"subssl_tls_certificate_hostname_match{_labels(**base)} {1 if tls.host_matches_cert else 0}"
                )
            lines.append(
                "subssl_tls_certificate_info"
                + _labels(**base, subject_cn=tls.subject_cn, issuer=tls.issuer, serial=tls.serial_hex, sha256=tls.sha256)
                + " 1"
            )
    return "\n".join(lines) + "\n"


async def push_metrics(cfg: Config, hosts: list[ScanHost], scanned_at: datetime) -> str | None:
    """Publish scan metrics, returning the endpoint used; no-op if disabled."""
    base_url = cfg.prometheus_url.strip().rstrip("/")
    if not base_url:
        return None
    if not base_url.startswith(("http://", "https://")):
        raise PrometheusPushError("Prometheus Pushgateway URL must start with http:// or https://")

    job = quote((cfg.prometheus_job or "subssl").strip(), safe="")
    # Grouping by domain keeps scans of several zones independent in one gateway.
    endpoint = f"{base_url}/metrics/job/{job}/domain/{quote(cfg.domain, safe='')}"
    timeout = aiohttp.ClientTimeout(total=max(1.0, cfg.prometheus_timeout))
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.put(
                endpoint,
                data=render_metrics(cfg, hosts, scanned_at).encode("utf-8"),
                headers={"Content-Type": "text/plain; version=0.0.4; charset=utf-8"},
            ) as response:
                if response.status not in (200, 202):
                    detail = (await response.text()).strip()
                    raise PrometheusPushError(f"Pushgateway returned HTTP {response.status}: {detail[:300]}")
    except PrometheusPushError:
        raise
    except aiohttp.ClientError as exc:
        raise PrometheusPushError(f"Cannot reach Prometheus Pushgateway: {exc}") from exc
    return endpoint
