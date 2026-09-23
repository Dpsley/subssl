from __future__ import annotations

import asyncio
import csv
import ipaddress
import json
import ssl
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

import dns.asyncresolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .config import Config, Secrets, REPORTS_DIR
from .nicru import NicRuClient, NicRuError, collect_zone_names
from .state import HostRegistry


def now_utc():
    return datetime.now(timezone.utc)


@dataclass
class DNSView:
    resolver: str
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_data(self):
        return bool(self.a or self.aaaa or self.cname)


@dataclass
class TLSView:
    ip: str
    port: int
    ok: bool
    error: str = ""
    subject_cn: str = ""
    issuer: str = ""
    serial_hex: str = ""
    sha256: str = ""
    not_before: str = ""
    not_after: str = ""
    days_left: int | None = None
    expired: bool | None = None
    host_matches_cert: bool | None = None
    sans: list[str] = field(default_factory=list)


@dataclass
class ScanHost:
    hostname: str
    record_types: list[str]
    resolution_scope: str = "none"
    dns: dict[str, DNSView] = field(default_factory=dict)
    tls: list[TLSView] = field(default_factory=list)


class Scanner:
    def __init__(self, cfg: Config, secrets: Secrets, verbose: bool = False):
        self.cfg = cfg
        self.secrets = secrets
        self.verbose = verbose
        self.sem = asyncio.Semaphore(max(1, cfg.concurrency))

    def log(self, msg: str):
        if self.verbose:
            print(msg, flush=True)

    async def query_one(self, resolver: str, host: str) -> DNSView:
        async with self.sem:
            r = dns.asyncresolver.Resolver(configure=False)
            r.nameservers = [resolver]
            r.timeout = self.cfg.dns_timeout
            r.lifetime = self.cfg.dns_timeout
            view = DNSView(resolver=resolver)
            for rdtype, attr in (("A", "a"), ("AAAA", "aaaa"), ("CNAME", "cname")):
                try:
                    ans = await r.resolve(host, rdtype, raise_on_no_answer=False, search=False)
                    if ans.rrset is None:
                        continue
                    values = []
                    for item in ans:
                        if rdtype == "CNAME":
                            values.append(str(item.target).rstrip(".").lower())
                        else:
                            values.append(str(item))
                    setattr(view, attr, sorted(set(values)))
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                except Exception as exc:
                    view.errors.append(f"{rdtype}: {type(exc).__name__}: {exc}")
            return view

    async def resolve_host(self, host: str) -> tuple[dict[str, DNSView], str]:
        overrides = self.cfg.local_overrides.get(host, [])
        if overrides:
            a, aaaa = [], []
            for value in overrides:
                try:
                    ip = ipaddress.ip_address(value)
                    (a if ip.version == 4 else aaaa).append(str(ip))
                except ValueError:
                    continue
            if a or aaaa:
                return {"override": DNSView(resolver="override", a=sorted(set(a)), aaaa=sorted(set(aaaa)))}, "override"

        if self.cfg.local_dns:
            local_views = await asyncio.gather(*(self.query_one(x, host) for x in self.cfg.local_dns))
            good = {x.resolver: x for x in local_views if x.has_data or x.errors}
            if any(x.has_data for x in local_views):
                return good, "local"

        fallback_views = await asyncio.gather(*(self.query_one(x, host) for x in self.cfg.fallback_dns))
        return {x.resolver: x for x in fallback_views if x.has_data or x.errors}, "fallback"

    @staticmethod
    def cert_match(pattern: str, host: str) -> bool:
        p = pattern.lower().rstrip(".")
        h = host.lower().rstrip(".")
        if p == h:
            return True
        if p.startswith("*."):
            return h.endswith(p[1:]) and h.count(".") == p.count(".")
        return False

    async def tls_probe(self, host: str, ip: str, port: int) -> TLSView:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            async with self.sem:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=context, server_hostname=host),
                    timeout=self.cfg.tls_timeout,
                )
            obj = writer.get_extra_info("ssl_object")
            if obj is None:
                raise RuntimeError("TLS handshake has no ssl_object")
            der = obj.getpeercert(binary_form=True)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            cert = x509.load_der_x509_certificate(der)
            try:
                cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            except Exception:
                cn = ""
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                sans = sorted(set(x.lower().rstrip(".") for x in ext.value.get_values_for_type(x509.DNSName)))
            except x509.ExtensionNotFound:
                sans = []
            if hasattr(cert, "not_valid_before_utc"):
                nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
            else:
                nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
                na = cert.not_valid_after.replace(tzinfo=timezone.utc)
            now = now_utc()
            candidates = sans or ([cn.lower()] if cn else [])
            return TLSView(
                ip=ip,
                port=port,
                ok=True,
                subject_cn=cn,
                issuer=cert.issuer.rfc4514_string(),
                serial_hex=f"{cert.serial_number:X}",
                sha256=cert.fingerprint(hashes.SHA256()).hex(),
                not_before=nb.isoformat(),
                not_after=na.isoformat(),
                days_left=int((na - now).total_seconds() // 86400),
                expired=na < now,
                host_matches_cert=any(self.cert_match(x, host) for x in candidates),
                sans=sans,
            )
        except Exception as exc:
            return TLSView(ip=ip, port=port, ok=False, error=f"{type(exc).__name__}: {exc}")

    @staticmethod
    def ips(views: dict[str, DNSView]) -> list[str]:
        values = set()
        for v in views.values():
            values.update(v.a)
            values.update(v.aaaa)
        return sorted(values)

    async def run(self) -> tuple[list[ScanHost], str, int]:
        if not self.cfg.domain:
            raise RuntimeError("Domain is not configured")
        nic = NicRuClient(
            self.secrets.client_id,
            self.secrets.client_secret,
            self.secrets.username,
            self.secrets.password,
            self.secrets.refresh_token,
        )
        self.log("[nic.ru] reading DNS zone")
        service, records = await nic.discover_service_and_records(self.cfg.domain, self.cfg.nic_service)
        if service != self.cfg.nic_service:
            self.cfg.nic_service = service
            self.cfg.save()
        if nic.new_refresh_token and nic.new_refresh_token != self.secrets.refresh_token:
            self.secrets.refresh_token = nic.new_refresh_token
            self.secrets.save()

        names = collect_zone_names(records, self.cfg.domain)
        registry = HostRegistry(self.cfg.domain, self.cfg.ignore_prefixes)
        registry.sync_zone(names)
        registry.save()
        enabled = [(h, sorted(types)) for h, types in sorted(names.items()) if registry.is_enabled(h)]
        self.log(f"[nic.ru] service={service}; records={len(records)}; hostnames={len(names)}; enabled={len(enabled)}")

        async def scan_one(host: str, types: list[str]) -> ScanHost:
            views, scope = await self.resolve_host(host)
            item = ScanHost(hostname=host, record_types=types, resolution_scope=scope, dns=views)
            tasks = [self.tls_probe(host, ip, port) for ip in self.ips(views) for port in self.cfg.ports]
            if tasks:
                item.tls = await asyncio.gather(*tasks)
            return item

        result = await asyncio.gather(*(scan_one(h, t) for h, t in enabled))
        return list(result), service, len(records)


def write_reports(cfg: Config, hosts: list[ScanHost], service: str, record_count: int, output_base: Path | None = None) -> tuple[Path, Path]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if output_base is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_base = REPORTS_DIR / f"{cfg.domain}-{stamp}"
    output_base.parent.mkdir(parents=True, exist_ok=True)
    json_path = output_base.with_suffix(".json")
    csv_path = output_base.with_suffix(".csv")

    payload = {
        "domain": cfg.domain,
        "generated_at": now_utc().isoformat(),
        "source": "nic.ru DNS-hosting API",
        "nic_service": service,
        "zone_record_count": record_count,
        "local_dns": cfg.local_dns,
        "fallback_dns": cfg.fallback_dns,
        "hosts": [asdict(h) for h in hosts],
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    fields = ["hostname", "record_types", "resolution_scope", "dns_ips", "dns_resolvers", "cnames", "tls_ip", "tls_port", "tls_ok", "tls_error", "subject_cn", "issuer", "not_after", "days_left", "expired", "host_matches_cert", "sans"]
    rows = []
    for h in hosts:
        ips = Scanner.ips(h.dns)
        resolvers = sorted(h.dns)
        cnames = sorted({x for v in h.dns.values() for x in v.cname})
        if h.tls:
            for t in h.tls:
                rows.append({
                    "hostname": h.hostname,
                    "record_types": ";".join(h.record_types),
                    "resolution_scope": h.resolution_scope,
                    "dns_ips": ";".join(ips),
                    "dns_resolvers": ";".join(resolvers),
                    "cnames": ";".join(cnames),
                    "tls_ip": t.ip,
                    "tls_port": t.port,
                    "tls_ok": t.ok,
                    "tls_error": t.error,
                    "subject_cn": t.subject_cn,
                    "issuer": t.issuer,
                    "not_after": t.not_after,
                    "days_left": "" if t.days_left is None else t.days_left,
                    "expired": "" if t.expired is None else t.expired,
                    "host_matches_cert": "" if t.host_matches_cert is None else t.host_matches_cert,
                    "sans": ";".join(t.sans),
                })
        else:
            rows.append({
                "hostname": h.hostname,
                "record_types": ";".join(h.record_types),
                "resolution_scope": h.resolution_scope,
                "dns_ips": ";".join(ips),
                "dns_resolvers": ";".join(resolvers),
                "cnames": ";".join(cnames),
                "tls_ip": "", "tls_port": "", "tls_ok": False, "tls_error": "No resolved IP / no TLS endpoint",
                "subject_cn": "", "issuer": "", "not_after": "", "days_left": "", "expired": "", "host_matches_cert": "", "sans": "",
            })
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return json_path, csv_path


async def run_scan(cfg: Config, secrets: Secrets, verbose: bool = False, output_base: Path | None = None):
    hosts, service, record_count = await Scanner(cfg, secrets, verbose=verbose).run()
    j, c = write_reports(cfg, hosts, service, record_count, output_base)
    # Import lazily to keep the scanner model independent from transport code.
    from .prometheus import PrometheusPushError, push_metrics
    try:
        endpoint = await push_metrics(cfg, hosts, now_utc())
        publish_error = None
    except PrometheusPushError as exc:
        # Reports are still useful when an external monitoring endpoint is down.
        endpoint = None
        publish_error = str(exc)
    return hosts, j, c, endpoint, publish_error
