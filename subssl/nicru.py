from __future__ import annotations

import asyncio
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import aiohttp

BASE_URL = "https://api.nic.ru"
TOKEN_URL = BASE_URL + "/oauth/token"
READ_SCOPE = "GET:/dns-master/.+"
TRANSIENT = {429, 500, 502, 503, 504}


class NicRuError(RuntimeError):
    pass


@dataclass
class NicRecord:
    name: str
    type: str


class NicRuClient:
    def __init__(self, client_id: str, client_secret: str, username: str = "", password: str = "", refresh_token: str = ""):
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.refresh_token = refresh_token
        self.access_token = ""
        self.new_refresh_token = ""

    async def _request(self, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
        timeout = aiohttp.ClientTimeout(total=30)
        last = None
        for attempt in range(3):
            try:
                session: aiohttp.ClientSession = kwargs.pop("session")
                resp = await session.request(method, url, timeout=timeout, **kwargs)
                if resp.status in TRANSIENT and attempt < 2:
                    await resp.release()
                    await asyncio.sleep(1 * (2 ** attempt))
                    kwargs["session"] = session
                    continue
                return resp
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last = exc
                if attempt >= 2:
                    raise NicRuError(str(exc)) from exc
                await asyncio.sleep(1 * (2 ** attempt))
                kwargs["session"] = session
        raise NicRuError(str(last or "request failed"))

    async def authenticate(self, session: aiohttp.ClientSession) -> str:
        if not self.client_id or not self.client_secret:
            raise NicRuError("NIC.RU OAuth application client_id/client_secret are not configured")

        if self.refresh_token:
            data = {"grant_type": "refresh_token", "refresh_token": self.refresh_token}
        else:
            if not self.username or not self.password:
                raise NicRuError(
                    "NIC.RU requires account username/password (for example 12345/NIC-D) in addition to OAuth app credentials"
                )
            data = {
                "grant_type": "password",
                "scope": READ_SCOPE,
                "username": self.username,
                "password": self.password,
                "offline": "1",
            }

        auth = aiohttp.BasicAuth(self.client_id, self.client_secret)
        async with session.post(TOKEN_URL, data=data, auth=auth, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            text = await resp.text()
            if resp.status >= 400:
                raise NicRuError(f"OAuth HTTP {resp.status}: {text[:500]}")
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise NicRuError(f"OAuth response is not JSON: {text[:300]}") from exc
            token = payload.get("access_token")
            if not token:
                raise NicRuError(f"OAuth response has no access_token: {payload}")
            self.access_token = token
            self.new_refresh_token = payload.get("refresh_token") or self.refresh_token
            return token

    async def _get_text(self, session: aiohttp.ClientSession, url: str) -> tuple[str, str]:
        if not self.access_token:
            await self.authenticate(session)
        headers = {"Authorization": f"Bearer {self.access_token}", "Accept": "application/json, application/xml, text/xml"}
        for attempt in range(3):
            try:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    text = await resp.text()
                    if resp.status in TRANSIENT and attempt < 2:
                        await asyncio.sleep(1 * (2 ** attempt))
                        continue
                    if resp.status >= 400:
                        raise NicRuError(f"GET {url} -> HTTP {resp.status}: {text[:500]}")
                    return text, resp.headers.get("content-type", "")
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                if attempt >= 2:
                    raise NicRuError(f"GET {url}: {exc}") from exc
                await asyncio.sleep(1 * (2 ** attempt))
        raise NicRuError(f"GET {url} failed")

    @staticmethod
    def _maybe_json(text: str) -> Any | None:
        try:
            return json.loads(text)
        except Exception:
            return None

    @staticmethod
    def _response_error_json(payload: Any) -> str | None:
        if isinstance(payload, dict):
            response = payload.get("response")
            if isinstance(response, dict) and response.get("status") not in (None, "success"):
                return str(response.get("errors") or response)
        return None

    async def get_services(self, session: aiohttp.ClientSession) -> list[str]:
        text, _ = await self._get_text(session, BASE_URL + "/dns-master/services")
        payload = self._maybe_json(text)
        if payload is not None:
            err = self._response_error_json(payload)
            if err:
                raise NicRuError(err)
            services = (((payload.get("response") or {}).get("data") or {}).get("service") or []) if isinstance(payload, dict) else []
            if isinstance(services, dict):
                services = [services]
            return [str(x.get("name")) for x in services if isinstance(x, dict) and x.get("name")]

        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise NicRuError(f"Cannot parse service list: {text[:300]}") from exc
        status = root.findtext("./status") or root.findtext(".//status")
        if status and status != "success":
            raise NicRuError("NIC.RU service list returned status=" + status)
        return sorted({(x.findtext("name") or "").strip() for x in root.findall(".//service") if (x.findtext("name") or "").strip()})

    async def get_records(self, session: aiohttp.ClientSession, service: str, zone: str) -> list[NicRecord]:
        url = f"{BASE_URL}/dns-master/services/{quote(service, safe='')}/zones/{quote(zone.encode('idna').decode(), safe='')}/records"
        text, _ = await self._get_text(session, url)
        payload = self._maybe_json(text)
        if payload is not None:
            err = self._response_error_json(payload)
            if err:
                raise NicRuError(err)
            zone_obj = (((payload.get("response") or {}).get("data") or {}).get("zone") or {}) if isinstance(payload, dict) else {}
            if isinstance(zone_obj, list):
                zone_obj = zone_obj[0] if zone_obj else {}
            rr = zone_obj.get("rr") or [] if isinstance(zone_obj, dict) else []
            if isinstance(rr, dict):
                rr = [rr]
            out = []
            for item in rr:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or item.get("idn-name") or "").strip()
                rtype = str(item.get("type") or "").strip().upper()
                if name or rtype:
                    out.append(NicRecord(name=name, type=rtype))
            return out

        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise NicRuError(f"Cannot parse zone records: {text[:300]}") from exc
        status = root.findtext("./status") or root.findtext(".//status")
        if status and status != "success":
            errors = "; ".join(x.text or "" for x in root.findall(".//errors/*"))
            raise NicRuError(errors or "NIC.RU records returned status=" + status)
        out = []
        for rr in root.findall(".//rr"):
            name = (rr.findtext("name") or rr.findtext("idn-name") or "").strip()
            rtype = (rr.findtext("type") or "").strip().upper()
            out.append(NicRecord(name=name, type=rtype))
        return out

    async def discover_service_and_records(self, zone: str, preferred_service: str = "") -> tuple[str, list[NicRecord]]:
        async with aiohttp.ClientSession() as session:
            await self.authenticate(session)
            if preferred_service:
                try:
                    return preferred_service, await self.get_records(session, preferred_service, zone)
                except NicRuError:
                    pass
            services = await self.get_services(session)
            if not services:
                raise NicRuError("No DNS-hosting services returned by NIC.RU")
            errors = []
            for service in services:
                try:
                    records = await self.get_records(session, service, zone)
                    return service, records
                except NicRuError as exc:
                    errors.append(f"{service}: {exc}")
            raise NicRuError("Zone not found on available services: " + " | ".join(errors))


def record_name_to_fqdn(name: str, zone: str) -> str | None:
    zone = zone.lower().rstrip(".")
    raw = (name or "").strip().lower().rstrip(".")
    if raw in ("", "@"):
        return zone
    if raw == zone or raw.endswith("." + zone):
        fqdn = raw
    else:
        fqdn = f"{raw}.{zone}"
    if fqdn == zone or fqdn.endswith("." + zone):
        return fqdn
    return None


def collect_zone_names(records: list[NicRecord], zone: str) -> dict[str, set[str]]:
    """Collect the zone apex and only direct, user-facing subdomains.

    DNS-hosting zones contain service records such as ACME challenges and
    DKIM/DMARC selectors. They are not web sites and may be many labels deep.
    A scan target is therefore the apex or exactly one ordinary label below it.
    """
    normalized_zone = zone.lower().rstrip(".")
    out: dict[str, set[str]] = {normalized_zone: set()}
    for rec in records:
        fqdn = record_name_to_fqdn(rec.name, normalized_zone)
        if fqdn == normalized_zone:
            out.setdefault(fqdn, set()).add(rec.type or "UNKNOWN")
            continue
        if not fqdn:
            continue
        relative = fqdn.removesuffix("." + normalized_zone)
        labels = relative.split(".")
        # _acme-challenge, DKIM/DMARC and wildcard records are DNS mechanics,
        # not hostnames suitable for a TLS endpoint check.
        if len(labels) == 1 and labels[0] not in ("", "*") and not labels[0].startswith("_"):
            out.setdefault(fqdn, set()).add(rec.type or "UNKNOWN")
    return out
