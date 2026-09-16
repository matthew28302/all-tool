#!/usr/bin/env python3
"""WHOIS lookup via https://whois.pavietnam.net/check/<domain>/.

This script uses the same HTTPS endpoint flow as the browser page.
It fetches returned HTML and extracts key fields from the page.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import socket
import sys
import threading
import time
from dataclasses import dataclass, replace
from typing import Any, Optional
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

DEFAULT_TIMEOUT = 12
WHOIS_CACHE_TTL_SECONDS = int(os.environ.get('WHOIS_CACHE_TTL_SECONDS', '15'))
WHOIS_NET_VN_URL = "https://www.whois.net.vn/whois.php?domain={domain}&act=getwhois"
WHOIS_CHECK_URL = "https://whois.pavietnam.net/check/{domain}/"
WHOIS_API_URL = "https://whois.pavietnam.net/whois.php"
VNNIC_WHOIS_URL = "https://whois.nic.vn/whois?domain={domain}"
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_TIMEOUT = 8
WHOIS_SOCKET_TIMEOUT = 8

_CACHE_LOCK = threading.Lock()
_WHOIS_CACHE: dict[str, tuple[float, WhoisResult]] = {}
_RDAP_SERVICES: Optional[dict[str, list[str]]] = None
_RDAP_LOCK = threading.Lock()


def _rdap_services() -> dict[str, list[str]]:
    global _RDAP_SERVICES
    with _RDAP_LOCK:
        if _RDAP_SERVICES is not None:
            return _RDAP_SERVICES
        try:
            payload, err = fetch_json_url(RDAP_BOOTSTRAP_URL, RDAP_TIMEOUT)
            services: dict[str, list[str]] = {}
            if not err and isinstance(payload, dict):
                for service in payload.get('services', []):
                    if len(service) != 2:
                        continue
                    tlds, urls = service
                    for tld in tlds:
                        services[str(tld).lower().lstrip('.')] = [str(url).rstrip('/') for url in urls]
            _RDAP_SERVICES = services
        except Exception:
            _RDAP_SERVICES = {}
        return _RDAP_SERVICES


def fetch_json_url(url: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    req = urlrequest.Request(url, headers={'User-Agent': 'all-tool/3.0', 'Accept': 'application/rdap+json, application/json'})
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode('utf-8', errors='replace'))
        return payload if isinstance(payload, dict) else None, None
    except Exception as exc:
        return None, str(exc)


@dataclass
class WhoisResult:
    domain: str
    source_url: str
    status_line: Optional[str]
    creation_date: Optional[str]
    expiry_date: Optional[str]
    delete_state_date: Optional[str]
    free_date: Optional[str]
    registrant_name: Optional[str]
    registrar_name: Optional[str]
    registrar_iana_id: Optional[str]
    registrar_abuse_contact_email: Optional[str]
    registrar_abuse_contact_phone: Optional[str]
    domain_status: Optional[str]
    registry_lock: Optional[str]
    name_servers: list[str]
    raw_html: Optional[str]
    errors: list[str]


def to_ascii_domain(domain: str) -> str:
    cleaned = domain.strip().lower().rstrip(".")
    if not cleaned:
        raise ValueError("Domain is empty")
    try:
        return cleaned.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid domain (IDNA encode failed): {domain}") from exc


def _cache_get(cache_key: str) -> Optional[WhoisResult]:
    now = time.time()
    with _CACHE_LOCK:
        cached = _WHOIS_CACHE.get(cache_key)
        if not cached:
            return None
        created_at, result = cached
        if now - created_at > WHOIS_CACHE_TTL_SECONDS:
            del _WHOIS_CACHE[cache_key]
            return None
        return result


def _cache_set(cache_key: str, result: WhoisResult) -> None:
    with _CACHE_LOCK:
        _WHOIS_CACHE[cache_key] = (time.time(), result)


def fetch_html(url: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[Optional[str], Optional[str]]:
    req = urlrequest.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) whois_lookup/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "vi,en-US;q=0.9,en;q=0.8",
        },
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace"), None
    except urlerror.HTTPError as exc:
        body = exc.read().decode('utf-8', errors='replace')
        if exc.code == 468 or 'slg-text' in body or 'product_data' in body:
            return None, 'PA WHOIS yêu cầu xác minh trình duyệt (anti-bot challenge)'
        return None, f"HTTP error: {exc.code}"
    except urlerror.URLError as exc:
        return None, f"Network error: {exc}"


def fetch_vnnic(domain: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[Optional[str], Optional[str]]:
    url = VNNIC_WHOIS_URL.format(domain=urlparse.quote(domain))
    req = urlrequest.Request(
        url,
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36',
            'Accept': 'text/plain,text/html,application/json;q=0.9,*/*;q=0.8',
            'Referer': 'https://whois.nic.vn/',
        },
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='replace'), None
    except Exception as exc:
        return None, str(exc)


def fetch_json(
    url: str,
    params: dict[str, str],
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    full_url = f"{url}?{urlparse.urlencode(params)}"
    req = urlrequest.Request(
        full_url,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) whois_lookup/2.0",
            "Accept": "application/json,text/plain,*/*",
            "Referer": f"{WHOIS_CHECK_URL.format(domain=params.get('domain', ''))}",
        },
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except urlerror.HTTPError as exc:
        return None, f"HTTP error (whois.php): {exc.code}"
    except urlerror.URLError as exc:
        return None, f"Network error (whois.php): {exc}"

    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        return None, f"Invalid JSON from whois.php: {exc}"

    if isinstance(data, dict):
        return data, None
    return None, "Unexpected JSON schema from whois.php"


def _extract_by_id(page_html: str, element_id: str) -> Optional[str]:
    pattern = rf'<[^>]+id="{re.escape(element_id)}"[^>]*>(.*?)</[^>]+>'
    match = re.search(pattern, page_html, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return html.unescape(re.sub(r"\s+", " ", match.group(1))).strip()


def _strip_tags(text: str) -> str:
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _normalize_status_text(raw_value: Any) -> Optional[str]:
    if not raw_value:
        return None

    if isinstance(raw_value, (list, tuple, set)):
        parts: list[str] = []
        for item in raw_value:
            normalized = _normalize_status_text(item)
            if normalized:
                parts.extend([part.strip() for part in normalized.split(",") if part.strip()])
        if parts:
            return ", ".join(dict.fromkeys(parts))
        return None

    text = html.unescape(raw_value)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)

    statuses: list[str] = []
    for line in text.splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        token = cleaned.split()[0].strip()
        if not token or token.lower().startswith("http"):
            continue
        statuses.append(token)

    if statuses:
        return ", ".join(dict.fromkeys(statuses))

    fallback = text.strip()
    return fallback or None


def _extract_field_value(page_html: str, field_class: str) -> Optional[str]:
    pattern = (
        rf'<div\s+class="fl\s+left\s+{re.escape(field_class)}"[^>]*>.*?</div>'
        rf'\s*<div\s+class="fl\s+right\s+{re.escape(field_class)}"[^>]*>(.*?)</div>'
    )
    match = re.search(pattern, page_html, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return _strip_tags(match.group(1))


def _extract_name_servers(page_html: str) -> list[str]:
    value = _extract_field_value(page_html, "name_servers")
    if not value:
        return []
    parts = [line.strip() for line in value.split(" ") if line.strip()]
    return parts


def _extract_token(page_html: str) -> Optional[str]:
    match = re.search(r'\btoken="([^"]+)"', page_html, flags=re.IGNORECASE)
    if not match:
        return None
    return match.group(1).strip()


def _clean_waiting(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned or cleaned.lower() == "waiting...":
        return None
    return cleaned


def _split_name_servers(raw_value: Optional[str]) -> list[str]:
    if not raw_value:
        return []
    return [item.strip() for item in raw_value.split("|") if item.strip()]


def apply_registrarinfo_payload(result: WhoisResult, payload: dict[str, Any]) -> None:
    registrar_info = payload.get("Registrar Info")
    if not isinstance(registrar_info, dict):
        return

    status_value = registrar_info.get("Status")
    domain_status_value = registrar_info.get("Domain Status")
    owner_value = registrar_info.get("Owner Name")
    registrar_value = registrar_info.get("Registrar Name") or registrar_info.get("Registrar")
    registrar_iana_value = registrar_info.get("Registrar IANA ID")
    abuse_email_value = registrar_info.get("Registrar Abuse Contact Email")
    abuse_phone_value = registrar_info.get("Registrar Abuse Contact Phone")
    registry_lock_value = registrar_info.get("Registry Lock")

    if isinstance(status_value, (str, list, tuple, set)) and status_value:
        result.status_line = _normalize_status_text(status_value)
    if isinstance(domain_status_value, (str, list, tuple, set)) and domain_status_value:
        result.domain_status = _normalize_status_text(domain_status_value)
        if not result.status_line:
            result.status_line = result.domain_status
    if isinstance(owner_value, str) and owner_value.strip():
        result.registrant_name = owner_value.strip()
    if isinstance(registrar_value, str) and registrar_value.strip():
        result.registrar_name = registrar_value.strip()
    if isinstance(registrar_iana_value, str) and registrar_iana_value.strip():
        result.registrar_iana_id = registrar_iana_value.strip()
    if isinstance(abuse_email_value, str) and abuse_email_value.strip():
        result.registrar_abuse_contact_email = abuse_email_value.strip()
    if isinstance(abuse_phone_value, str) and abuse_phone_value.strip():
        result.registrar_abuse_contact_phone = abuse_phone_value.strip()
    if isinstance(registry_lock_value, str) and registry_lock_value.strip():
        result.registry_lock = _strip_tags(registry_lock_value.strip())

    date_block = payload.get("Important Dates(dd/mm/yyyy)")
    if not isinstance(date_block, dict):
        date_block = payload.get("Important Dates")

    if isinstance(date_block, dict):
        creation_value = date_block.get("Creation Date")
        expiry_value = date_block.get("Registry Expiry Date")
        if isinstance(creation_value, str) and creation_value.strip():
            result.creation_date = creation_value.strip()
        if isinstance(expiry_value, str) and expiry_value.strip():
            result.expiry_date = expiry_value.strip()

    name_server_block = payload.get("Name Servers")
    if isinstance(name_server_block, dict):
        ns_value = name_server_block.get("Name Servers")
        if isinstance(ns_value, str):
            parsed_ns = _split_name_servers(ns_value)
            if parsed_ns:
                result.name_servers = parsed_ns
        else:
            parsed_ns = [key.strip() for key in name_server_block.keys() if isinstance(key, str) and key.strip()]
            if parsed_ns:
                result.name_servers = parsed_ns


def parse_pavietnam_html(domain: str, source_url: str, page_html: str) -> WhoisResult:
    status_line = _normalize_status_text(_extract_field_value(page_html, "status"))
    registrant_name = _extract_field_value(page_html, "owner_name")
    registrar_name = _extract_field_value(page_html, "other_registrar_name")
    if not registrar_name:
        registrar_name = _extract_field_value(page_html, "registrar")

    return WhoisResult(
        domain=domain,
        source_url=source_url,
        status_line=status_line,
        creation_date=_extract_by_id(page_html, "CreationDate"),
        expiry_date=_extract_by_id(page_html, "RegistryExpiryDate"),
        delete_state_date=_extract_by_id(page_html, "RenwealDate"),
        free_date=_extract_by_id(page_html, "DateDelete"),
        registrant_name=registrant_name,
        registrar_name=registrar_name,
        registrar_iana_id=None,
        registrar_abuse_contact_email=None,
        registrar_abuse_contact_phone=None,
        domain_status=None,
        registry_lock=None,
        name_servers=_extract_name_servers(page_html),
        raw_html=page_html,
        errors=[],
    )


def _rdap_event(payload: dict[str, Any], action: str) -> Optional[str]:
    for event in payload.get('events', []) or []:
        if isinstance(event, dict) and event.get('eventAction') == action:
            return event.get('eventDate')
    return None


def _rdap_entity(payload: dict[str, Any], roles: set[str]) -> Optional[dict[str, Any]]:
    for entity in payload.get('entities', []) or []:
        if not isinstance(entity, dict) or not roles.intersection(set(entity.get('roles', []) or [])):
            continue
        vcard = entity.get('vcardArray')
        props = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
        values = {}
        for prop in props:
            if isinstance(prop, list) and len(prop) > 3:
                values[prop[0]] = prop[3]
        return {'name': values.get('fn') or values.get('org'), 'email': values.get('email')}
    return None


def parse_rdap(domain: str, source_url: str, payload: dict[str, Any]) -> WhoisResult:
    registrant = _rdap_entity(payload, {'registrant'}) or {}
    registrar = _rdap_entity(payload, {'registrar'}) or {}
    nameservers = []
    for nameserver in payload.get('nameservers', []) or []:
        if isinstance(nameserver, dict) and nameserver.get('ldhName'):
            nameservers.append(str(nameserver['ldhName']).rstrip('.'))
    statuses = payload.get('status') or []
    return WhoisResult(
        domain=domain,
        source_url=source_url,
        status_line=', '.join(str(item) for item in statuses) if statuses else None,
        creation_date=_rdap_event(payload, 'registration'),
        expiry_date=_rdap_event(payload, 'expiration'),
        delete_state_date=_rdap_event(payload, 'deletion'),
        free_date=None,
        registrant_name=registrant.get('name'),
        registrar_name=registrar.get('name'),
        registrar_iana_id=payload.get('registrarIanaId'),
        registrar_abuse_contact_email=registrar.get('email'),
        registrar_abuse_contact_phone=None,
        domain_status=', '.join(str(item) for item in statuses) if statuses else None,
        registry_lock=None,
        name_servers=nameservers,
        raw_html=None,
        errors=[],
    )


def _whois_server_for_domain(ascii_domain: str) -> Optional[str]:
    tld = ascii_domain.rsplit('.', 1)[-1].lower()
    known = {
        'com': 'whois.verisign-grs.com', 'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org', 'info': 'whois.afilias.net', 'biz': 'whois.biz',
        'vn': 'whois.vnnic.vn',
    }
    return known.get(tld)


def lookup_whois_socket(domain: str, server: str) -> tuple[Optional[WhoisResult], Optional[str]]:
    try:
        with socket.create_connection((server, 43), timeout=WHOIS_SOCKET_TIMEOUT) as conn:
            conn.sendall((domain + '\r\n').encode('ascii'))
            chunks = []
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(len(item) for item in chunks) > 512 * 1024:
                    break
        text = b''.join(chunks).decode('utf-8', errors='replace')
        if not text.strip():
            return None, 'Empty WHOIS response'
        return parse_whois_text(domain, f'whois://{server}/{domain}', text), None
    except Exception as exc:
        return None, str(exc)


def parse_whois_text(domain: str, source_url: str, text: str) -> WhoisResult:
    def field(*labels: str) -> Optional[str]:
        for line in text.splitlines():
            for label in labels:
                if line.lower().startswith(label.lower() + ':'):
                    value = line.split(':', 1)[1].strip()
                    if value and not value.lower().startswith('%'):
                        return value
        return None
    statuses = [line.split(':', 1)[1].strip() for line in text.splitlines() if line.lower().startswith('domain status:')]
    nameservers = []
    for line in text.splitlines():
        if line.lower().startswith(('name server:', 'nameserver:')):
            nameservers.append(line.split(':', 1)[1].strip().rstrip('.'))
    return WhoisResult(
        domain=domain, source_url=source_url,
        status_line=', '.join(statuses) or field('status'),
        creation_date=field('creation date', 'created'),
        expiry_date=field('registry expiry date', 'expiration date', 'expiry date'),
        delete_state_date=None, free_date=None,
        registrant_name=field('registrant name', 'registrant organization', 'owner name'),
        registrar_name=field('registrar'), registrar_iana_id=field('registrar iana id'),
        registrar_abuse_contact_email=field('registrar abuse contact email'),
        registrar_abuse_contact_phone=field('registrar abuse contact phone'),
        domain_status=', '.join(statuses) or None, registry_lock=None,
        name_servers=list(dict.fromkeys(nameservers)), raw_html=None, errors=[])


def fetch_whois_net_vn(domain: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[Optional[WhoisResult], Optional[str]]:
    source_url = WHOIS_NET_VN_URL.format(domain=urlparse.quote(domain))
    req = urlrequest.Request(source_url, headers={
        'User-Agent': 'all-tool/3.0',
        'Accept': 'text/html,text/plain,application/xhtml+xml,*/*;q=0.8',
    })
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode('utf-8', errors='replace')
    except Exception as exc:
        return None, str(exc)

    text = re.sub(r'<br\s*/?>', '\n', body, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    text = html.unescape(text)
    text = re.sub(r'\r\n?', '\n', text)
    text = '\n'.join(line.strip() for line in text.split('\n') if line.strip())
    if not text or 'record found' not in text.lower():
        return None, 'Domain record not found'

    def value(label: str) -> Optional[str]:
        match = re.search(rf'{re.escape(label)}\s*:\s*(.+)', text, flags=re.IGNORECASE)
        return match.group(1).strip() if match else None

    dns_value = value('DNS') or ''
    return WhoisResult(
        domain=domain,
        source_url=source_url,
        status_line=value('Status'),
        creation_date=value('Issue Date'),
        expiry_date=value('Expired Date'),
        delete_state_date=None,
        free_date=None,
        registrant_name=value('Owner Name'),
        registrar_name=value('Registrar Name'),
        registrar_iana_id=None,
        registrar_abuse_contact_email=None,
        registrar_abuse_contact_phone=None,
        domain_status=value('Status'),
        registry_lock=None,
        name_servers=[item.strip() for item in dns_value.split(',') if item.strip()],
        raw_html=body,
        errors=[],
    ), None


def lookup_domain(domain: str, include_html: bool) -> WhoisResult:
    ascii_domain = to_ascii_domain(domain)
    source_url = WHOIS_CHECK_URL.format(domain=urlparse.quote(ascii_domain))

    cache_key = f"{ascii_domain}"
    cached = _cache_get(cache_key)
    if cached is not None:
        if include_html:
            return cached
        return replace(cached, raw_html=None)

    net_vn_result, net_vn_error = fetch_whois_net_vn(ascii_domain, DEFAULT_TIMEOUT)
    if net_vn_result:
        if not include_html:
            net_vn_result.raw_html = None
        _cache_set(cache_key, net_vn_result)
        return net_vn_result

    tld = ascii_domain.rsplit('.', 1)[-1].lower()
    rdap_urls = _rdap_services().get(tld, [])
    for base_url in rdap_urls:
        rdap_url = f'{base_url.rstrip("/")}/domain/{urlparse.quote(ascii_domain)}'
        payload, rdap_err = fetch_json_url(rdap_url, RDAP_TIMEOUT)
        if payload:
            result = parse_rdap(ascii_domain, rdap_url, payload)
            _cache_set(cache_key, result)
            return result

    whois_server = _whois_server_for_domain(ascii_domain)
    if whois_server:
        socket_result, socket_err = lookup_whois_socket(ascii_domain, whois_server)
        if socket_result:
            _cache_set(cache_key, socket_result)
            return socket_result

    if tld == 'vn':
        vnnic_url = VNNIC_WHOIS_URL.format(domain=urlparse.quote(ascii_domain))
        vnnic_text, vnnic_err = fetch_vnnic(ascii_domain, WHOIS_SOCKET_TIMEOUT)
        if vnnic_text and len(vnnic_text.strip()) > 20:
            result = parse_whois_text(ascii_domain, vnnic_url, vnnic_text)
            _cache_set(cache_key, result)
            return result

    page_html, err = fetch_html(source_url)

    if err:
        return WhoisResult(
            domain=ascii_domain,
            source_url=source_url,
            status_line=None,
            creation_date=None,
            expiry_date=None,
            delete_state_date=None,
            free_date=None,
            registrant_name=None,
            registrar_name=None,
            registrar_iana_id=None,
            registrar_abuse_contact_email=None,
            registrar_abuse_contact_phone=None,
            domain_status=None,
            registry_lock=None,
            name_servers=[],
            raw_html=None,
            errors=[err if 'anti-bot' in err else 'WHOIS source temporarily unavailable'],
        )

    result = parse_pavietnam_html(ascii_domain, source_url, page_html)

    # Timeline fields in initial HTML are often placeholders before JS updates.
    result.creation_date = _clean_waiting(result.creation_date)
    result.expiry_date = _clean_waiting(result.expiry_date)
    result.delete_state_date = _clean_waiting(result.delete_state_date)
    result.free_date = _clean_waiting(result.free_date)

    token = _extract_token(page_html)
    if token:
        payload, api_err = fetch_json(
            WHOIS_API_URL,
            {
                "domain": ascii_domain,
                "cmd": "registrarinfo",
                "token": token,
            },
        )
        if api_err:
            result.errors.append(api_err)
        elif payload:
            apply_registrarinfo_payload(result, payload)
    else:
        result.errors.append("Could not extract token from check page")
    if not include_html:
        result.raw_html = None

    if not any([result.creation_date, result.expiry_date, result.registrant_name, result.status_line]):
        result.errors.append("Could not parse WHOIS fields from response")

    _cache_set(cache_key, result)

    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Lookup domain info via whois.pavietnam.net/check/<domain>/"
    )
    parser.add_argument("domain", help="Domain to lookup")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument(
        "--include-html",
        action="store_true",
        help="Include full returned HTML in output",
    )
    parser.add_argument(
        "--save-html",
        metavar="PATH",
        help="Save returned HTML to file",
    )
    return parser


def print_text_output(result: WhoisResult) -> None:
    print(f"Domain: {result.domain}")
    print(f"Source: {result.source_url}")
    print("\n=== Parsed Whois ===")
    print(f"Status: {result.status_line or 'N/A'}")
    print(f"Creation Date: {result.creation_date or 'N/A'}")
    print(f"Expiry Date: {result.expiry_date or 'N/A'}")
    print(f"Delete State: {result.delete_state_date or 'N/A'}")
    print(f"Free Date: {result.free_date or 'N/A'}")
    print(f"Registrant Name: {result.registrant_name or 'N/A'}")
    print(f"Registrar Name: {result.registrar_name or 'N/A'}")
    print(f"Registrar IANA ID: {result.registrar_iana_id or 'N/A'}")
    print(f"Registrar Abuse Contact Email: {result.registrar_abuse_contact_email or 'N/A'}")
    print(f"Registrar Abuse Contact Phone: {result.registrar_abuse_contact_phone or 'N/A'}")
    print(f"Domain Status: {result.domain_status or 'N/A'}")
    print(f"Registry Lock: {result.registry_lock or 'N/A'}")

    if result.name_servers:
        print("Name Servers:")
        for item in result.name_servers:
            print(f"- {item}")
    else:
        print("Name Servers: N/A")

    if result.errors:
        print("\n=== Errors ===")
        for err in result.errors:
            print(f"- {err}")


def print_json_output(result: WhoisResult) -> None:
    payload = {
        "domain": result.domain,
        "source_url": result.source_url,
        "status": result.status_line,
        "creation_date": result.creation_date,
        "expiry_date": result.expiry_date,
        "delete_state_date": result.delete_state_date,
        "free_date": result.free_date,
        "registrant_name": result.registrant_name,
        "registrar_name": result.registrar_name,
        "registrar_iana_id": result.registrar_iana_id,
        "registrar_abuse_contact_email": result.registrar_abuse_contact_email,
        "registrar_abuse_contact_phone": result.registrar_abuse_contact_phone,
        "domain_status": result.domain_status,
        "registry_lock": result.registry_lock,
        "name_servers": result.name_servers,
        "raw_html": result.raw_html,
        "errors": result.errors,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        result = lookup_domain(args.domain, include_html=args.include_html or bool(args.save_html))
    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    if args.save_html and result.raw_html is not None:
        with open(args.save_html, "w", encoding="utf-8") as fp:
            fp.write(result.raw_html)

    if args.json:
        print_json_output(result)
    else:
        print_text_output(result)

    if result.errors and not any([result.creation_date, result.expiry_date, result.registrant_name, result.status_line]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
