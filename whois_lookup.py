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
WHOIS_CHECK_URL = "https://whois.pavietnam.net/check/{domain}/"
WHOIS_API_URL = "https://whois.pavietnam.net/whois.php"

_CACHE_LOCK = threading.Lock()
_WHOIS_CACHE: dict[str, tuple[float, WhoisResult]] = {}


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
        return None, f"HTTP error: {exc.code}"
    except urlerror.URLError as exc:
        return None, f"Network error: {exc}"


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


def lookup_domain(domain: str, include_html: bool) -> WhoisResult:
    ascii_domain = to_ascii_domain(domain)
    source_url = WHOIS_CHECK_URL.format(domain=urlparse.quote(ascii_domain))

    cache_key = f"{ascii_domain}"
    cached = _cache_get(cache_key)
    if cached is not None:
        if include_html:
            return cached
        return replace(cached, raw_html=None)

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
            name_servers=[],
            raw_html=None,
            errors=[err],
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
