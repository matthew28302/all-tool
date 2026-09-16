import sys
import re

file_path = r'c:\Users\NVX\Downloads\all-tool\app.py'

with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. ThreadPools
content = content.replace(
    'executor = ThreadPoolExecutor(max_workers=32)',
    'executor = ThreadPoolExecutor(max_workers=64)'
)
content = content.replace(
    '_acme_worker_pool = ThreadPoolExecutor(max_workers=4)',
    '_acme_worker_pool = ThreadPoolExecutor(max_workers=10)'
)

# 2. Bulk DNS workers
content = content.replace(
    'max_workers = min(6, len(domains))',
    'max_workers = min(30, len(domains))'
)

# 3. SSL Timeouts
content = content.replace(
    'resp = requests.get(test_url, timeout=8, allow_redirects=False)',
    'resp = requests.get(test_url, timeout=3, allow_redirects=False)'
)
content = content.replace(
    'with socket.create_connection((host, port), timeout=7) as sock:',
    'with socket.create_connection((host, port), timeout=3) as sock:'
)

# 4. _request_public_dns_cache_clear sequential -> parallel
clear_dns_old = """    for target_name, ns_ip in dns_targets.items():
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ns_ip]
            resolver.timeout = 3
            resolver.lifetime = 3
            resolver.resolve(domain, 'TXT')
        except Exception:
            pass

        try:
            doh_url = f"https://{ns_ip}/dns-query"
            requests.get(doh_url, params={'name': domain, 'type': 'TXT'}, headers={'accept': 'application/dns-json'}, timeout=5)
        except Exception:
            pass"""
clear_dns_new = """    def _clear_target(ns_ip):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ns_ip]
            resolver.timeout = 2
            resolver.lifetime = 2
            resolver.resolve(domain, 'TXT')
        except Exception:
            pass
        try:
            doh_url = f"https://{ns_ip}/dns-query"
            requests.get(doh_url, params={'name': domain, 'type': 'TXT'}, headers={'accept': 'application/dns-json'}, timeout=3)
        except Exception:
            pass
            
    with ThreadPoolExecutor(max_workers=5) as pool:
        pool.map(_clear_target, dns_targets.values())"""
content = content.replace(clear_dns_old, clear_dns_new)

# 5. _augment_history_sources sequential -> parallel
aug_old = """    related_records = []
    for lookup_type, answer, endpoint, params in related_queries:
        try:
            resp = requests.get(endpoint, params=params, timeout=12)
            payload = resp.json() if resp.content else {}
            if resp.status_code != 200:
                continue

            if isinstance(payload, dict) and payload.get('records'):
                for item in payload.get('records', []):
                    rrtype = (item.get('rrtype') or '').upper()
                    if rrtype and rrtype not in DNS_HISTORY_RECORD_TYPES:
                        continue
                    rrname = item.get('rrname', '')
                    if not _is_history_domain_related(rrname, domain):
                        continue
                    related_records.append(_normalize_history_record(
                        source_id='robtex_related',
                        source_label='Robtex Historic Reverse',
                        rrclass='IN',
                        rrtype=rrtype,
                        query=item.get('rrname', domain),
                        answer=item.get('rrdata', ''),
                        first_seen=item.get('time_first'),
                        last_seen=item.get('time_last'),
                        count=item.get('count'),
                        note=f'{lookup_type}:{answer}',
                    ))
            elif isinstance(payload, list):
                for item in payload:
                    rrtype = (item.get('rrtype') or '').upper()
                    if rrtype and rrtype not in DNS_HISTORY_RECORD_TYPES:
                        continue
                    rrname = item.get('rrname', '')
                    if not _is_history_domain_related(rrname, domain):
                        continue
                    related_records.append(_normalize_history_record(
                        source_id='robtex_related',
                        source_label='Robtex Historic Reverse',
                        rrclass='IN',
                        rrtype=rrtype,
                        query=item.get('rrname', domain),
                        answer=item.get('rrdata', ''),
                        first_seen=item.get('time_first'),
                        last_seen=item.get('time_last'),
                        count=item.get('count'),
                        note=f'{lookup_type}:{answer}',
                    ))
        except Exception:
            pass"""

aug_new = """    related_records = []
    def _fetch_related(query_info):
        lookup_type, answer, endpoint, params = query_info
        out = []
        try:
            resp = requests.get(endpoint, params=params, timeout=8)
            payload = resp.json() if resp.content else {}
            if resp.status_code != 200:
                return out

            items = []
            if isinstance(payload, dict) and payload.get('records'):
                items = payload.get('records', [])
            elif isinstance(payload, list):
                items = payload

            for item in items:
                rrtype = (item.get('rrtype') or '').upper()
                if rrtype and rrtype not in DNS_HISTORY_RECORD_TYPES:
                    continue
                rrname = item.get('rrname', '')
                if not _is_history_domain_related(rrname, domain):
                    continue
                out.append(_normalize_history_record(
                    source_id='robtex_related',
                    source_label='Robtex Historic Reverse',
                    rrclass='IN',
                    rrtype=rrtype,
                    query=item.get('rrname', domain),
                    answer=item.get('rrdata', ''),
                    first_seen=item.get('time_first'),
                    last_seen=item.get('time_last'),
                    count=item.get('count'),
                    note=f'{lookup_type}:{answer}',
                ))
        except Exception:
            pass
        return out

    with ThreadPoolExecutor(max_workers=6) as pool:
        for result in pool.map(_fetch_related, related_queries):
            related_records.extend(result)"""
content = content.replace(aug_old, aug_new)

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Basic refactoring done.")
