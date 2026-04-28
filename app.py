import logging
logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
logger = logging.getLogger(__name__)
#!/usr/bin/env python3
"""
DNS Checker Tool - Ultra Fast Version
Parallel queries, no WHOIS, minimal timeouts
"""

from flask import Flask, render_template, request, jsonify
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography import x509 as cx509
from cryptography.x509.oid import NameOID
from flask_cors import CORS
import dns.resolver
import dns.rdatatype
from datetime import datetime, timezone
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import ssl
import socket
import requests
import re
import json
import time
import subprocess
import hashlib
import base64
import ipaddress
from urllib.parse import urlparse

# ACME / Let's Encrypt
import josepy as jose
import acme.client
import acme.challenges
import acme.messages
from acme import client as acme_client, challenges as acme_challenges, messages as acme_messages

app = Flask(__name__)
CORS(app)
@app.route('/ping')
def ping():
    return 'OK', 200  # Response siêu ngắn

# --- API: Check certificate files on server ---
@app.route('/api/check-cert-file', methods=['POST'])
def api_check_cert_file():
    """Check and parse 3 certificate files: cert domain, ca bundle 1, ca bundle 2"""
    logger.info(f"Received request: /api/check-cert-file | data: {request.json}")
    try:
        data = request.json
        cert_path = data.get('cert_path', '').strip()
        ca_bundle1_path = data.get('ca_bundle1_path', '').strip()
        ca_bundle2_path = data.get('ca_bundle2_path', '').strip()

        if not (cert_path and ca_bundle1_path and ca_bundle2_path):
            logger.warning("Missing one or more file paths in request body")
            return jsonify({"error": "cert_path, ca_bundle1_path, ca_bundle2_path are required"}), 400

        def load_cert_info(path):
            logger.debug(f"Loading cert info from: {path}")
            if not os.path.isfile(path):
                logger.error(f"File not found: {path}")
                return {"error": f"File not found: {path}"}
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                logger.debug(f"Read {len(data)} bytes from {path}")
                # Có thể file chứa nhiều cert, lấy tất cả
                certs = []
                import re
                for cert in re.findall(b'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', data, re.DOTALL):
                    pem = b'-----BEGIN CERTIFICATE-----' + cert + b'-----END CERTIFICATE-----'
                    x = x509.load_pem_x509_certificate(pem, default_backend())
                    certs.append(x)
                logger.debug(f"Found {len(certs)} cert(s) in {path}")
                if not certs:
                    # Có thể là 1 cert duy nhất
                    x = x509.load_pem_x509_certificate(data, default_backend())
                    certs.append(x)
                infos = []
                for c in certs:
                    infos.append({
                        "subject": c.subject.rfc4514_string(),
                        "issuer": c.issuer.rfc4514_string(),
                        "not_valid_before": c.not_valid_before.strftime('%Y-%m-%d %H:%M:%S'),
                        "not_valid_after": c.not_valid_after.strftime('%Y-%m-%d %H:%M:%S'),
                        "serial_number": str(c.serial_number),
                        "signature_algorithm": c.signature_hash_algorithm.name if c.signature_hash_algorithm else None,
                        "version": c.version.name
                    })
                logger.info(f"Parsed {len(infos)} cert(s) from {path}")
                return {"certs": infos}
            except Exception as e:
                logger.error(f"Error parsing {path}: {e}")
                return {"error": str(e)}

        result = {
            "cert_domain": load_cert_info(cert_path),
            "ca_bundle1": load_cert_info(ca_bundle1_path),
            "ca_bundle2": load_cert_info(ca_bundle2_path)
        }
        logger.info(f"Returning result for /api/check-cert-file: {result}")
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Exception in /api/check-cert-file: {e}")
        return jsonify({"error": str(e)}), 500

# Disable caching for all responses
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# DNS Servers configuration
DNS_SERVERS = {
    "Google Public DNS": "8.8.8.8",
    "Google Public DNS Secondary": "8.8.4.4",
    "Cloudflare DNS": "1.1.1.1",
    "Cloudflare DNS Secondary": "1.0.0.1",
    "OpenDNS": "208.67.222.222",
    "OpenDNS Secondary": "208.67.220.220",
    "Quad9": "9.9.9.9",
    "Quad9 Secondary": "149.112.112.112",
    "AdGuard DNS": "94.140.14.14",
    "AdGuard DNS Secondary": "94.140.15.15",
    "CleanBrowsing": "185.228.168.9",
    "CleanBrowsing Secondary": "185.228.169.9",
    "Comodo Secure DNS": "8.26.56.26",
    "Neustar UltraDNS": "156.154.70.1",
    "Verisign Public DNS": "64.6.64.6",
    "Verisign Public DNS Secondary": "64.6.65.6",
    "Level3 DNS": "209.244.0.3",
    "Level3 DNS Secondary": "209.244.0.4",
    "Gcore Public DNS": "95.85.95.85",
    "Oracle Cloud DNS": "216.146.35.35",
    "Yandex DNS": "77.88.8.8",
    "Yandex DNS Secondary": "77.88.8.1",
    "Hurricane Electric": "74.82.42.42",
    "CIRA Canadian Shield": "149.112.121.10",
    "NextDNS": "45.90.28.0",
}

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

# Thread pool for parallel queries
executor = ThreadPoolExecutor(max_workers=32)


def query_dns_record(domain: str, record_type: str, dns_server: str, server_name: str) -> Dict:
    """Query DNS record from specific server - returns result dict"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.cache = None
        resolver.nameservers = [dns_server]
        # Keep fast checks, but avoid overly aggressive timeouts that create false negatives.
        resolver.timeout = 3
        resolver.lifetime = 3
        
        answers = resolver.resolve(domain, record_type)
        results = []
        for rdata in answers:
            if record_type == "MX":
                results.append(f"{rdata.preference} {rdata.exchange}")
            else:
                results.append(str(rdata))
        
        return {
            "server_name": server_name,
            "ip": dns_server,
            "record_type": record_type,
            "status": "success",
            "records": results
        }
    except Exception:
        return {
            "server_name": server_name,
            "ip": dns_server,
            "record_type": record_type,
            "status": "no_records",
            "records": []
        }


def check_dnssec_fast(domain: str) -> Dict:
    """Check DNSSEC status - fast version"""
    result = {
        "enabled": False,
        "valid": False,
        "status": "Not enabled",
        "details": {}
    }
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.cache = None
        resolver.timeout = 3
        resolver.lifetime = 3
        resolver.use_edns(0, dns.flags.DO, 4096)
        
        # Check DNSKEY and DS in parallel
        def check_dnskey():
            try:
                response = resolver.resolve(domain, 'DNSKEY')
                return True, len(list(response))
            except:
                return False, 0
        
        def check_ds():
            try:
                response = resolver.resolve(domain, 'DS')
                return True, len(list(response))
            except:
                return False, 0
        
        with ThreadPoolExecutor(max_workers=2) as ex:
            dnskey_future = ex.submit(check_dnskey)
            ds_future = ex.submit(check_ds)
            
            dnskey_result = dnskey_future.result()
            ds_result = ds_future.result()
        
        result["details"]["dnskey"] = dnskey_result[0]
        result["details"]["dnskey_count"] = dnskey_result[1]
        result["details"]["ds"] = ds_result[0]
        result["details"]["ds_count"] = ds_result[1]
        
        # Determine DNSSEC status
        if result["details"]["dnskey"] and result["details"]["ds"]:
            result["enabled"] = True
            result["valid"] = True
            result["status"] = "Enabled & Signed"
        elif result["details"]["dnskey"]:
            result["enabled"] = True
            result["valid"] = False
            result["status"] = "Enabled (no DS)"
        else:
            result["status"] = "Not enabled"
            
    except Exception as e:
        result["status"] = "Check failed"
    
    return result


def check_dns_fast(domain: str, record_types: List[str]) -> Dict:
    """Ultra-fast DNS check using parallel queries"""
    results = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "dns_records": {},
        "dnssec": {},
        "summary": {}
    }
    
    # Initialize results structure
    for record_type in record_types:
        results["dns_records"][record_type] = {
            "servers": {},
            "success_rate": f"0/{len(DNS_SERVERS)}"
        }
        for server_name, server_ip in DNS_SERVERS.items():
            results["dns_records"][record_type]["servers"][server_name] = {
                "ip": server_ip,
                "status": "pending",
                "records": []
            }
    
    # Create all tasks for parallel execution
    futures = []
    
    # DNS queries - all in parallel
    for record_type in record_types:
        for server_name, server_ip in DNS_SERVERS.items():
            future = executor.submit(query_dns_record, domain, record_type, server_ip, server_name)
            futures.append(future)
    
    # DNSSEC check in parallel
    dnssec_future = executor.submit(check_dnssec_fast, domain)
    
    # Collect DNS results
    for future in as_completed(futures):
        try:
            result = future.result()
            record_type = result["record_type"]
            server_name = result["server_name"]
            
            results["dns_records"][record_type]["servers"][server_name] = {
                "ip": result["ip"],
                "status": result["status"],
                "records": result["records"]
            }
        except:
            pass

    for record_type in record_types:
        for server_data in results["dns_records"][record_type]["servers"].values():
            if server_data["status"] == "pending":
                server_data["status"] = "no_records"
    
    # Get DNSSEC result
    results["dnssec"] = dnssec_future.result()
    
    # Calculate success rates
    for record_type in record_types:
        servers = results["dns_records"][record_type]["servers"]
        success_count = sum(1 for s in servers.values() if s["status"] == "success")
        results["dns_records"][record_type]["success_rate"] = f"{success_count}/{len(DNS_SERVERS)}"
    
    # Summary
    results["summary"] = {
        "dnssec_enabled": results["dnssec"]["enabled"],
        "resolver_count": len(DNS_SERVERS)
    }
    
    return results


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/check-dns', methods=['POST'])
def api_check_dns():
    try:
        data = request.json
        domain = data.get('domain', '').strip().lower()
        record_types = data.get('record_types', ['A'])
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        valid_types = [rt for rt in record_types if rt in RECORD_TYPES]
        if not valid_types:
            valid_types = ['A']
        
        results = check_dns_fast(domain, valid_types)
        return jsonify(results), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/check-dns-basic', methods=['POST'])
def api_check_dns_basic():
    """Quick DNS basic mode: query a single reliable resolver (Google) for A/MX/TXT,
    include a fast DNSSEC check and a lightweight SSL probe (issuer + validity).
    Returns only one representative record per type to keep it fast.
    """
    try:
        data = request.get_json(silent=True) or {}
        domain = data.get('domain', '').strip().lower()
        # Basic mode default record types: A, TXT, MX, SOA, NS
        record_types = data.get('record_types', ['A', 'TXT', 'MX', 'SOA', 'NS'])

        if not domain:
            return jsonify({"error": "Domain is required"}), 400

        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]

        # Limit to allowed record types
        valid_types = [rt for rt in record_types if rt in RECORD_TYPES]
        if not valid_types:
            valid_types = ['A', 'TXT', 'MX', 'SOA', 'NS']

        # Use Google's DNS-over-HTTPS API to fetch a single authoritative-looking answer
        resolver_ip = '8.8.8.8'
        records_out = {}
        for rt in valid_types:
            try:
                # Google's DoH endpoint
                url = 'https://dns.google/resolve'
                params = {'name': domain, 'type': rt}
                resp = requests.get(url, params=params, timeout=4)
                if resp.status_code == 200:
                    j = resp.json()
                    answers = []
                    if 'Answer' in j and isinstance(j['Answer'], list) and len(j['Answer']) > 0:
                        for answer_item in j['Answer']:
                            data_value = answer_item.get('data')
                            if data_value is not None:
                                answers.append(data_value)
                    if answers:
                        records_out[rt] = {"status": "success", "records": answers}
                    else:
                        records_out[rt] = {"status": "no_record", "records": []}
                else:
                    records_out[rt] = {"status": "no_record", "records": []}
            except Exception:
                records_out[rt] = {"status": "no_record", "records": []}

        # Fast DNSSEC check
        dnssec = check_dnssec_fast(domain)

        # Quick SSL probe (issuer + valid_from/valid_to)
        ssl_info = {
            "issuer": None,
            "valid_from": None,
            "valid_to": None,
            "days_remaining": None,
            "error": None
        }
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            cert_der = None
            try:
                with socket.create_connection((domain, 443), timeout=6) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert_der = ssock.getpeercert(binary_form=True)
            except Exception as e:
                cert_der = None

            if cert_der:
                cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                issuer_cn = cert_obj.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                issuer_org = cert_obj.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                valid_from = getattr(cert_obj, 'not_valid_before_utc', cert_obj.not_valid_before.replace(tzinfo=timezone.utc))
                valid_to = getattr(cert_obj, 'not_valid_after_utc', cert_obj.not_valid_after.replace(tzinfo=timezone.utc))
                now_utc = datetime.now(timezone.utc)

                ssl_info.update({
                    "issuer": issuer_cn[0].value if issuer_cn else (issuer_org[0].value if issuer_org else 'Unknown'),
                    "valid_from": valid_from.isoformat(),
                    "valid_to": valid_to.isoformat(),
                    "days_remaining": int((valid_to - now_utc).total_seconds() // 86400)
                })
        except Exception as e:
            ssl_info["error"] = str(e)

        result = {
            "domain": domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "records": records_out,
            "dnssec": dnssec,
            "ssl": ssl_info,
            "resolver_used": {"name": "Google Public DNS", "ip": resolver_ip}
        }

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/record-types', methods=['GET'])
def api_record_types():
    return jsonify({"record_types": RECORD_TYPES}), 200


@app.route('/api/dns-servers', methods=['GET'])
def api_dns_servers():
    return jsonify({"dns_servers": DNS_SERVERS}), 200


@app.route('/api/clear-cache', methods=['POST'])
def api_clear_cache():
    return jsonify({
        "message": "Cache cleared",
        "cache_enabled": False,
        "note": "All DNS queries are always fresh (no caching)"
    }), 200


@app.route('/api/check-ssl', methods=['POST'])
def api_check_ssl():
    """Check SSL certificate for a domain"""
    try:
        data = request.get_json(silent=True) or {}
        domain = data.get('domain', '').strip().lower()
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
        # Clean domain
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
        
        result = {
            "domain": domain,
            "requested_domain": domain,
            "valid": False,
            "issuer": None,
            "issuer_org": None,
            "subject": None,
            "subject_alt_names": [],
            "presented_names": [],
            "matched_name": None,
            "valid_from": None,
            "valid_to": None,
            "days_remaining": None,
            "serial_number": None,
            "signature_algorithm": None,
            "version": None,
            "redirect_detected": False,
            "redirect_chain": [],
            "final_url": None,
            "final_host": None,
            "error": None
        }
        
        try:
            def _collect_redirect_info(host: str) -> dict:
                urls = [f"https://{host}", f"http://{host}"]
                for url in urls:
                    try:
                        resp = requests.get(
                            url,
                            timeout=8,
                            allow_redirects=True,
                            verify=False,
                            headers={"User-Agent": "SSLTool/1.0"}
                        )
                        chain = []
                        for r in resp.history:
                            if r.url and (not chain or chain[-1] != r.url):
                                chain.append(r.url)
                        if resp.url and (not chain or chain[-1] != resp.url):
                            chain.append(resp.url)

                        final_url = chain[-1] if chain else resp.url or url
                        final_host = (urlparse(final_url).hostname or '').lower() if final_url else None

                        return {
                            "redirect_chain": chain,
                            "final_url": final_url,
                            "final_host": final_host,
                        }
                    except Exception:
                        continue
                return {
                    "redirect_chain": [],
                    "final_url": None,
                    "final_host": None,
                }

            # Use multiple TLS context profiles to support both modern and legacy endpoints.
            def _build_tls_contexts() -> List[tuple]:
                contexts: List[tuple] = []

                modern_ctx = ssl.create_default_context()
                modern_ctx.check_hostname = False
                modern_ctx.verify_mode = ssl.CERT_NONE
                contexts.append((modern_ctx, "modern"))

                legacy_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                legacy_ctx.check_hostname = False
                legacy_ctx.verify_mode = ssl.CERT_NONE
                try:
                    legacy_ctx.minimum_version = ssl.TLSVersion.TLSv1
                except Exception:
                    pass
                try:
                    legacy_ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
                except Exception:
                    pass
                if hasattr(ssl, 'OP_LEGACY_SERVER_CONNECT'):
                    try:
                        legacy_ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
                    except Exception:
                        pass
                contexts.append((legacy_ctx, "legacy"))

                compat_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
                compat_ctx.check_hostname = False
                compat_ctx.verify_mode = ssl.CERT_NONE
                try:
                    compat_ctx.set_ciphers('ALL:@SECLEVEL=0')
                except Exception:
                    pass
                contexts.append((compat_ctx, "compat"))

                return contexts

            cert_der = None
            last_handshake_error = None
            tls_profile = None

            for context, profile in _build_tls_contexts():
                try:
                    with socket.create_connection((domain, 443), timeout=7) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert_der = ssock.getpeercert(binary_form=True)
                            tls_profile = profile
                            break
                except ssl.SSLError as handshake_err:
                    last_handshake_error = handshake_err
                    continue

            if not cert_der:
                if last_handshake_error:
                    raise last_handshake_error
                raise ValueError("Cannot complete TLS handshake")

            def _hostname_matches(pattern: str, host: str) -> bool:
                p = (pattern or '').strip().lower()
                h = (host or '').strip().lower()
                if not p or not h:
                    return False
                if p.startswith('*.'):
                    suffix = p[1:]
                    return h.endswith(suffix) and h.count('.') >= p.count('.')
                return h == p
            
            cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())

            valid_from = getattr(cert_obj, 'not_valid_before_utc', cert_obj.not_valid_before.replace(tzinfo=timezone.utc))
            valid_to = getattr(cert_obj, 'not_valid_after_utc', cert_obj.not_valid_after.replace(tzinfo=timezone.utc))
            now_utc = datetime.now(timezone.utc)

            issuer_cn = cert_obj.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            issuer_org = cert_obj.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            subject_cn = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            subject_org = cert_obj.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)

            san_names: List[str] = []
            try:
                san_ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san_names = list(san_ext.value.get_values_for_type(x509.DNSName))
            except x509.ExtensionNotFound:
                san_names = []

            candidate_names = san_names or [subject_cn[0].value] if subject_cn else san_names
            hostname_ok = any(_hostname_matches(name, domain) for name in candidate_names)
            matched_name = next((name for name in candidate_names if _hostname_matches(name, domain)), None)

            redirect_info = _collect_redirect_info(domain)
            redirect_chain = redirect_info.get("redirect_chain", [])
            final_url = redirect_info.get("final_url")
            final_host = redirect_info.get("final_host")

            result["redirect_chain"] = redirect_chain
            result["final_url"] = final_url
            result["final_host"] = final_host
            result["redirect_detected"] = bool(redirect_chain and len(redirect_chain) > 1)

            result["issuer"] = issuer_cn[0].value if issuer_cn else (issuer_org[0].value if issuer_org else 'Unknown')
            result["issuer_org"] = issuer_org[0].value if issuer_org else ''
            result["subject"] = subject_cn[0].value if subject_cn else domain
            result["subject_org"] = subject_org[0].value if subject_org else ''
            result["subject_alt_names"] = san_names[:20]
            result["presented_names"] = candidate_names[:20]
            result["matched_name"] = matched_name
            result["valid_from"] = valid_from.isoformat()
            result["valid_to"] = valid_to.isoformat()
            result["days_remaining"] = int((valid_to - now_utc).total_seconds() // 86400)
            result["serial_number"] = format(cert_obj.serial_number, 'X')
            result["signature_algorithm"] = cert_obj.signature_hash_algorithm.name if cert_obj.signature_hash_algorithm else None
            result["version"] = cert_obj.version.value + 1

            time_ok = valid_from <= now_utc <= valid_to
            result["valid"] = bool(time_ok and hostname_ok)

            if not time_ok:
                if now_utc > valid_to:
                    result["error"] = "Certificate has expired"
                else:
                    result["error"] = "Certificate is not valid yet"
            elif not hostname_ok:
                cert_names_preview = ', '.join(candidate_names[:5]) if candidate_names else '(no SAN/CN)'
                result["error"] = f"Certificate hostname mismatch (requested: {domain}; cert: {cert_names_preview})"

                if final_host and final_host != domain:
                    redirect_match = any(_hostname_matches(name, final_host) for name in candidate_names)
                    if redirect_match:
                        result["error"] = (
                            f"Certificate hostname mismatch for {domain}. "
                            f"Domain appears to redirect to {final_host}, and certificate matches redirect target."
                        )
            elif tls_profile and tls_profile != "modern":
                result["error"] = f"Connected with fallback TLS profile: {tls_profile}"

        except socket.timeout:
            result["error"] = "Connection timed out"
        except socket.gaierror:
            result["error"] = "Domain not found"
        except ConnectionRefusedError:
            result["error"] = "Connection refused (port 443)"
        except Exception as e:
            result["error"] = str(e)
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/check-host', methods=['POST'])
def api_check_host():
    """Check hosting information for IP or domain"""
    try:
        data = request.get_json(silent=True) or {}
        host = data.get('host', '').strip()
        
        if not host:
            return jsonify({"error": "Host is required"}), 400
        
        # Clean input
        host = host.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
        
        result = {
            "input": host,
            "ip": None,
            "hostname": None,
            "reverse_dns": None,
            "provider": None,
            "org": None,
            "asn": None,
            "country": None,
            "city": None,
            "region": None,
            "error": None
        }
        
        # Check if input is IP or domain
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        is_ip = ip_pattern.match(host)

        def _reverse_dns_lookup(ip_value: str) -> Optional[str]:
            try:
                rev_name = dns.reversename.from_address(ip_value)
                resolver = dns.resolver.Resolver(configure=False)
                resolver.cache = None
                resolver.nameservers = ['8.8.8.8', '1.1.1.1']
                resolver.timeout = 3
                resolver.lifetime = 3
                answers = resolver.resolve(rev_name, 'PTR')
                ptr = str(answers[0]).rstrip('.') if answers else None
                return ptr or None
            except Exception:
                return None

        try:
            if is_ip:
                result["ip"] = host
            else:
                # Get IP from domain using DNS (not local resolver)
                result["hostname"] = host
                try:
                    # Use public DNS to resolve, not local hosts file
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = ['8.8.8.8']  # Google DNS
                    resolver.timeout = 2
                    resolver.lifetime = 2
                    answers = resolver.resolve(host, 'A')
                    result["ip"] = str(answers[0])
                except:
                    result["error"] = "Cannot resolve domain"
                    return jsonify(result), 200
            
            # Get hosting details via HTTPS endpoint.
            if result["ip"]:
                try:
                    resp = requests.get(
                        f"https://ipwho.is/{result['ip']}",
                        timeout=3
                    )
                    if resp.status_code == 200:
                        ip_data = resp.json()
                        if ip_data.get('success') is True:
                            conn = ip_data.get('connection', {}) or {}
                            result["provider"] = conn.get('isp', '')
                            result["org"] = conn.get('org', '')
                            result["asn"] = conn.get('asn', '')
                            result["country"] = ip_data.get('country', '')
                            result["city"] = ip_data.get('city', '')
                            result["region"] = ip_data.get('region', '')

                            reverse = _reverse_dns_lookup(result["ip"])
                            result["reverse_dns"] = reverse
                            if is_ip and reverse:
                                result["hostname"] = reverse
                except:
                    pass
                    
        except Exception as e:
            result["error"] = str(e)
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================
#  FREE SSL  –  Let's Encrypt ACME (v2)
# ============================================================

LETSENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING   = "https://acme-staging-v02.api.letsencrypt.org/directory"
ZEROSSL_DIRECTORY     = "https://acme.zerossl.com/v2/DV90"
SSLCOM_DIRECTORY      = "https://acme.ssl.com/sslcom-dv-rsa"

# ZeroSSL EAB credentials
ZEROSSL_EAB_KID      = "kyaE5yBCELSi9mkeIMWGJQ"
ZEROSSL_EAB_HMAC_KEY = "kC71g9TNBKJte-0w_PTYrx3C19q8yETcG-yFKOsCoB3gDFzUsGz6TdRrMvFbZCmKAqd0Au-9dSocDkG6aoxyAA"

# SSL.com EAB credentials (can override via env vars)
SSLCOM_EAB_KID      = os.environ.get("SSLCOM_EAB_KID", "da187936f992")
SSLCOM_EAB_HMAC_KEY = os.environ.get("SSLCOM_EAB_HMAC_KEY", "VyCwgtb-h19dlmNEwIRrqdi9WPGqs21PcyVRWVO6xaI")

ACME_PROVIDER_DIRECTORIES = {
    'letsencrypt': LETSENCRYPT_DIRECTORY,
    'zerossl':     ZEROSSL_DIRECTORY,
    'sslcom':      SSLCOM_DIRECTORY,
}

DNS_CACHE_CLEAR_TARGETS = [
    {
        "provider": "Google Public DNS",
        "label": "8.8.8.8",
        "resolver_ip": "8.8.8.8",
        "doh_url": "https://dns.google/resolve",
    },
    {
        "provider": "Google Public DNS",
        "label": "8.8.4.4",
        "resolver_ip": "8.8.4.4",
        "doh_url": "https://dns.google/resolve",
    },
    {
        "provider": "Cloudflare DNS",
        "label": "1.1.1.1",
        "resolver_ip": "1.1.1.1",
        "doh_url": "https://cloudflare-dns.com/dns-query",
    },
    {
        "provider": "OpenDNS (Cisco)",
        "label": "208.67.222.222",
        "resolver_ip": "208.67.222.222",
        "doh_url": "https://doh.opendns.com/dns-query",
    },
    {
        "provider": "Quad9",
        "label": "9.9.9.9",
        "resolver_ip": "9.9.9.9",
        "doh_url": "https://dns.quad9.net/dns-query",
    },
]

ISSUED_SSL_STORE_PATH = os.path.join(app.root_path, 'acme', 'issued_ssl_store.json')

# In-memory session store  { session_id -> {...} }
_ssl_sessions: Dict[str, dict] = {}
_ssl_sessions_lock = threading.Lock()
_issued_ssl_store_lock = threading.Lock()
_acme_worker_pool = ThreadPoolExecutor(max_workers=4)

SSL_SESSION_TTL_SECONDS = 2 * 60 * 60
SSL_SESSION_MAX_COUNT = 300
SSL_STORE_SYNC_MIN_INTERVAL_SECONDS = 1.5


def _gen_session_id() -> str:
    import uuid
    return str(uuid.uuid4())


def _gen_run_id(prefix: str = 'run') -> str:
    return f"{prefix}-{int(time.time() * 1000)}"


def _get_acme_client(email: str, provider: str = 'letsencrypt') -> tuple:
    """Create an ACME client with a fresh RSA account key.
    Supports: letsencrypt, zerossl (EAB), sslcom (EAB).
    """
    directory_url = ACME_PROVIDER_DIRECTORIES.get(provider, LETSENCRYPT_DIRECTORY)
    account_key_pem_bytes = _generate_rsa_private_key_pem(2048)
    account_key = jose.JWKRSA.load(account_key_pem_bytes)
    net = acme_client.ClientNetwork(account_key, user_agent="SSLTool/1.0", verify_ssl=True)
    directory = acme_messages.Directory.from_json(net.get(directory_url).json())
    client = acme_client.ClientV2(directory, net)
    # Build registration kwargs
    new_reg_kwargs: dict = dict(email=email, terms_of_service_agreed=True)
    # ZeroSSL requires External Account Binding (EAB)
    if provider == 'zerossl':
        eab = acme_messages.ExternalAccountBinding.from_data(
            account_public_key=account_key.public_key(),
            kid=ZEROSSL_EAB_KID,
            hmac_key=ZEROSSL_EAB_HMAC_KEY,
            directory=directory,
        )
        new_reg_kwargs['external_account_binding'] = eab
    # SSL.com also requires External Account Binding (EAB)
    elif provider == 'sslcom':
        if not SSLCOM_EAB_KID or not SSLCOM_EAB_HMAC_KEY or '...' in SSLCOM_EAB_HMAC_KEY:
            raise ValueError("SSL.com EAB chưa đầy đủ. Cập nhật SSLCOM_EAB_KID và SSLCOM_EAB_HMAC_KEY trong môi trường/server.")
        eab = acme_messages.ExternalAccountBinding.from_data(
            account_public_key=account_key.public_key(),
            kid=SSLCOM_EAB_KID,
            hmac_key=SSLCOM_EAB_HMAC_KEY,
            directory=directory,
        )
        new_reg_kwargs['external_account_binding'] = eab
    client.new_account(
        acme_messages.NewRegistration.from_data(**new_reg_kwargs)
    )
    return client, account_key_pem_bytes


def _generate_rsa_private_key_pem(key_size: int = 2048) -> bytes:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def _generate_csr_pem(domain: str, sans: list, private_key_pem: bytes) -> bytes:
    """Generate a CSR for the given domain + SANs."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    alt_names = []
    all_domains = list(dict.fromkeys([domain] + [s for s in sans if s and s != domain]))
    for d in all_domains:
        alt_names.append(cx509.DNSName(d))
    builder = (
        cx509.CertificateSigningRequestBuilder()
        .subject_name(cx509.Name([
            cx509.NameAttribute(NameOID.COMMON_NAME, domain),
        ]))
        .add_extension(
            cx509.SubjectAlternativeName(alt_names),
            critical=False
        )
    )
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())
    return csr.public_bytes(serialization.Encoding.PEM)


def _b64_jose(data: bytes) -> str:
    """Base64url encode (no padding) – JOSE style."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _split_identifier_tokens(raw_value) -> List[str]:
    """Split identifiers from string/list input by comma/space/newline/semicolon."""
    if raw_value is None:
        return []
    if isinstance(raw_value, (list, tuple, set)):
        raw_items = [str(x) for x in raw_value if str(x).strip()]
    else:
        raw_items = [str(raw_value)]

    tokens: List[str] = []
    for item in raw_items:
        for part in re.split(r'[\s,;]+', item.strip()):
            if part:
                tokens.append(part)
    return tokens


def _normalize_identifier(raw_identifier: str) -> str:
    """
    Normalize & validate domain identifier for ACME.
    Supports wildcard only in form *.example.com
    """
    value = (raw_identifier or '').strip().lower().rstrip('.')
    if not value:
        raise ValueError("Identifier is empty")

    # Remove URL scheme/path/port if user pasted full URL
    if '://' in value:
        parsed = urlparse(value)
        value = parsed.netloc or parsed.path
    value = value.split('/')[0]
    if ':' in value and value.count(':') == 1:
        value = value.split(':')[0]

    wildcard = value.startswith('*.')
    if '*' in value and not wildcard:
        raise ValueError(f"Invalid wildcard format: {raw_identifier}")

    host = value[2:] if wildcard else value
    if not host or '.' not in host:
        raise ValueError(f"Invalid domain (must be FQDN): {raw_identifier}")
    if '..' in host:
        raise ValueError(f"Invalid domain (double dots): {raw_identifier}")

    # IDN support (unicode -> punycode)
    try:
        host_ascii = host.encode('idna').decode('ascii')
    except Exception:
        raise ValueError(f"Invalid internationalized domain: {raw_identifier}")

    labels = host_ascii.split('.')
    for label in labels:
        if not label:
            raise ValueError(f"Invalid domain label in: {raw_identifier}")
        if len(label) > 63:
            raise ValueError(f"Domain label too long in: {raw_identifier}")
        if label.startswith('-') or label.endswith('-'):
            raise ValueError(f"Invalid hyphen position in: {raw_identifier}")
        if not re.fullmatch(r'[a-z0-9-]+', label):
            raise ValueError(f"Invalid characters in: {raw_identifier}")

    if wildcard and host_ascii.startswith('*.'):
        raise ValueError(f"Invalid wildcard format: {raw_identifier}")

    return ('*.' + host_ascii) if wildcard else host_ascii


def _parse_identifiers(domain_input, sans_input) -> tuple:
    """Return (primary_domain, sans_list) from mixed domain/sans inputs."""
    domain_tokens = _split_identifier_tokens(domain_input)
    sans_tokens = _split_identifier_tokens(sans_input)

    if not domain_tokens:
        raise ValueError("domain is required")

    normalized: List[str] = []
    for token in domain_tokens + sans_tokens:
        normalized.append(_normalize_identifier(token))

    # Deduplicate while preserving order
    uniq = list(dict.fromkeys([x for x in normalized if x]))
    primary = uniq[0]
    sans = [x for x in uniq[1:] if x != primary]
    return primary, sans


def _is_likely_apex_domain(host: str) -> bool:
    """Heuristic: detect apex/root domain to auto-add www for single-domain requests."""
    if not host or host.startswith('*.'):
        return False
    labels = host.split('.')
    if len(labels) <= 2:
        return True

    # common 2-level public suffixes (practical subset)
    two_level_suffixes = {
        'com.vn', 'net.vn', 'org.vn', 'edu.vn', 'gov.vn', 'id.vn',
        'co.uk', 'org.uk', 'com.au', 'co.jp', 'co.kr', 'com.sg'
    }
    suffix2 = '.'.join(labels[-2:])
    if suffix2 in two_level_suffixes and len(labels) == 3:
        return True
    return False


def _ensure_issued_ssl_store() -> None:
    os.makedirs(os.path.dirname(ISSUED_SSL_STORE_PATH), exist_ok=True)
    if not os.path.isfile(ISSUED_SSL_STORE_PATH):
        with open(ISSUED_SSL_STORE_PATH, 'w', encoding='utf-8') as f:
            json.dump([], f, ensure_ascii=False, indent=2)


def _load_issued_ssl_store() -> List[dict]:
    _ensure_issued_ssl_store()
    try:
        with open(ISSUED_SSL_STORE_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_issued_ssl_store(items: List[dict]) -> None:
    _ensure_issued_ssl_store()
    with open(ISSUED_SSL_STORE_PATH, 'w', encoding='utf-8') as f:
        json.dump(items, f, ensure_ascii=False, indent=2)


def _ensure_ssl_store_writable() -> None:
    target_dir = os.path.dirname(ISSUED_SSL_STORE_PATH)
    os.makedirs(target_dir, exist_ok=True)
    if not os.access(target_dir, os.W_OK):
        raise PermissionError(f"Không có quyền ghi file tại: {target_dir}")


def _extract_cert_summary(cert_pem: str) -> dict:
    summary = {
        "subject": None,
        "issuer": None,
        "valid_from": None,
        "valid_to": None,
        "serial_number": None,
    }
    if not cert_pem:
        return summary
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        summary.update({
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "valid_from": cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S'),
            "valid_to": cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S'),
            "serial_number": str(cert.serial_number),
        })
    except Exception:
        pass
    return summary


def _request_public_dns_cache_clear(dns_name: str) -> List[dict]:
    """
    Best-effort refresh request to public DNS resolvers.
    Public resolvers generally do not expose hard cache purge APIs,
    so we trigger fresh TXT lookups via DNS + DoH endpoints.
    """
    results: List[dict] = []
    for target in DNS_CACHE_CLEAR_TARGETS:
        provider = target.get("provider")
        label = target.get("label")
        resolver_ip = target.get("resolver_ip")
        doh_url = target.get("doh_url")

        entry = {
            "provider": provider,
            "resolver": label,
            "dns_name": dns_name,
            "dns_query": "skipped",
            "doh_query": "skipped",
            "ok": False,
            "note": "Best-effort refresh request sent",
        }

        # 1) Direct DNS query to target resolver
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.cache = None
            resolver.nameservers = [resolver_ip]
            resolver.timeout = 3
            resolver.lifetime = 3
            resolver.resolve(dns_name, 'TXT', raise_on_no_answer=False)
            entry["dns_query"] = "ok"
        except Exception as e:
            entry["dns_query"] = f"fail: {str(e)}"

        # 2) DoH query (where available)
        try:
            if doh_url:
                params = {
                    "name": dns_name,
                    "type": "TXT",
                    "cd": "0",
                    "do": "1",
                    "ts": str(int(time.time() * 1000)),
                }
                headers = {
                    "accept": "application/dns-json"
                }
                resp = requests.get(doh_url, params=params, headers=headers, timeout=5)
                if resp.status_code < 400:
                    entry["doh_query"] = "ok"
                else:
                    entry["doh_query"] = f"fail: HTTP {resp.status_code}"
        except Exception as e:
            entry["doh_query"] = f"fail: {str(e)}"

        entry["ok"] = entry["dns_query"] == "ok" or entry["doh_query"] == "ok"
        results.append(entry)
    return results


def _extract_acme_error_payload(err: Exception) -> dict:
    payload = {
        "type": "acme:error:unknown",
        "detail": str(err),
    }

    for attr_name in ("problem", "error"):
        obj = getattr(err, attr_name, None)
        if obj is None:
            continue
        typ = getattr(obj, "typ", None) or getattr(obj, "type", None)
        detail = getattr(obj, "detail", None)
        if typ:
            payload["type"] = str(typ)
        if detail:
            payload["detail"] = str(detail)

    text = str(err)
    if payload["detail"] == text:
        json_match = re.search(r'\{.*\}', text)
        if json_match:
            try:
                parsed = json.loads(json_match.group(0))
                payload["type"] = str(parsed.get("type") or payload["type"])
                payload["detail"] = str(parsed.get("detail") or payload["detail"])
            except Exception:
                pass
    return payload


def _map_acme_error_message(acme_error: dict) -> str:
    err_type = (acme_error or {}).get("type", "").lower()
    detail = (acme_error or {}).get("detail", "Lỗi ACME").strip()

    if "caa" in err_type or "caa" in detail.lower():
        return "Domain chặn SSL (CAA). Kiểm tra lại CAA record."
    if "dns" in err_type or "nxdomain" in detail.lower():
        return "DNS chưa đúng hoặc chưa propagate."
    if "rate" in err_type or "rate" in detail.lower():
        return "Vượt giới hạn cấp phát. Hãy thử lại sau."
    if "malformed" in err_type:
        return "Request không hợp lệ (malformed). Kiểm tra lại trạng thái challenge/order."
    return detail


def _resolve_caa_records(domain: str) -> List[str]:
    records: List[str] = []
    for resolver_ip in ('8.8.8.8', '1.1.1.1'):
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.cache = None
            resolver.nameservers = [resolver_ip]
            resolver.timeout = 3
            resolver.lifetime = 3
            answers = resolver.resolve(domain, 'CAA')
            for rdata in answers:
                records.append(str(rdata))
            if records:
                break
        except Exception:
            continue
    return list(dict.fromkeys(records))


def _check_caa_policy(domains: List[str], provider: str) -> dict:
    allowed_issue_map = {
        'letsencrypt': ['letsencrypt.org'],
        'zerossl': ['sectigo.com', 'zerossl.com'],
        'sslcom': ['ssl.com'],
    }
    allowed = allowed_issue_map.get(provider, allowed_issue_map['letsencrypt'])

    checked_domains = []
    for d in domains:
        host = (d or '').replace('*.', '', 1)
        if not host:
            continue
        checked_domains.append(host)

    for host in list(dict.fromkeys(checked_domains)):
        caa_records = _resolve_caa_records(host)
        if not caa_records:
            continue

        normalized = [r.lower() for r in caa_records]
        if any(' issue "' in r or ' issuewild "' in r for r in normalized):
            if not any(any(issuer in r for issuer in allowed) for r in normalized):
                return {
                    "ok": False,
                    "domain": host,
                    "records": caa_records,
                    "message": f"CAA record không cho phép nhà cung cấp {provider}",
                }

    return {"ok": True, "message": "CAA check passed"}


def _set_session_status(session_id: str, status: str, extra: Optional[dict] = None) -> Optional[dict]:
    with _ssl_sessions_lock:
        sess = _ssl_sessions.get(session_id)
        if not sess:
            return None
        sess['status'] = status
        if extra:
            sess.update(extra)
        _ssl_sessions[session_id] = sess
        return sess


def _cleanup_expired_ssl_sessions() -> None:
    now = time.time()
    with _ssl_sessions_lock:
        if not _ssl_sessions:
            return

        to_delete = []
        for sid, sess in _ssl_sessions.items():
            created_at = float(sess.get('created_at', now))
            status = sess.get('status', 'pending')
            if now - created_at > SSL_SESSION_TTL_SECONDS and status != 'finalizing':
                to_delete.append(sid)

        for sid in to_delete:
            _ssl_sessions.pop(sid, None)

        # Hard cap to avoid memory growth on high traffic.
        if len(_ssl_sessions) > SSL_SESSION_MAX_COUNT:
            ordered = sorted(_ssl_sessions.items(), key=lambda kv: float(kv[1].get('created_at', now)))
            overflow = len(_ssl_sessions) - SSL_SESSION_MAX_COUNT
            for sid, _ in ordered[:overflow]:
                _ssl_sessions.pop(sid, None)


def _query_txt_values(dns_name: str, resolvers: Optional[List[str]] = None) -> List[str]:
    values: List[str] = []
    resolver_ips = resolvers or ['8.8.8.8', '1.1.1.1']
    for resolver_ip in resolver_ips:
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.cache = None
            resolver.nameservers = [resolver_ip]
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = resolver.resolve(dns_name, 'TXT')
            for rdata in answers:
                for s in rdata.strings:
                    values.append(s.decode() if isinstance(s, bytes) else str(s))
        except Exception:
            continue
    return list(dict.fromkeys(values))


def _acme_status_to_str(status_obj) -> str:
    if status_obj is None:
        return 'pending'
    for attr in ('name', 'value'):
        value = getattr(status_obj, attr, None)
        if value:
            return str(value).lower()
    raw = str(status_obj).strip().lower()
    if raw.startswith('status(') and raw.endswith(')'):
        raw = raw[len('status('):-1]
    return raw


def _poll_authorizations_until_done(sess: dict, timeout_seconds: int = 90) -> tuple:
    acme_cl: acme_client.ClientV2 = sess['acme_client']
    authz_list = sess.get('authz_list', [])
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        all_valid = True
        any_invalid = False
        updated_authz_list = []
        domain_statuses = []

        for authz in authz_list:
            updated = acme_cl.poll(authz)
            if isinstance(updated, tuple):
                updated_auth = updated[0]
            else:
                updated_auth = updated
            updated_authz_list.append(updated_auth)

            auth_status = _acme_status_to_str(getattr(updated_auth.body, 'status', 'pending'))
            auth_domain = updated_auth.body.identifier.value
            domain_statuses.append({"domain": auth_domain, "status": auth_status})

            if auth_status == 'invalid':
                any_invalid = True
                all_valid = False
            elif auth_status != 'valid':
                all_valid = False

        sess['authz_list'] = updated_authz_list
        sess['domains'] = [
            {
                **d,
                "status": next((x['status'] for x in domain_statuses if x['domain'] == d.get('domain')), d.get('status', 'pending')),
            }
            for d in sess.get('domains', [])
        ]

        if any_invalid:
            return False, "invalid", domain_statuses
        if all_valid:
            return True, "valid", domain_statuses
        time.sleep(2)

    return False, "timeout", [{"domain": d.get('domain'), "status": d.get('status', 'pending')} for d in sess.get('domains', [])]


def _finalize_order_and_collect_cert(session_id: str, sess: dict) -> tuple:
    acme_cl: acme_client.ClientV2 = sess['acme_client']
    order = sess['order']

    _set_session_status(session_id, 'finalizing')
    _append_session_log(session_id, 'Đang finalize order và chờ cấp chứng chỉ...', 'loading', force_sync=True)
    _patch_issued_ssl_record_by_session(session_id, {"status": "finalizing"})

    deadline = time.time() + 90
    finalized_order = None
    while time.time() < deadline:
        try:
            order_resource = acme_cl.poll_and_finalize(order)
            if order_resource.fullchain_pem:
                finalized_order = order_resource
                break
        except Exception as poll_err:
            acme_error = _extract_acme_error_payload(poll_err)
            _set_session_status(session_id, 'invalid', {"last_error": acme_error})
            _append_session_log(session_id, _map_acme_error_message(acme_error), 'error', force_sync=True)
            _patch_issued_ssl_record_by_session(session_id, {
                "status": "invalid",
                "last_error": acme_error,
            })
            return None, acme_error
        time.sleep(2)

    if not finalized_order:
        acme_error = {
            "type": "acme:error:timeout",
            "detail": "Timeout while waiting order status to become valid",
        }
        _set_session_status(session_id, 'pending', {"last_error": acme_error})
        _append_session_log(session_id, 'Timeout khi chờ cấp chứng chỉ. Có thể retry.', 'error', force_sync=True)
        _patch_issued_ssl_record_by_session(session_id, {
            "status": "pending",
            "last_error": acme_error,
        })
        return None, acme_error

    fullchain = finalized_order.fullchain_pem
    cert_blocks = re.findall(
        r'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)',
        fullchain, re.DOTALL
    )
    leaf_cert = cert_blocks[0] if cert_blocks else ''
    ca_bundle = '\n'.join(cert_blocks[1:]) if len(cert_blocks) > 1 else ''

    result = {
        "certificate": leaf_cert,
        "private_key": sess['domain_key_pem'],
        "ca_bundle": ca_bundle,
        "full_chain": fullchain,
        "domain": sess['domain'],
    }
    return result, None


def _run_acme_background_flow(session_id: str) -> None:
    try:
        with _ssl_sessions_lock:
            sess = _ssl_sessions.get(session_id)
            if not sess:
                return
        _append_session_log(session_id, 'Đã gửi challenge tới ACME. Đang polling authorization...', 'loading')

        auth_ok, auth_status, auth_domains = _poll_authorizations_until_done(sess, timeout_seconds=90)
        sess['domains'] = [
            {
                **d,
                "status": next((x['status'] for x in auth_domains if x['domain'] == d.get('domain')), d.get('status', 'pending')),
            }
            for d in sess.get('domains', [])
        ]

        if not auth_ok:
            next_status = 'invalid' if auth_status == 'invalid' else 'pending'
            _set_session_status(session_id, next_status, {"domains": sess.get('domains', [])})
            if auth_status == 'invalid':
                _append_session_log(session_id, 'Authorization invalid. Kiểm tra lại DNS/CAA rồi retry.', 'error')
            else:
                _append_session_log(session_id, 'Authorization chưa hoàn tất. Bạn có thể bấm Verify lại.', 'info')
            _sync_session_to_store(session_id)
            return

        _set_session_status(session_id, 'valid', {"domains": sess.get('domains', [])})
        _append_session_log(session_id, 'Tất cả authorization đã valid.', 'success', force_sync=True)
        _sync_session_to_store(session_id, force=True)

        finalize_result, finalize_error = _finalize_order_and_collect_cert(session_id, sess)
        if finalize_error:
            _set_session_status(session_id, 'invalid', {"last_error": finalize_error})
            _sync_session_to_store(session_id, force=True)
            return

        with _ssl_sessions_lock:
            if session_id in _ssl_sessions:
                _ssl_sessions[session_id]['status'] = 'issued'
                _ssl_sessions[session_id]['result'] = finalize_result

        _ensure_ssl_store_writable()
        _upsert_issued_ssl_record(_build_issued_ssl_record(sess, finalize_result))
        _append_session_log(session_id, 'Đã cấp cert thành công.', 'success', force_sync=True)
        _sync_session_to_store(session_id, force=True)
    except Exception as e:
        acme_error = _extract_acme_error_payload(e)
        _set_session_status(session_id, 'invalid', {"last_error": acme_error})
        _append_session_log(session_id, _map_acme_error_message(acme_error), 'error', force_sync=True)
        _sync_session_to_store(session_id, force=True)
    finally:
        with _ssl_sessions_lock:
            if session_id in _ssl_sessions:
                _ssl_sessions[session_id]['worker_running'] = False


def _upsert_issued_ssl_record(record: dict) -> dict:
    with _issued_ssl_store_lock:
        items = _load_issued_ssl_store()

        # Priority 1: match by explicit id
        existing_idx = None
        record_id = record.get('id')
        if record_id:
            existing_idx = next((i for i, item in enumerate(items) if item.get('id') == record_id), None)

        # Priority 2: match by session_id (for in-progress records)
        if existing_idx is None and record.get('session_id'):
            sess_id = record.get('session_id')
            existing_idx = next((i for i, item in enumerate(items) if item.get('session_id') == sess_id), None)

        if existing_idx is not None:
            existing_id = items[existing_idx].get('id')
            record['id'] = existing_id or record.get('id') or _gen_session_id()
            record['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            items[existing_idx] = record
        else:
            record['id'] = record.get('id') or _gen_session_id()
            record['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            items.insert(0, record)
        _save_issued_ssl_store(items)
        return record


def _patch_issued_ssl_record_by_session(session_id: str, updates: dict) -> Optional[dict]:
    with _issued_ssl_store_lock:
        items = _load_issued_ssl_store()
        idx = next((i for i, item in enumerate(items) if item.get('session_id') == session_id), None)
        if idx is None:
            return None
        item = dict(items[idx])
        item.update(updates or {})
        item['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        items[idx] = item
        _save_issued_ssl_store(items)
        return item


def _sync_session_to_store(session_id: str, force: bool = False) -> None:
    with _ssl_sessions_lock:
        sess = _ssl_sessions.get(session_id)
        if not sess:
            return
        now = time.time()
        last_sync = float(sess.get("last_store_sync_at", 0.0) or 0.0)
        if not force and (now - last_sync) < SSL_STORE_SYNC_MIN_INTERVAL_SECONDS:
            return
        sess["last_store_sync_at"] = now
        _ssl_sessions[session_id] = sess
        updates = {
            "status": sess.get("status", "pending"),
            "domains": sess.get("domains", []),
            "last_error": sess.get("last_error"),
            "progress_logs": sess.get("progress_logs", []),
            "progress_text": sess.get("progress_text"),
        }
    _patch_issued_ssl_record_by_session(session_id, updates)


def _append_session_log(session_id: str, message: str, level: str = "info", force_sync: bool = False, run_id: Optional[str] = None) -> None:
    log_item = {
        "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "level": level,
        "message": message,
    }
    with _ssl_sessions_lock:
        sess = _ssl_sessions.get(session_id)
        if not sess:
            return
        active_run_id = run_id or sess.get("current_run_id") or "default"
        log_item["run_id"] = active_run_id
        logs = list(sess.get("progress_logs", []))
        logs.append(log_item)
        sess["progress_logs"] = logs[-80:]
        sess["progress_text"] = message
        _ssl_sessions[session_id] = sess
    _sync_session_to_store(session_id, force=force_sync)


def _build_pending_ssl_record(sess: dict, session_id: str) -> dict:
    return {
        "id": sess.get('storage_id'),
        "session_id": session_id,
        "domain": sess.get('domain'),
        "sans": sess.get('sans', []),
        "challenge_type": sess.get('challenge_type'),
        "issued_at": None,
        "status": "pending",
        "certificate": "",
        "private_key": "",
        "ca_bundle": "",
        "full_chain": "",
        "valid_from": None,
        "valid_to": None,
        "subject": None,
        "issuer": None,
        "serial_number": None,
        "provider": sess.get('provider', 'letsencrypt'),
        "email": sess.get('email'),
        "challenges": sess.get('challenges', []),
        "order_url": sess.get('order_url') or sess.get('order_uri'),
        "finalize_url": sess.get('finalize_url'),
        "auth_urls": sess.get('auth_urls', []),
        "domains": sess.get('domains', []),
        "created_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "last_check_at": None,
        "last_check_results": [],
        "dns_cache_clear": [],
        "progress_logs": sess.get('progress_logs', []),
        "progress_text": sess.get('progress_text', 'Đang chờ xác thực'),
        "last_error": sess.get('last_error'),
        "current_run_id": sess.get('current_run_id'),
    }


def _build_issued_ssl_record(sess: dict, result: dict) -> dict:
    cert_summary = _extract_cert_summary(result.get('certificate', ''))
    return {
        "id": sess.get('storage_id'),
        "session_id": sess.get('session_id'),
        "domain": sess.get('domain'),
        "sans": sess.get('sans', []),
        "challenge_type": sess.get('challenge_type'),
        "issued_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "status": "issued",
        "certificate": result.get('certificate', ''),
        "private_key": result.get('private_key', ''),
        "ca_bundle": result.get('ca_bundle', ''),
        "full_chain": result.get('full_chain', ''),
        "valid_from": cert_summary.get('valid_from'),
        "valid_to": cert_summary.get('valid_to'),
        "subject": cert_summary.get('subject'),
        "issuer": cert_summary.get('issuer'),
        "serial_number": cert_summary.get('serial_number'),
        "provider": sess.get('provider', 'letsencrypt'),
        "email": sess.get('email'),
        "order_url": sess.get('order_url') or sess.get('order_uri'),
        "finalize_url": sess.get('finalize_url'),
        "auth_urls": sess.get('auth_urls', []),
        "domains": sess.get('domains', []),
        "progress_logs": sess.get('progress_logs', []),
        "progress_text": 'Đã cấp chứng chỉ thành công',
        "last_error": sess.get('last_error'),
        "current_run_id": sess.get('current_run_id'),
    }


@app.route('/api/ssl-free/start', methods=['POST'])
def api_ssl_free_start():
    """
    Step 1 & 2: Generate RSA key + CSR, send ACME order, get challenges.
    Body: { domain, sans (optional list), challenge_type: "dns-01"|"http-01", email, provider: "letsencrypt"|"zerossl"|"sslcom" }
    Returns: { session_id, challenges: [{type, domain, token, key_auth, dns_name, dns_value, file_path, file_content}] }
    """
    try:
        _cleanup_expired_ssl_sessions()
        data = request.json or {}
        domain_input = data.get('domain', '')
        sans_raw = data.get('sans', [])
        challenge_type = data.get('challenge_type', 'dns-01')  # dns-01 | http-01
        email = (data.get('email') or '').strip()
        provider = data.get('provider', 'letsencrypt')
        if provider not in ACME_PROVIDER_DIRECTORIES:
            provider = 'letsencrypt'

        domain, sans = _parse_identifiers(domain_input, sans_raw)
        all_identifiers = [domain] + sans

        # Provider capability rules
        if provider == 'sslcom':
            if any(x.startswith('*.') for x in all_identifiers):
                return jsonify({"error": "SSL.com không hỗ trợ wildcard domain"}), 400
            if len(all_identifiers) > 1:
                return jsonify({"error": "SSL.com chỉ hỗ trợ 1 domain (không multi-domain/SAN)"}), 400

        if provider == 'zerossl' and any(x.startswith('*.') for x in all_identifiers):
            return jsonify({"error": "ZeroSSL không hỗ trợ wildcard domain"}), 400

        # Default behavior (Let's Encrypt + ZeroSSL):
        # if only apex primary domain is provided, automatically include www.<domain>
        if (
            provider in ('letsencrypt', 'zerossl')
            and len(sans) == 0
            and not domain.startswith('*.')
            and not domain.startswith('www.')
            and _is_likely_apex_domain(domain)
        ):
            sans = [f'www.{domain}']
            all_identifiers = [domain] + sans

        if any(x.startswith('*.') for x in all_identifiers) and challenge_type != 'dns-01':
            return jsonify({"error": "Wildcard domain chỉ hỗ trợ với DNS-01 challenge"}), 400

        if not email:
            non_wildcard = next((d for d in [domain] + sans if not d.startswith('*.')), domain)
            email = 'admin@' + non_wildcard.replace('www.', '', 1).replace('*.', '', 1)

        caa_check = _check_caa_policy([domain] + sans, provider)
        if not caa_check.get("ok"):
            return jsonify({
                "error": caa_check.get("message") or "CAA check failed",
                "acme_error": {
                    "type": "acme:error:caa",
                    "detail": caa_check.get("message") or "CAA policy blocks issuance",
                },
                "caa": caa_check,
            }), 400

        logger.info(f"[ACME] start: domain={domain} sans={sans} type={challenge_type} provider={provider}")

        # 1. Generate domain private key
        domain_key_pem = _generate_rsa_private_key_pem(2048)

        # 2. Generate CSR
        csr_pem = _generate_csr_pem(domain, sans, domain_key_pem)

        # 3. Create ACME client + place order
        acme_cl, account_key_pem = _get_acme_client(email, provider=provider)
        order = acme_cl.new_order(csr_pem)

        # 4. Extract challenges
        challenge_infos = []
        authz_list = list(order.authorizations)
        domain_states = []

        for authz in authz_list:
            authz_domain = authz.body.identifier.value
            for ch in authz.body.challenges:
                ch_type = ch.chall.typ
                if ch_type != challenge_type:
                    continue
                token = ch.chall.token
                key_auth = ch.chall.key_authorization(jose.JWKRSA.load(account_key_pem))

                if challenge_type == 'dns-01':
                    # SHA256 of key_auth, base64url
                    digest = hashlib.sha256(key_auth.encode()).digest()
                    dns_value = _b64_jose(digest)
                    challenge_url = getattr(ch, 'uri', None)
                    challenge_infos.append({
                        "type": "dns-01",
                        "domain": authz_domain,
                        "token": _b64_jose(token),
                        "key_auth": key_auth,
                        "dns_name": f"_acme-challenge.{authz_domain}",
                        "dns_value": dns_value,
                        "auth_url": getattr(authz, 'uri', None),
                        "challenge_url": challenge_url,
                        "status": "pending",
                    })
                else:  # http-01
                    token_str = _b64_jose(token)
                    challenge_url = getattr(ch, 'uri', None)
                    challenge_infos.append({
                        "type": "http-01",
                        "domain": authz_domain,
                        "token": token_str,
                        "key_auth": key_auth,
                        "file_path": f"/.well-known/acme-challenge/{token_str}",
                        "file_content": key_auth,
                        "auth_url": getattr(authz, 'uri', None),
                        "challenge_url": challenge_url,
                        "status": "pending",
                    })
                    
                domain_states.append({
                    "domain": authz_domain,
                    "auth_url": getattr(authz, 'uri', None),
                    "challenge_url": challenge_url,
                    "status": "pending",
                    "last_error": None,
                })
                break  # one challenge per authz

        if not challenge_infos:
            return jsonify({"error": f"No {challenge_type} challenges found in authorization"}), 400

        # 5. Store session
        session_id = _gen_session_id()
        with _ssl_sessions_lock:
            _ssl_sessions[session_id] = {
                "session_id": session_id,
                "domain": domain,
                "sans": sans,
                "email": email,
                "provider": provider,
                "challenge_type": challenge_type,
                "domain_key_pem": domain_key_pem.decode(),
                "csr_pem": csr_pem.decode(),
                "account_key_pem": account_key_pem.decode(),
                "order_url": order.uri,
                "order_uri": order.uri,
                "finalize_url": str(getattr(order.body, 'finalize', '') or ''),
                "auth_urls": [getattr(a, 'uri', None) for a in authz_list],
                "authz_list": authz_list,
                "acme_client": acme_cl,
                "order": order,
                "domains": domain_states,
                "challenges": challenge_infos,
                "created_at": time.time(),
                "status": "pending",
                "worker_running": False,
                "progress_logs": [],
                "progress_text": "Đang chờ bạn cấu hình bản ghi xác thực",
                "current_run_id": _gen_run_id('init'),
            }

        with _ssl_sessions_lock:
            pending_sess = _ssl_sessions.get(session_id)

        _append_session_log(session_id, 'Order ACME đã tạo. Vui lòng thêm bản ghi xác thực.', 'success', force_sync=True)

        pending_record = _upsert_issued_ssl_record(_build_pending_ssl_record(pending_sess, session_id))

        with _ssl_sessions_lock:
            if session_id in _ssl_sessions:
                _ssl_sessions[session_id]['storage_id'] = pending_record.get('id')

        return jsonify({
            "session_id": session_id,
            "storage_id": pending_record.get('id'),
            "domain": domain,
            "challenge_type": challenge_type,
            "order_url": order.uri,
            "finalize_url": str(getattr(order.body, 'finalize', '') or ''),
            "auth_urls": [getattr(a, 'uri', None) for a in authz_list],
            "domains": domain_states,
            "challenges": challenge_infos,
            "csr_pem": csr_pem.decode(),
        }), 200

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"[ACME] start error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/ssl-free/check-challenge', methods=['POST'])
def api_ssl_free_check_challenge():
    """
    Step 3: Pre-check challenge (DNS TXT or HTTP file) before telling LE to validate.
    Body: { session_id }
    Returns: { results: [{domain, type, ok, detail}] }
    """
    try:
        _cleanup_expired_ssl_sessions()
        data = request.json or {}
        session_id = data.get('session_id', '')

        with _ssl_sessions_lock:
            sess = _ssl_sessions.get(session_id)
        if not sess:
            return jsonify({"error": "Session not found or expired"}), 404

        if sess.get('status') in ('processing', 'finalizing'):
            return jsonify({
                "status": sess.get('status'),
                "message": "Session đang xử lý ở background.",
                "domains": sess.get('domains', []),
                "progress_logs": sess.get('progress_logs', []),
                "current_run_id": sess.get('current_run_id'),
            }), 200

        new_run_id = _gen_run_id('verify')
        with _ssl_sessions_lock:
            if session_id in _ssl_sessions:
                _ssl_sessions[session_id]['current_run_id'] = new_run_id

        challenges = sess['challenges']
        challenge_type = sess['challenge_type']
        results = []
        dns_cache_clear_results = []

        _set_session_status(session_id, 'processing')
        _append_session_log(session_id, 'Đang pre-check bản ghi xác thực...', 'loading')
        _patch_issued_ssl_record_by_session(session_id, {
            "status": "processing",
        })

        dns_lookup_cache: Dict[str, List[str]] = {}
        if challenge_type == 'dns-01':
            dns_names = sorted(set(ch.get('dns_name') for ch in challenges if ch.get('dns_name')))
            for dns_name in dns_names:
                dns_cache_clear_results.append({
                    "dns_name": dns_name,
                    "targets": _request_public_dns_cache_clear(dns_name),
                })
                dns_lookup_cache[dns_name] = _query_txt_values(dns_name)

        for ch in challenges:
            ch_domain = ch['domain']
            ok = False
            detail = ''

            if challenge_type == 'dns-01':
                expected_value = ch['dns_value']
                dns_name = ch['dns_name']
                try:
                    found_values = dns_lookup_cache.get(dns_name, [])
                    if expected_value in found_values:
                        ok = True
                        detail = f"Tìm thấy TXT record đúng: {expected_value}"
                    else:
                        detail = f"Chưa thấy giá trị đúng. Tìm được: {found_values or 'Không có'} | Cần: {expected_value}"
                except Exception as e:
                    detail = f"Lỗi DNS: {str(e)}"

            else:  # http-01
                file_url = f"http://{ch_domain}{ch['file_path']}"
                expected_content = ch['key_auth']
                try:
                    resp = requests.get(file_url, timeout=8, allow_redirects=True)
                    if resp.status_code == 404:
                        detail = f"File xác thực không tồn tại (HTTP 404): {file_url}"
                    elif resp.status_code >= 400:
                        detail = f"Truy cập file xác thực lỗi HTTP {resp.status_code}: {file_url}"
                    else:
                        actual = (resp.text or '').strip()
                        if actual == expected_content.strip():
                            ok = True
                            detail = "File truy cập được và nội dung đúng"
                        else:
                            snippet = actual[:120] if actual else '(rỗng)'
                            detail = f"File truy cập được nhưng nội dung sai. Nhận được: {snippet} | Cần: {expected_content[:80]}"
                except requests.exceptions.ConnectionError:
                    detail = f"Không kết nối được tới {file_url}"
                except requests.exceptions.Timeout:
                    detail = f"Timeout khi truy cập {file_url}"
                except Exception as e:
                    detail = f"Lỗi HTTP: {str(e)}"

            results.append({"domain": ch_domain, "type": challenge_type, "ok": ok, "detail": detail})

        all_ok = all(r['ok'] for r in results)
        if not all_ok:
            _append_session_log(session_id, f'Pre-check chưa đạt ({sum(1 for x in results if x.get("ok"))}/{len(results)}).', 'error')
            _set_session_status(session_id, 'pending', {
                "last_check_results": results,
                "dns_cache_clear": dns_cache_clear_results,
            })
            _patch_issued_ssl_record_by_session(session_id, {
                "status": "pending",
                "last_check_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "last_check_results": results,
                "dns_cache_clear": dns_cache_clear_results,
            })
            return jsonify({
                "results": results,
                "all_ok": False,
                "dns_cache_clear": dns_cache_clear_results,
                "status": "pending",
            }), 200

        # Step 3b: call challenge only for pending authorizations to avoid malformed
        acme_cl: acme_client.ClientV2 = sess['acme_client']
        authz_list = sess['authz_list']
        account_key = jose.JWKRSA.load(sess['account_key_pem'].encode())

        for authz in authz_list:
            authz_domain = authz.body.identifier.value
            domain_state = next((d for d in sess.get('domains', []) if d.get('domain') == authz_domain), None)
            if domain_state and domain_state.get('status') != 'pending':
                continue
            for ch in authz.body.challenges:
                if ch.chall.typ != challenge_type:
                    continue
                try:
                    acme_cl.answer_challenge(ch, ch.chall.response(account_key))
                except Exception as e:
                    acme_error = _extract_acme_error_payload(e)
                    user_msg = _map_acme_error_message(acme_error)
                    _set_session_status(session_id, 'invalid', {"last_error": acme_error})
                    _append_session_log(session_id, user_msg, 'error')
                    _patch_issued_ssl_record_by_session(session_id, {
                        "status": "invalid",
                        "last_error": acme_error,
                        "last_check_results": results,
                        "dns_cache_clear": dns_cache_clear_results,
                    })
                    return jsonify({
                        "error": user_msg,
                        "acme_error": acme_error,
                        "results": results,
                        "all_ok": False,
                        "status": "invalid",
                    }), 400
                break
        _append_session_log(session_id, 'Pre-check đạt. Đã gửi challenge, bắt đầu xác thực tự động...', 'success')
        _set_session_status(session_id, 'processing', {
            "last_check_results": results,
            "dns_cache_clear": dns_cache_clear_results,
        })
        _patch_issued_ssl_record_by_session(session_id, {
            "status": "processing",
            "last_check_at": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "last_check_results": results,
            "dns_cache_clear": dns_cache_clear_results,
        })

        with _ssl_sessions_lock:
            if session_id in _ssl_sessions:
                if not _ssl_sessions[session_id].get('worker_running'):
                    _ssl_sessions[session_id]['worker_running'] = True
                    _acme_worker_pool.submit(_run_acme_background_flow, session_id)

        return jsonify({
            "results": results,
            "all_ok": True,
            "auth_ok": False,
            "auto_finalized": False,
            "status": "processing",
            "domains": sess.get('domains', []),
            "dns_cache_clear": dns_cache_clear_results,
            "progress_logs": sess.get('progress_logs', []),
            "current_run_id": new_run_id,
        }), 200

    except Exception as e:
        logger.error(f"[ACME] check-challenge error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/ssl-free/clear-dns-cache', methods=['POST'])
def api_ssl_free_clear_dns_cache():
    """
    Trigger best-effort DNS cache refresh requests for DNS-01 challenges.
    Body: { session_id }
    """
    try:
        data = request.json or {}
        session_id = data.get('session_id', '')

        with _ssl_sessions_lock:
            sess = _ssl_sessions.get(session_id)
        if not sess:
            return jsonify({"error": "Session not found or expired"}), 404

        if sess.get('challenge_type') != 'dns-01':
            return jsonify({"results": [], "note": "Challenge type is not dns-01"}), 200

        challenges = sess.get('challenges', [])
        dns_names = sorted(set(ch.get('dns_name') for ch in challenges if ch.get('dns_name')))
        refresh_results = []

        for dns_name in dns_names:
            refresh_results.append({
                "dns_name": dns_name,
                "targets": _request_public_dns_cache_clear(dns_name),
            })

        with _ssl_sessions_lock:
            if session_id in _ssl_sessions:
                _ssl_sessions[session_id]['dns_cache_clear'] = refresh_results

        _patch_issued_ssl_record_by_session(session_id, {
            "dns_cache_clear": refresh_results,
        })

        return jsonify({"results": refresh_results}), 200
    except Exception as e:
        logger.error(f"[ACME] clear-dns-cache error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/ssl-free/finalize', methods=['POST'])
def api_ssl_free_finalize():
    """
    Step 4: Tell ACME server to validate, poll until valid, download cert.
    Body: { session_id }
    Returns: { certificate, private_key, ca_bundle, full_chain }
    """
    try:
        _cleanup_expired_ssl_sessions()
        data = request.json or {}
        session_id = data.get('session_id', '')

        with _ssl_sessions_lock:
            sess = _ssl_sessions.get(session_id)
        if not sess:
            return jsonify({"error": "Session not found or expired"}), 404

        result, finalize_error = _finalize_order_and_collect_cert(session_id, sess)
        if finalize_error:
            mapped_msg = _map_acme_error_message(finalize_error)
            code = 408 if finalize_error.get('type') == 'acme:error:timeout' else 400
            return jsonify({
                "error": mapped_msg,
                "acme_error": finalize_error,
            }), code

        with _ssl_sessions_lock:
            if session_id in _ssl_sessions:
                _ssl_sessions[session_id]['status'] = 'issued'
                _ssl_sessions[session_id]['result'] = result

        _ensure_ssl_store_writable()
        stored_record = _upsert_issued_ssl_record(_build_issued_ssl_record(sess, result))
        result["storage_id"] = stored_record["id"]

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"[ACME] finalize error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/ssl-free/list', methods=['GET'])
def api_ssl_free_list():
    try:
        keyword = request.args.get('q', '').strip().lower()
        with _issued_ssl_store_lock:
            items = _load_issued_ssl_store()

        def _matches(item: dict) -> bool:
            if not keyword:
                return True
            haystacks = [item.get('domain', ''), item.get('issuer', ''), item.get('subject', '')]
            haystacks.extend(item.get('sans', []))
            return any(keyword in (h or '').lower() for h in haystacks)

        filtered = [
            {
                "id": item.get("id"),
                "domain": item.get("domain"),
                "sans": item.get("sans", []),
                "issued_at": item.get("issued_at"),
                "valid_to": item.get("valid_to"),
                "issuer": item.get("issuer"),
                "challenge_type": item.get("challenge_type"),
                "provider": item.get("provider", "letsencrypt"),
                "status": item.get("status", "issued"),
                "session_id": item.get("session_id"),
            }
            for item in items if _matches(item)
        ]
        return jsonify({"items": filtered, "count": len(filtered)}), 200
    except Exception as e:
        logger.error(f"[ACME] list error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/ssl-free/item/<item_id>', methods=['GET'])
def api_ssl_free_get_item(item_id):
    try:
        with _issued_ssl_store_lock:
            items = _load_issued_ssl_store()
        item = next((x for x in items if x.get('id') == item_id), None)
        if not item:
            return jsonify({"error": "Stored SSL item not found"}), 404
        return jsonify(item), 200
    except Exception as e:
        logger.error(f"[ACME] get-item error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/ssl-free/item/<item_id>', methods=['DELETE'])
def api_ssl_free_delete_item(item_id):
    try:
        with _issued_ssl_store_lock:
            items = _load_issued_ssl_store()
            new_items = [x for x in items if x.get('id') != item_id]
            if len(new_items) == len(items):
                return jsonify({"error": "Stored SSL item not found"}), 404
            _save_issued_ssl_store(new_items)
        return jsonify({"message": "Deleted successfully"}), 200
    except Exception as e:
        logger.error(f"[ACME] delete-item error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/ssl-free/session/<session_id>/status', methods=['GET'])
def api_ssl_free_session_status(session_id):
    try:
        _cleanup_expired_ssl_sessions()
        with _ssl_sessions_lock:
            sess = _ssl_sessions.get(session_id)
        if not sess:
            return jsonify({"error": "Session not found or expired"}), 404

        payload = {
            "session_id": session_id,
            "storage_id": sess.get('storage_id'),
            "status": sess.get('status', 'pending'),
            "domains": sess.get('domains', []),
            "progress_logs": sess.get('progress_logs', []),
            "progress_text": sess.get('progress_text'),
            "last_error": sess.get('last_error'),
            "current_run_id": sess.get('current_run_id'),
            "result": sess.get('result') if sess.get('status') == 'issued' else None,
        }
        return jsonify(payload), 200
    except Exception as e:
        logger.error(f"[ACME] session-status error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("⚡ DNS Checker Tool - Ultra Fast Mode")
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    print(f"📍 Open: http://localhost:{port}")
    app.run(debug=debug_mode, host='0.0.0.0', port=port, threaded=True, use_reloader=False)
