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
from datetime import datetime
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
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
    "Verisign": "64.6.64.6",
    "Level3": "209.244.0.3",
}

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

# Thread pool for parallel queries
executor = ThreadPoolExecutor(max_workers=20)


def query_dns_record(domain: str, record_type: str, dns_server: str, server_name: str) -> Dict:
    """Query DNS record from specific server - returns result dict"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.cache = None
        resolver.nameservers = [dns_server]
        resolver.timeout = 1  # Ultra fast timeout
        resolver.lifetime = 1
        
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
        resolver.timeout = 1
        resolver.lifetime = 1
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
            "success_rate": "0/6"
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
    
    # Get DNSSEC result
    results["dnssec"] = dnssec_future.result()
    
    # Calculate success rates
    for record_type in record_types:
        servers = results["dns_records"][record_type]["servers"]
        success_count = sum(1 for s in servers.values() if s["status"] == "success")
        results["dns_records"][record_type]["success_rate"] = f"{success_count}/{len(DNS_SERVERS)}"
    
    # Summary
    a_records = results["dns_records"].get("A", {}).get("servers", {})
    success_a = sum(1 for s in a_records.values() if s["status"] == "success")
    
    results["summary"] = {
        "propagation": f"{success_a}/{len(DNS_SERVERS)}" if "A" in record_types else "N/A",
        "dnssec_enabled": results["dnssec"]["enabled"]
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
        data = request.json
        domain = data.get('domain', '').strip().lower()
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
        # Clean domain
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
        
        result = {
            "domain": domain,
            "valid": False,
            "issuer": None,
            "issuer_org": None,
            "subject": None,
            "subject_alt_names": [],
            "valid_from": None,
            "valid_to": None,
            "days_remaining": None,
            "serial_number": None,
            "signature_algorithm": None,
            "version": None,
            "error": None
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    result["valid"] = True
                    
                    # Parse issuer
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    result["issuer"] = issuer.get('commonName', issuer.get('organizationName', 'Unknown'))
                    result["issuer_org"] = issuer.get('organizationName', '')
                    result["issuer_country"] = issuer.get('countryName', '')
                    
                    # Parse subject
                    subject = dict(x[0] for x in cert.get('subject', []))
                    result["subject"] = subject.get('commonName', domain)
                    result["subject_org"] = subject.get('organizationName', '')
                    
                    # Parse SAN (Subject Alternative Names)
                    san = cert.get('subjectAltName', [])
                    result["subject_alt_names"] = [name for type_, name in san if type_ == 'DNS'][:10]
                    
                    # Parse dates
                    not_before = cert.get('notBefore', '')
                    not_after = cert.get('notAfter', '')
                    
                    if not_before:
                        dt = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                        result["valid_from"] = dt.strftime('%Y-%m-%d %H:%M:%S')
                    
                    if not_after:
                        dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        result["valid_to"] = dt.strftime('%Y-%m-%d %H:%M:%S')
                        result["days_remaining"] = (dt - datetime.now()).days
                    
                    # Serial number
                    sn = cert.get('serialNumber')
                    if sn:
                        if isinstance(sn, int):
                            result["serial_number"] = format(sn, 'X')
                        else:
                            result["serial_number"] = str(sn)
                    
                    # Version
                    result["version"] = cert.get('version', 0) + 1
                    
        except ssl.SSLCertVerificationError as e:
            result["error"] = f"SSL verification failed: {str(e)}"
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
        data = request.json
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
            
            # Get ALL info from ip-api.com (including reverse DNS)
            if result["ip"]:
                try:
                    resp = requests.get(
                        f"http://ip-api.com/json/{result['ip']}?fields=status,country,regionName,city,isp,org,as,reverse",
                        timeout=3
                    )
                    if resp.status_code == 200:
                        ip_data = resp.json()
                        if ip_data.get('status') == 'success':
                            result["provider"] = ip_data.get('isp', '')
                            result["org"] = ip_data.get('org', '')
                            result["asn"] = ip_data.get('as', '')
                            result["country"] = ip_data.get('country', '')
                            result["city"] = ip_data.get('city', '')
                            result["region"] = ip_data.get('regionName', '')
                            # Reverse DNS from ip-api.com (not local)
                            reverse = ip_data.get('reverse', '')
                            result["reverse_dns"] = reverse if reverse else None
                            # If input was IP, use reverse DNS as hostname
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

ISSUED_SSL_STORE_PATH = os.path.join(app.root_path, 'acme', 'issued_ssl_store.json')

# In-memory session store  { session_id -> {...} }
_ssl_sessions: Dict[str, dict] = {}
_ssl_sessions_lock = threading.Lock()
_issued_ssl_store_lock = threading.Lock()


def _gen_session_id() -> str:
    import uuid
    return str(uuid.uuid4())


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
    regr = client.new_account(
        acme_messages.NewRegistration.from_data(**new_reg_kwargs)
    )
    return client, account_key_pem_bytes, regr


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


def _upsert_issued_ssl_record(record: dict) -> dict:
    with _issued_ssl_store_lock:
        items = _load_issued_ssl_store()
        # Key: same domain AND same provider → overwrite that specific record
        existing_idx = next(
            (i for i, item in enumerate(items)
             if item.get('domain') == record.get('domain')
             and item.get('provider', 'letsencrypt') == record.get('provider', 'letsencrypt')),
            None
        )
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


def _build_issued_ssl_record(sess: dict, result: dict) -> dict:
    cert_summary = _extract_cert_summary(result.get('certificate', ''))
    return {
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
    }


@app.route('/api/ssl-free/start', methods=['POST'])
def api_ssl_free_start():
    """
    Step 1 & 2: Generate RSA key + CSR, send ACME order, get challenges.
    Body: { domain, sans (optional list), challenge_type: "dns-01"|"http-01", email, provider: "letsencrypt"|"zerossl"|"sslcom" }
    Returns: { session_id, challenges: [{type, domain, token, key_auth, dns_name, dns_value, file_path, file_content}] }
    """
    try:
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

        logger.info(f"[ACME] start: domain={domain} sans={sans} type={challenge_type} provider={provider}")

        # 1. Generate domain private key
        domain_key_pem = _generate_rsa_private_key_pem(2048)

        # 2. Generate CSR
        csr_pem = _generate_csr_pem(domain, sans, domain_key_pem)

        # 3. Create ACME client + place order
        acme_cl, account_key_pem, regr = _get_acme_client(email, provider=provider)
        all_domains = list(dict.fromkeys([domain] + [s for s in sans if s]))
        order = acme_cl.new_order(csr_pem)

        # 4. Extract challenges
        challenge_infos = []
        authz_list = list(order.authorizations)

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
                    challenge_infos.append({
                        "type": "dns-01",
                        "domain": authz_domain,
                        "token": _b64_jose(token),
                        "key_auth": key_auth,
                        "dns_name": f"_acme-challenge.{authz_domain}",
                        "dns_value": dns_value,
                    })
                else:  # http-01
                    token_str = _b64_jose(token)
                    challenge_infos.append({
                        "type": "http-01",
                        "domain": authz_domain,
                        "token": token_str,
                        "key_auth": key_auth,
                        "file_path": f"/.well-known/acme-challenge/{token_str}",
                        "file_content": key_auth,
                    })
                break  # one challenge per authz

        if not challenge_infos:
            return jsonify({"error": f"No {challenge_type} challenges found in authorization"}), 400

        # 5. Store session
        session_id = _gen_session_id()
        with _ssl_sessions_lock:
            _ssl_sessions[session_id] = {
                "domain": domain,
                "sans": sans,
                "email": email,
                "provider": provider,
                "challenge_type": challenge_type,
                "domain_key_pem": domain_key_pem.decode(),
                "csr_pem": csr_pem.decode(),
                "account_key_pem": account_key_pem.decode(),
                "order_uri": order.uri,
                "authz_list": authz_list,
                "acme_client": acme_cl,
                "order": order,
                "challenges": challenge_infos,
                "created_at": time.time(),
                "status": "pending",
            }

        return jsonify({
            "session_id": session_id,
            "domain": domain,
            "challenge_type": challenge_type,
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
        data = request.json or {}
        session_id = data.get('session_id', '')

        with _ssl_sessions_lock:
            sess = _ssl_sessions.get(session_id)
        if not sess:
            return jsonify({"error": "Session not found or expired"}), 404

        challenges = sess['challenges']
        challenge_type = sess['challenge_type']
        results = []

        for ch in challenges:
            ch_domain = ch['domain']
            ok = False
            detail = ''

            if challenge_type == 'dns-01':
                expected_value = ch['dns_value']
                dns_name = ch['dns_name']
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
                    resolver.timeout = 5
                    resolver.lifetime = 5
                    answers = resolver.resolve(dns_name, 'TXT')
                    found_values = []
                    for rdata in answers:
                        for s in rdata.strings:
                            found_values.append(s.decode() if isinstance(s, bytes) else s)
                    if expected_value in found_values:
                        ok = True
                        detail = f"✅ Tìm thấy TXT record đúng: {expected_value}"
                    else:
                        detail = f"❌ Chưa thấy giá trị đúng. Tìm được: {found_values or 'Không có'} | Cần: {expected_value}"
                except dns.resolver.NXDOMAIN:
                    detail = f"❌ Record {dns_name} chưa tồn tại (NXDOMAIN)"
                except dns.resolver.NoAnswer:
                    detail = f"❌ Không có TXT record tại {dns_name}"
                except Exception as e:
                    detail = f"❌ Lỗi DNS: {str(e)}"

            else:  # http-01
                file_url = f"http://{ch_domain}{ch['file_path']}"
                expected_content = ch['key_auth']
                try:
                    resp = requests.get(file_url, timeout=8, allow_redirects=True)
                    actual = resp.text.strip()
                    if actual == expected_content.strip():
                        ok = True
                        detail = f"✅ File truy cập được và nội dung đúng"
                    else:
                        detail = f"❌ File tồn tại nhưng nội dung sai. Nhận được: {actual[:80]} | Cần: {expected_content[:80]}"
                except requests.exceptions.ConnectionError:
                    detail = f"❌ Không kết nối được tới {file_url}"
                except requests.exceptions.Timeout:
                    detail = f"❌ Timeout khi truy cập {file_url}"
                except Exception as e:
                    detail = f"❌ Lỗi HTTP: {str(e)}"

            results.append({"domain": ch_domain, "type": challenge_type, "ok": ok, "detail": detail})

        all_ok = all(r['ok'] for r in results)
        return jsonify({"results": results, "all_ok": all_ok}), 200

    except Exception as e:
        logger.error(f"[ACME] check-challenge error: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route('/api/ssl-free/finalize', methods=['POST'])
def api_ssl_free_finalize():
    """
    Step 4: Tell ACME server to validate, poll until valid, download cert.
    Body: { session_id }
    Returns: { certificate, private_key, ca_bundle, full_chain }
    """
    try:
        data = request.json or {}
        session_id = data.get('session_id', '')

        with _ssl_sessions_lock:
            sess = _ssl_sessions.get(session_id)
        if not sess:
            return jsonify({"error": "Session not found or expired"}), 404

        acme_cl: acme_client.ClientV2 = sess['acme_client']
        order = sess['order']
        authz_list = sess['authz_list']
        challenge_type = sess['challenge_type']
        challenges_info = sess['challenges']

        # Build a map: authz_domain -> challenge object
        ch_map = {c['domain']: c for c in challenges_info}

        # Respond to each challenge
        for authz in authz_list:
            authz_domain = authz.body.identifier.value
            for ch in authz.body.challenges:
                if ch.chall.typ != challenge_type:
                    continue
                # Tell ACME we're ready
                acme_cl.answer_challenge(ch, ch.chall.response(jose.JWKRSA.load(sess['account_key_pem'].encode())))
                break

        # Poll order until valid or invalid
        deadline = time.time() + 120  # wait up to 2 min
        finalized_order = None
        poll_status = "processing"

        while time.time() < deadline:
            try:
                order_resource = acme_cl.poll_and_finalize(order)
                if order_resource.fullchain_pem:
                    finalized_order = order_resource
                    poll_status = "valid"
                    break
            except Exception as poll_err:
                err_str = str(poll_err)
                if 'invalid' in err_str.lower():
                    poll_status = "invalid"
                    return jsonify({"error": f"Let's Encrypt validation failed: {err_str}"}), 400
            time.sleep(3)

        if not finalized_order:
            return jsonify({"error": f"Timeout waiting for certificate. Last status: {poll_status}"}), 408

        # Split fullchain into leaf cert + CA bundle
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

        with _ssl_sessions_lock:
            if session_id in _ssl_sessions:
                _ssl_sessions[session_id]['status'] = 'issued'
                _ssl_sessions[session_id]['result'] = result

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


if __name__ == '__main__':
    print("⚡ DNS Checker Tool - Ultra Fast Mode")
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    print(f"📍 Open: http://localhost:{port}")
    app.run(debug=debug_mode, host='0.0.0.0', port=port, threaded=True, use_reloader=False)
