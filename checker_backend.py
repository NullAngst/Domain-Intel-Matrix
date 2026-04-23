# checker_backend.py
# Description: A local Flask server to perform domain and reverse IP lookups.
# Dependencies: Flask, Flask-Cors, dnspython, python-whois, requests, ipaddress
# To run: python checker_backend.py

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import dns.resolver
import whois
import requests
import socket
import ssl
import os
import ipaddress
import logging
import re

# ---------------------------------------------------------------------------
# Logging Toggle
# Set VERBOSE_LOGGING = True for detailed debugging output.
# ---------------------------------------------------------------------------
VERBOSE_LOGGING = False

if VERBOSE_LOGGING:
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
else:
    logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

# ---------------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder=os.path.dirname(os.path.abspath(__file__)))
CORS(app)

# Shared session with a browser-like User-Agent to avoid blocks from some servers
HTTP_SESSION = requests.Session()
HTTP_SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; DomainIntelMatrix/2.0; +https://github.com/NullAngst/Domain-Intel-Matrix)"
})

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_api_key():
    """Safely import the HackerTarget API key from config.py."""
    try:
        import config
        key = getattr(config, 'HACKERTARGET_API_KEY', None)
        if key and key != "YOUR_API_KEY_HERE":
            return key
        return None
    except ImportError:
        logging.warning("config.py not found. Reverse IP lookups will use the free tier.")
        return None


def sanitize_domain(raw: str) -> str:
    """
    Strip scheme, path, query string, and port from a raw domain input.
    Returns a lowercase, stripped hostname string.
    """
    # Remove scheme (http://, https://, ftp://, etc.)
    if '://' in raw:
        raw = raw.split('://', 1)[1]
    # Remove path, query string, and fragment
    raw = raw.split('/')[0].split('?')[0].split('#')[0]
    # Remove port
    if raw.startswith('['):
        # IPv6 literal like [::1]:443
        raw = raw.split(']')[0].lstrip('[')
    else:
        raw = raw.split(':')[0]
    return raw.strip().lower()


def is_ip_address(query: str) -> bool:
    """Return True if query is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(query)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """
    Basic validation: domain must contain at least one dot, consist of valid
    characters only, and not look like a local/reserved address.
    """
    if not domain or len(domain) > 253:
        return False
    # Must have at least one dot (TLD present)
    if '.' not in domain:
        return False
    # Only valid hostname characters
    if not re.match(r'^[a-z0-9._-]+$', domain):
        return False
    # Reject localhost and obviously local names
    if domain in ('localhost',) or domain.endswith('.local') or domain.endswith('.internal'):
        return False
    return True


def parse_nameserver(nameserver_str: str):
    """
    Parse a nameserver string that may contain an IPv6 literal, a bare IPv6
    address, or an IPv4:port combo. Returns (ip, port, is_ipv6).
    """
    ip = nameserver_str.strip()
    port = 53
    is_ipv6 = False

    if ip.startswith('[') and ']:' in ip:          # [::1]:5335
        parts = ip.split(']:')
        ip = parts[0][1:]
        port = int(parts[1])
        is_ipv6 = True
    elif ip.count(':') > 1:                          # bare IPv6 like ::1
        is_ipv6 = True
    elif ':' in ip:                                  # IPv4:port like 9.9.9.9:53
        parts = ip.split(':', 1)
        ip = parts[0]
        port = int(parts[1])

    return ip, port, is_ipv6


def get_ipv6_source_address(dest_ip: str) -> str:
    """Find the local IPv6 source address used to reach dest_ip."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect((dest_ip, 80))
        source_ip = s.getsockname()[0]
        s.close()
        return source_ip
    except Exception as e:
        logging.error(f"Could not determine source IPv6 address: {e}")
    return '::'


def get_dns_records(domain: str, record_type: str, nameserver_str: str):
    """
    Query specific DNS record types using a custom resolver.
    Returns a list of strings, None if no records, or a list with an error string.
    """
    logging.info(f"Querying {record_type} for '{domain}' via '{nameserver_str}'")
    try:
        ip, port, is_ipv6 = parse_nameserver(nameserver_str)
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        resolver.port = port

        source_address = get_ipv6_source_address(ip) if is_ipv6 else '0.0.0.0'
        answers = resolver.resolve(domain, record_type, source=source_address)

        if record_type in ('A', 'AAAA'):
            return [r.to_text() for r in answers]
        if record_type == 'MX':
            return sorted([f"{r.preference} {r.exchange.to_text()}" for r in answers])
        if record_type == 'TXT':
            return [''.join(s.decode('utf-8', errors='replace') for s in r.strings) for r in answers]
        if record_type == 'SOA':
            r = answers[0]
            return [
                f"MNAME: {r.mname.to_text()}",
                f"RNAME: {r.rname.to_text()}",
                f"Serial: {r.serial}",
                f"Refresh: {r.refresh}",
                f"Retry: {r.retry}",
                f"Expire: {r.expire}",
                f"Minimum TTL: {r.minimum}",
            ]
        return [r.to_text() for r in answers]

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout) as e:
        logging.warning(f"DNS query {domain} ({record_type}) → {type(e).__name__}")
        return None
    except Exception as e:
        logging.error(f"Unexpected DNS error for {domain} ({record_type}): {e}", exc_info=True)
        return [f"Error: {e}"]


def analyze_security_headers(headers: dict) -> dict:
    """Check for the presence of common HTTP security headers."""
    lower = {k.lower(): v for k, v in headers.items()}
    checks = {
        "Strict-Transport-Security": "strict-transport-security",
        "Content-Security-Policy": "content-security-policy",
        "X-Content-Type-Options": "x-content-type-options",
        "X-Frame-Options": "x-frame-options",
        "Referrer-Policy": "referrer-policy",
        "Permissions-Policy": "permissions-policy",
        "Cross-Origin-Opener-Policy": "cross-origin-opener-policy",
        "Cross-Origin-Resource-Policy": "cross-origin-resource-policy",
    }
    return {name: lower.get(header, "Missing") for name, header in checks.items()}


def detect_technologies(headers: dict, content: str) -> dict:
    """
    Detect server software and frameworks from HTTP headers and page content.
    """
    tech = {}
    lower = {k.lower(): v for k, v in headers.items()}

    if 'server' in lower:
        tech['Server'] = lower['server']
    if 'x-powered-by' in lower:
        tech['X-Powered-By'] = lower['x-powered-by']
    if 'x-generator' in lower:
        tech['Generator'] = lower['x-generator']
    if 'x-drupal-cache' in lower or 'x-drupal-dynamic-cache' in lower:
        tech['Framework'] = 'Drupal'
    if 'x-shopify-stage' in lower or 'x-storefront-renderer-rendered-by' in lower:
        tech['Platform'] = 'Shopify'

    # Content-based detection (order matters: more specific checks first)
    if 'Framework' not in tech and 'Platform' not in tech:
        if re.search(r'/wp-content/|/wp-includes/|wp-json', content, re.IGNORECASE):
            tech['Framework'] = 'WordPress'
        elif re.search(r'Joomla!', content, re.IGNORECASE):
            tech['Framework'] = 'Joomla'
        elif re.search(r'<meta[^>]+Drupal', content, re.IGNORECASE):
            tech['Framework'] = 'Drupal'
        elif re.search(r'Powered by Ghost', content, re.IGNORECASE):
            tech['Framework'] = 'Ghost'
        elif re.search(r'__next|_next/static', content, re.IGNORECASE):
            tech['Framework'] = 'Next.js'
        elif re.search(r'nuxt|__nuxt', content, re.IGNORECASE):
            tech['Framework'] = 'Nuxt.js'

    # CDN / edge detection via headers
    if 'cf-ray' in lower:
        tech['CDN'] = 'Cloudflare'
    elif 'x-amz-cf-id' in lower or 'x-amz-cf-pop' in lower:
        tech['CDN'] = 'Amazon CloudFront'
    elif 'x-cache' in lower and 'varnish' in lower.get('x-cache', '').lower():
        tech['CDN/Cache'] = 'Varnish'
    elif 'x-fastly-request-id' in lower:
        tech['CDN'] = 'Fastly'
    elif 'x-akamai-transformed' in lower:
        tech['CDN'] = 'Akamai'

    return tech if tech else {"Info": "No specific technologies detected."}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    """Serve the main HTML UI."""
    return app.send_static_file('checker_frontend.html')


@app.route('/check')
def check_query():
    """Main endpoint: handles domain checks and reverse IP lookups."""
    query = (request.args.get('query') or '').strip()
    nameserver = (request.args.get('nameserver') or '9.9.9.9').strip()

    if not query:
        return jsonify({"error": "Query parameter is required"}), 400

    if is_ip_address(query):
        return handle_reverse_ip(query)
    else:
        return handle_domain_check(query, nameserver)


def handle_reverse_ip(ip: str):
    """Perform a reverse IP lookup via HackerTarget."""
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.version == 6:
        return jsonify({
            "type": "ip_lookup",
            "hostnames": ["Reverse IP lookup for IPv6 is not currently supported."]
        })
    try:
        api_key = get_api_key()
        api_url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        if api_key:
            api_url += f"&apikey={api_key}"
        response = HTTP_SESSION.get(api_url, timeout=10)
        if response.status_code == 200 and not response.text.startswith("error"):
            hostnames = [h for h in response.text.strip().split('\n') if h]
            return jsonify({"type": "ip_lookup", "hostnames": hostnames})
        else:
            return jsonify({"type": "ip_lookup", "hostnames": [f"API Error: {response.text.strip()}"]})
    except requests.RequestException as e:
        return jsonify({"type": "ip_lookup", "hostnames": [f"Request failed: {e}"]})


def handle_domain_check(raw_domain: str, nameserver: str):
    """Perform a full domain intelligence check."""
    domain = sanitize_domain(raw_domain)

    if not is_valid_domain(domain):
        return jsonify({"error": f"Invalid or unsupported domain: '{domain}'"}), 400

    results = {
        "domain": domain,
        "whois": {},
        "dns": {},
        "security": {},
        "server": {},
    }

    # ---- WHOIS ----
    try:
        w = whois.whois(domain)

        def first(val):
            return val[0] if isinstance(val, list) else val

        creation_date = first(w.creation_date)
        expiration_date = first(w.expiration_date)
        registrar = first(w.registrar)

        # name_servers may be a set or list; normalise to sorted list
        name_servers = w.name_servers
        if isinstance(name_servers, (set, list)):
            name_servers = sorted({ns.lower().rstrip('.') for ns in name_servers if ns})
        else:
            name_servers = [str(name_servers)] if name_servers else []

        results["whois"] = {
            "registrar": registrar or "N/A",
            "creation_date": creation_date.isoformat() if creation_date else "N/A",
            "expiration_date": expiration_date.isoformat() if expiration_date else "N/A",
            "name_servers": name_servers,
        }
    except Exception as e:
        results["whois"]["error"] = f"Could not fetch WHOIS data: {e}"

    # ---- DNS ----
    a_records = get_dns_records(domain, 'A', nameserver)
    results["dns"]["A"] = a_records
    results["dns"]["AAAA"] = get_dns_records(domain, 'AAAA', nameserver)
    results["dns"]["A_www"] = get_dns_records(f"www.{domain}", 'A', nameserver)
    results["dns"]["CNAME_www"] = get_dns_records(f"www.{domain}", 'CNAME', nameserver)
    results["dns"]["NS"] = get_dns_records(domain, 'NS', nameserver)
    mx_records = get_dns_records(domain, 'MX', nameserver)
    results["dns"]["MX"] = mx_records
    results["dns"]["SOA"] = get_dns_records(domain, 'SOA', nameserver)

    # rDNS for primary A record
    if a_records and not (len(a_records) == 1 and a_records[0].startswith("Error:")):
        try:
            addr = socket.gethostbyaddr(a_records[0])
            results["dns"]["rDNS"] = {"ip": a_records[0], "hostname": addr[0]}
        except socket.herror:
            results["dns"]["rDNS"] = {"ip": a_records[0], "hostname": "No rDNS record found."}

    # ---- Security / Email Records ----
    txt_records = get_dns_records(domain, 'TXT', nameserver) or []
    results["security"]["SPF"] = next((r for r in txt_records if r.startswith('v=spf1')), None)
    results["security"]["DMARC"] = get_dns_records(f"_dmarc.{domain}", 'TXT', nameserver)
    results["security"]["CAA"] = get_dns_records(domain, 'CAA', nameserver)
    results["security"]["DNSSEC"] = (
        "Enabled" if get_dns_records(domain, 'DNSKEY', nameserver) else "Not Enabled or Not Found"
    )

    # DKIM — check common selectors
    common_dkim_selectors = [
        'default', 'google', 'selector1', 'selector2',
        'k1', 'k2', 'mail', 'dkim', 'protonmail', 'zoho',
    ]
    found_dkim = []
    for selector in common_dkim_selectors:
        records = get_dns_records(f"{selector}._domainkey.{domain}", 'TXT', nameserver)
        if records:
            for r in records:
                found_dkim.append(f"Selector: {selector}\nRecord: {r}")
    results["security"]["DKIM"] = found_dkim if found_dkim else None

    # MX PTR records
    if mx_records:
        mx_ptr = []
        for record in mx_records:
            parts = record.split(' ', 1)
            if len(parts) < 2:
                continue
            mail_server = parts[1].rstrip('.')
            ips = get_dns_records(mail_server, 'A', nameserver)
            if ips and not ips[0].startswith("Error:"):
                try:
                    ptr_addr = socket.gethostbyaddr(ips[0])
                    mx_ptr.append({"mail_server": mail_server, "ip": ips[0], "ptr": ptr_addr[0]})
                except socket.herror:
                    mx_ptr.append({"mail_server": mail_server, "ip": ips[0], "ptr": "No PTR record found."})
            else:
                mx_ptr.append({"mail_server": mail_server, "ip": "N/A", "ptr": "Could not resolve MX host."})
        results["dns"]["MX_PTR"] = mx_ptr

    # ---- HTTP Headers / Technology Detection ----
    server_response = None
    for scheme in ('https', 'http'):
        try:
            server_response = HTTP_SESSION.get(
                f"{scheme}://{domain}",
                timeout=7,
                verify=(scheme == 'https'),
                allow_redirects=True,
            )
            results["server"]["protocol"] = scheme
            results["server"]["headers"] = dict(server_response.headers)
            results["server"]["status_code"] = server_response.status_code
            results["server"]["final_url"] = server_response.url
            results["server"]["security_headers"] = analyze_security_headers(server_response.headers)
            results["server"]["technologies"] = detect_technologies(
                server_response.headers, server_response.text
            )
            break
        except requests.exceptions.SSLError as e:
            # SSL error on https — record it but still try http
            results["server"]["ssl_error"] = str(e)
            continue
        except requests.exceptions.RequestException:
            continue

    if server_response is None:
        results["server"]["error"] = "Could not connect to the server on HTTPS or HTTP."

    # ---- SSL Certificate ----
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                # san: subject alternative names
                san_list = []
                for (stype, svalue) in cert.get('subjectAltName', []):
                    if stype == 'DNS':
                        san_list.append(svalue)
                results["server"]["ssl_info"] = {
                    "issuer_common_name": issuer.get('commonName', 'N/A'),
                    "issuer_org": issuer.get('organizationName', 'N/A'),
                    "subject_common_name": subject.get('commonName', 'N/A'),
                    "expires": cert.get('notAfter'),
                    "subject_alt_names": san_list[:10],  # cap at 10 for display
                }
    except Exception as e:
        results["server"]["ssl_info"] = {"error": f"Could not retrieve SSL certificate: {e}"}

    return jsonify({"type": "domain_check", "data": results})


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.abspath(__file__))
    print("=" * 60)
    print(" Domain Intel Matrix — Backend Server")
    print("=" * 60)
    print(f" Serving UI from : {base_dir}")
    print(f" Access at       : http://127.0.0.1:4500")
    print(f" Network access  : http://0.0.0.0:4500")
    print("=" * 60)
    app.run(host='0.0.0.0', port=4500, debug=False)
