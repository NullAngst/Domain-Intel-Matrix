# checker_backend.py
# A self-hosted Flask server for domain intelligence and reverse IP lookups.
# Dependencies: see requirements.txt
# Run: python checker_backend.py

import concurrent.futures as cf
import ipaddress
import logging
import os
import re
import socket
import ssl
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import dns.reversename
import requests
import urllib3
import whois
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from flask import Flask, jsonify, request, send_file
from requests.adapters import HTTPAdapter
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

# ---------------------------------------------------------------------------
# Configuration (environment variables override the defaults)
# ---------------------------------------------------------------------------
def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FILE = os.path.join(BASE_DIR, "checker_frontend.html")

VERBOSE_LOGGING = _env_bool("DIM_VERBOSE", False)
HOST = os.environ.get("DIM_HOST", "0.0.0.0")
PORT = int(os.environ.get("DIM_PORT", "4500"))
DEFAULT_NAMESERVER = os.environ.get("DIM_DEFAULT_NAMESERVER", "9.9.9.9")
# When False (default), HTTP/TLS probes refuse to connect to private, loopback,
# link-local, or otherwise non-public addresses. DNS queries to a custom
# resolver are not affected, so a local resolver like 127.0.0.1:5335 still works.
ALLOW_PRIVATE_TARGETS = _env_bool("DIM_ALLOW_PRIVATE_TARGETS", False)

HTTP_TIMEOUT = 7          # seconds per HTTP attempt
TLS_TIMEOUT = 5           # seconds per TLS handshake
DNS_TIMEOUT = 3           # seconds per resolver attempt
DNS_LIFETIME = 5          # total seconds per DNS query
WHOIS_TIMEOUT = 15        # seconds before giving up on WHOIS
MAX_BODY_BYTES = 512 * 1024   # page body read for technology detection
MAX_REDIRECTS = 5

logging.basicConfig(
    level=logging.DEBUG if VERBOSE_LOGGING else logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
log = logging.getLogger("dim")


def _load_api_key():
    """HackerTarget key from $HACKERTARGET_API_KEY, falling back to config.py."""
    key = os.environ.get("HACKERTARGET_API_KEY")
    if not key:
        try:
            import config  # noqa: WPS433 (optional local file)
            key = getattr(config, "HACKERTARGET_API_KEY", None)
        except ImportError:
            key = None
    if not key or key.upper() == "YOUR_API_KEY_HERE":
        log.warning("No HackerTarget API key configured. Reverse IP lookups use the free tier.")
        return None
    return key

HACKERTARGET_API_KEY = _load_api_key()

# ---------------------------------------------------------------------------
# App setup
# static_folder=None: Flask must not serve the project directory, which holds
# config.py (the API key) and the source code.
# ---------------------------------------------------------------------------
app = Flask(__name__, static_folder=None)


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    )
    return resp

# ---------------------------------------------------------------------------
# Outbound connection guard
#
# Every HTTP(S) connection is checked after the TCP connect, against the
# address the socket actually connected to. Checking the connected peer
# (rather than resolving the name first and checking that) closes the DNS
# rebinding gap, and it also covers every redirect hop.
# ---------------------------------------------------------------------------
class BlockedAddressError(OSError):
    pass


def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def _check_peer(sock):
    if ALLOW_PRIVATE_TARGETS:
        return
    peer = sock.getpeername()[0]
    if not is_public_ip(peer):
        sock.close()
        raise BlockedAddressError(f"Refusing to connect to non-public address {peer}")


class _GuardedHTTPConnection(urllib3.connection.HTTPConnection):
    def _new_conn(self):
        sock = super()._new_conn()
        _check_peer(sock)
        return sock


class _GuardedHTTPSConnection(urllib3.connection.HTTPSConnection):
    def _new_conn(self):
        sock = super()._new_conn()
        _check_peer(sock)
        return sock


class _GuardedHTTPPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection


class _GuardedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection


class _GuardedAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {"http": _GuardedHTTPPool, "https": _GuardedHTTPSPool}


def make_session() -> requests.Session:
    s = requests.Session()
    s.trust_env = False  # an environment proxy would make the peer check meaningless
    s.max_redirects = MAX_REDIRECTS
    # trust_env=False also ignores REQUESTS_CA_BUNDLE, so honour it explicitly
    s.verify = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("CURL_CA_BUNDLE") or True
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; DomainIntelMatrix/2.1; +https://github.com/NullAngst/Domain-Intel-Matrix)"
    })
    adapter = _GuardedAdapter()
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def guarded_tcp_connect(host: str, port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    _check_peer(sock)
    return sock

# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_RESERVED_SUFFIXES = ("localhost", "local", "internal", "lan", "home.arpa", "invalid", "test", "onion")


def sanitize_domain(raw: str) -> str:
    """Strip scheme, credentials, path, query, fragment, and port. Returns an
    ASCII (punycode) lowercase hostname, or '' if the name can't be encoded."""
    raw = raw.strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = re.split(r"[/?#]", raw, maxsplit=1)[0]
    raw = raw.rsplit("@", 1)[-1]              # user:pass@host
    if raw.startswith("["):
        raw = raw[1:].split("]", 1)[0]
    elif raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    raw = raw.strip().rstrip(".").lower()
    try:
        return raw.encode("idna").decode("ascii") if raw else ""
    except UnicodeError:
        return ""


def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    labels = domain.split(".")
    if not all(_LABEL_RE.match(l) for l in labels):
        return False
    if labels[-1].isdigit():                  # "1.2.3" would be parsed as an IPv4 address
        return False
    return not any(domain == s or domain.endswith("." + s) for s in _RESERVED_SUFFIXES)


def parse_nameserver(value: str):
    """Accepts 9.9.9.9, 9.9.9.9:53, 2620:fe::fe, [2620:fe::fe]:53.
    Returns (ip, port). Raises ValueError on bad input."""
    value = value.strip()
    port = 53
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        if rest:
            if not rest.startswith(":"):
                raise ValueError("expected ]:port")
            port = int(rest[1:])
    elif value.count(":") == 1:
        host, port_s = value.split(":")
        port = int(port_s)
    else:
        host = value
    ipaddress.ip_address(host)                # dnspython needs a literal IP
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    return host, port

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
class DNS:
    def __init__(self, ip: str, port: int):
        self.ip, self.port = ip, port

    def _resolver(self):
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [self.ip]
        r.port = self.port
        r.timeout = DNS_TIMEOUT
        r.lifetime = DNS_LIFETIME
        return r

    def query(self, name, rtype: str):
        """Returns (records, error). records is a list (possibly empty) on
        success or NoAnswer/NXDOMAIN, None on error."""
        log.debug("DNS %s %s via %s:%s", rtype, name, self.ip, self.port)
        try:
            answers = self._resolver().resolve(name, rtype)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return [], None
        except dns.exception.Timeout:
            return None, "DNS query timed out"
        except dns.resolver.NoNameservers:
            return None, "Resolver returned SERVFAIL or refused the query"
        except Exception as e:  # noqa: BLE001
            log.error("DNS error for %s %s: %s", name, rtype, e, exc_info=VERBOSE_LOGGING)
            return None, f"DNS error: {e}"

        if rtype == "MX":
            return sorted((f"{r.preference} {r.exchange.to_text()}" for r in answers),
                          key=lambda s: (int(s.split()[0]), s)), None
        if rtype == "TXT":
            return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers], None
        if rtype == "PTR":
            return [r.target.to_text().rstrip(".") for r in answers], None
        if rtype == "SOA":
            r = answers[0]
            return [
                f"MNAME: {r.mname.to_text()}", f"RNAME: {r.rname.to_text()}",
                f"Serial: {r.serial}", f"Refresh: {r.refresh}", f"Retry: {r.retry}",
                f"Expire: {r.expire}", f"Minimum TTL: {r.minimum}",
            ], None
        return [r.to_text() for r in answers], None

    def display(self, name, rtype):
        """Frontend-friendly form: list of strings, None if nothing, or ['Error: ...']."""
        records, err = self.query(name, rtype)
        if err:
            return [f"Error: {err}"]
        return records or None

    def ptr(self, ip: str) -> str:
        records, err = self.query(dns.reversename.from_address(ip), "PTR")
        if err:
            return f"Error: {err}"
        return records[0] if records else "No PTR record found."

# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------
def _first(v):
    return v[0] if isinstance(v, (list, tuple)) and v else v


def _iso(v):
    v = _first(v)
    if v is None:
        return "N/A"
    return v.isoformat() if hasattr(v, "isoformat") else str(v)


def get_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)
    except Exception as e:  # noqa: BLE001
        return {"error": f"Could not fetch WHOIS data: {e}"}
    ns = w.get("name_servers") if hasattr(w, "get") else getattr(w, "name_servers", None)
    if isinstance(ns, (list, tuple, set)):
        ns = sorted({str(n).lower().rstrip(".") for n in ns if n})
    else:
        ns = [str(ns).lower().rstrip(".")] if ns else []
    return {
        "registrar": _first(w.registrar) or "N/A",
        "creation_date": _iso(w.creation_date),
        "expiration_date": _iso(w.expiration_date),
        "name_servers": ns,
    }

# ---------------------------------------------------------------------------
# HTTP analysis
# ---------------------------------------------------------------------------
SECURITY_HEADERS = (
    "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
    "X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
    "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
)


def analyze_security_headers(headers) -> dict:
    # requests' CaseInsensitiveDict handles casing
    return {name: headers.get(name, "Missing") for name in SECURITY_HEADERS}


_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']{1,120})[\"']"
    r"|<meta[^>]+content=[\"']([^\"']{1,120})[\"'][^>]*name=[\"']generator[\"']",
    re.IGNORECASE,
)


def detect_technologies(headers, content: str) -> dict:
    h = {k.lower(): v for k, v in headers.items()}
    tech = {}
    for key, label in (("server", "Server"), ("x-powered-by", "X-Powered-By"), ("x-generator", "Generator")):
        if key in h:
            tech[label] = h[key]

    m = _GENERATOR_RE.search(content)
    if m and "Generator" not in tech:
        tech["Generator"] = (m.group(1) or m.group(2)).strip()

    if "x-drupal-cache" in h or "x-drupal-dynamic-cache" in h:
        tech["Framework"] = "Drupal"
    elif "x-shopify-stage" in h or "x-shopid" in h or "x-storefront-renderer-rendered-by" in h:
        tech["Platform"] = "Shopify"
    else:
        for pattern, name in (
            (r"/wp-content/|/wp-includes/|/wp-json/", "WordPress"),
            (r"/media/jui/|Joomla!", "Joomla"),
            (r"Drupal\.settings|/sites/default/files/", "Drupal"),
            (r"ghost-(?:portal|sdk)|content=\"Ghost", "Ghost"),
            (r"__NEXT_DATA__|/_next/static/", "Next.js"),
            (r"window\.__NUXT__|/_nuxt/", "Nuxt.js"),
            (r"cdn\.shopify\.com", "Shopify"),
        ):
            if re.search(pattern, content, re.IGNORECASE):
                tech["Framework"] = name
                break

    server = h.get("server", "").lower()
    via = h.get("via", "").lower()
    if "cf-ray" in h:
        tech["CDN"] = "Cloudflare"
    elif "x-amz-cf-id" in h or "x-amz-cf-pop" in h:
        tech["CDN"] = "Amazon CloudFront"
    elif "x-fastly-request-id" in h or ("x-served-by" in h and "cache-" in h["x-served-by"]):
        tech["CDN"] = "Fastly"
    elif "akamaighost" in server or any(k.startswith("x-akamai") for k in h):
        tech["CDN"] = "Akamai"
    elif "x-vercel-id" in h:
        tech["CDN"] = "Vercel"
    elif "x-nf-request-id" in h:
        tech["CDN"] = "Netlify"
    elif "x-azure-ref" in h:
        tech["CDN"] = "Azure Front Door"
    if "x-varnish" in h or "varnish" in via or "varnish" in server or "varnish" in h.get("x-cache", "").lower():
        tech["Cache"] = "Varnish"

    return tech or {"Info": "No specific technologies detected."}


def _read_capped(resp) -> str:
    chunks, total = [], 0
    for chunk in resp.iter_content(16384):
        chunks.append(chunk)
        total += len(chunk)
        if total >= MAX_BODY_BYTES:
            break
    return b"".join(chunks)[:MAX_BODY_BYTES].decode(resp.encoding or "utf-8", errors="replace")


def probe_http(domain: str) -> dict:
    out = {}
    session = make_session()
    try:
        for scheme in ("https", "http"):
            try:
                with session.get(f"{scheme}://{domain}", timeout=HTTP_TIMEOUT,
                                 allow_redirects=True, stream=True) as resp:
                    body = _read_capped(resp)
                    out.update({
                        "protocol": scheme,
                        "headers": dict(resp.headers),
                        "status_code": resp.status_code,
                        "final_url": resp.url,
                        "redirects": [r.url for r in resp.history],
                        "security_headers": analyze_security_headers(resp.headers),
                        "technologies": detect_technologies(resp.headers, body),
                    })
                    return out
            except requests.exceptions.SSLError as e:
                out["ssl_error"] = str(e)
            except requests.exceptions.TooManyRedirects:
                out.setdefault("errors", []).append(f"{scheme}: more than {MAX_REDIRECTS} redirects")
            except requests.exceptions.RequestException as e:
                msg = "blocked (non-public address)" if "non-public address" in str(e) else type(e).__name__
                out.setdefault("errors", []).append(f"{scheme}: {msg}")
        out["error"] = "Could not connect to the server on HTTPS or HTTP."
        return out
    finally:
        session.close()

# ---------------------------------------------------------------------------
# TLS certificate
# ---------------------------------------------------------------------------
def _name_attr(name, oid):
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else "N/A"


def get_tls_info(domain: str) -> dict:
    verify_error = None
    der = tls_version = cipher = None

    def handshake(ctx):
        with guarded_tcp_connect(domain, 443, TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert(binary_form=True), ssock.version(), ssock.cipher()[0]

    try:
        der, tls_version, cipher = handshake(ssl.create_default_context())
    except ssl.SSLCertVerificationError as e:
        verify_error = e.verify_message or str(e)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            der, tls_version, cipher = handshake(ctx)
        except Exception as e2:  # noqa: BLE001
            return {"error": f"Could not retrieve TLS certificate: {e2}"}
    except BlockedAddressError as e:
        return {"error": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"error": f"Could not retrieve TLS certificate: {e}"}

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:  # noqa: BLE001
        return {"error": f"Could not parse certificate: {e}"}

    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    return {
        "valid": verify_error is None,
        "verification_error": verify_error,
        "issuer_common_name": _name_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "subject_common_name": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "expires": not_after.isoformat(),
        "days_remaining": (not_after - datetime.now(timezone.utc)).days,
        "tls_version": tls_version,
        "cipher": cipher,
        "subject_alt_names_total": len(sans),
        "subject_alt_names": sans[:50],
    }

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_file(FRONTEND_FILE)


@app.route("/check")
def check_query():
    query = (request.args.get("query") or "").strip()
    nameserver = (request.args.get("nameserver") or DEFAULT_NAMESERVER).strip()
    if not query:
        return jsonify({"error": "Query parameter is required."}), 400
    if len(query) > 2048:
        return jsonify({"error": "Query is too long."}), 400

    bare = query.strip("[]")
    try:
        ipaddress.ip_address(bare)
        return handle_reverse_ip(bare)
    except ValueError:
        pass

    try:
        ns_ip, ns_port = parse_nameserver(nameserver)
    except ValueError:
        return jsonify({"error": f"Invalid DNS resolver '{nameserver}'. Use an IP, optionally with :port."}), 400
    return handle_domain_check(query, DNS(ns_ip, ns_port))


_HOSTNAME_LINE_RE = re.compile(r"^[A-Za-z0-9._-]+\.[A-Za-z0-9-]+$")


def handle_reverse_ip(ip: str):
    def reply(hostnames=None, error=None):
        return jsonify({"type": "ip_lookup", "hostnames": hostnames or [], "error": error})

    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.version == 6:
        return reply(error="Reverse IP lookup for IPv6 is not supported.")
    if not ip_obj.is_global:
        return reply(error="Reverse IP lookup only works for public addresses.")

    params = {"q": ip}
    if HACKERTARGET_API_KEY:
        params["apikey"] = HACKERTARGET_API_KEY
    try:
        resp = requests.get("https://api.hackertarget.com/reverseiplookup/", params=params,
                            timeout=10, headers={"User-Agent": "DomainIntelMatrix/2.1"})
    except requests.RequestException as e:
        return reply(error=f"Request to HackerTarget failed: {type(e).__name__}")

    lines = [l.strip() for l in resp.text.splitlines() if l.strip()]
    if resp.status_code != 200 or not lines:
        return reply(error=f"HackerTarget returned HTTP {resp.status_code}: {resp.text.strip()[:200]}")
    # HackerTarget reports errors and quota exhaustion as plain-text 200 responses
    if not all(_HOSTNAME_LINE_RE.match(l) for l in lines):
        return reply(error=f"HackerTarget: {lines[0][:200]}")
    return reply(hostnames=lines)


DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2", "k3",
                  "mail", "dkim", "s1", "s2", "protonmail", "zoho", "mxvault")


def handle_domain_check(raw_domain: str, resolver: DNS):
    domain = sanitize_domain(raw_domain)
    if not is_valid_domain(domain):
        return jsonify({"error": f"Invalid or unsupported domain: '{domain or raw_domain[:100]}'"}), 400

    results = {"domain": domain, "resolver": f"{resolver.ip}:{resolver.port}",
               "whois": {}, "dns": {}, "security": {}, "server": {}}

    pool = cf.ThreadPoolExecutor(max_workers=24)
    try:
        # Phase 1: independent lookups
        f_whois = pool.submit(get_whois, domain)
        f_http = pool.submit(probe_http, domain)
        f_tls = pool.submit(get_tls_info, domain)
        dns_jobs = {
            "A": (domain, "A"), "AAAA": (domain, "AAAA"),
            "A_www": (f"www.{domain}", "A"), "CNAME_www": (f"www.{domain}", "CNAME"),
            "NS": (domain, "NS"), "MX": (domain, "MX"), "SOA": (domain, "SOA"),
            "TXT": (domain, "TXT"), "DMARC": (f"_dmarc.{domain}", "TXT"),
            "CAA": (domain, "CAA"), "DS": (domain, "DS"), "DNSKEY": (domain, "DNSKEY"),
        }
        f_dns = {k: pool.submit(resolver.query, *v) for k, v in dns_jobs.items()}
        f_dkim = {s: pool.submit(resolver.query, f"{s}._domainkey.{domain}", "TXT") for s in DKIM_SELECTORS}

        raw = {k: f.result() for k, f in f_dns.items()}

        def disp(key):
            records, err = raw[key]
            return [f"Error: {err}"] if err else (records or None)

        for key in ("A", "AAAA", "A_www", "CNAME_www", "NS", "MX", "SOA"):
            results["dns"][key] = disp(key)

        # Phase 2: lookups that depend on phase 1
        a_ips = (raw["A"][0] or [])[:5]
        mx_hosts = [r.split(" ", 1)[1].rstrip(".") for r in (raw["MX"][0] or []) if " " in r]

        def mx_ptr(host):
            ips, err = resolver.query(host, "A")
            if err or not ips:
                return {"mail_server": host, "ip": "N/A", "ptr": err or "Could not resolve MX host."}
            return {"mail_server": host, "ip": ips[0], "ptr": resolver.ptr(ips[0])}

        f_rdns = [(ip, pool.submit(resolver.ptr, ip)) for ip in a_ips]
        f_mx = [pool.submit(mx_ptr, h) for h in mx_hosts[:10]]

        if f_rdns:
            results["dns"]["rDNS"] = [{"ip": ip, "hostname": f.result()} for ip, f in f_rdns]
        if f_mx:
            results["dns"]["MX_PTR"] = [f.result() for f in f_mx]

        # Email / security records
        txt, txt_err = raw["TXT"]
        spf = [r for r in (txt or []) if r.lower().startswith("v=spf1")]
        results["security"]["SPF"] = [f"Error: {txt_err}"] if txt_err else (spf or None)
        if len(spf) > 1:
            results["security"]["SPF_warning"] = "Multiple SPF records found. RFC 7208 treats this as a permanent error."
        dmarc_records, dmarc_err = raw["DMARC"]
        results["security"]["DMARC"] = ([f"Error: {dmarc_err}"] if dmarc_err else
                                        [r for r in dmarc_records if r.lower().startswith("v=dmarc1")] or None)
        results["security"]["CAA"] = disp("CAA")

        ds, ds_err = raw["DS"]
        dnskey, dnskey_err = raw["DNSKEY"]
        if ds_err or dnskey_err:
            results["security"]["DNSSEC"] = f"Unknown ({ds_err or dnskey_err})"
        elif ds and dnskey:
            results["security"]["DNSSEC"] = "Signed (DS at parent, DNSKEY published)"
        elif dnskey:
            results["security"]["DNSSEC"] = "DNSKEY published but no DS at parent (chain of trust incomplete)"
        elif ds:
            results["security"]["DNSSEC"] = "DS at parent but no DNSKEY (likely broken)"
        else:
            results["security"]["DNSSEC"] = "Not signed at this name"

        dkim = []
        for sel, f in f_dkim.items():
            records, err = f.result()
            for r in records or []:
                if "p=" in r or r.lower().startswith("v=dkim1"):
                    dkim.append(f"Selector: {sel}\nRecord: {r}")
        results["security"]["DKIM"] = dkim or None

        results["server"] = f_http.result()
        results["server"]["ssl_info"] = f_tls.result()

        try:
            results["whois"] = f_whois.result(timeout=WHOIS_TIMEOUT)
        except cf.TimeoutError:
            results["whois"] = {"error": f"WHOIS lookup timed out after {WHOIS_TIMEOUT}s"}
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    return jsonify({"type": "domain_check", "data": results})

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print(" Domain Intel Matrix backend")
    print(f" Listening on    : http://{HOST}:{PORT}")
    print(f" Private targets : {'allowed' if ALLOW_PRIVATE_TARGETS else 'blocked'}")
    print("=" * 60)
    try:
        from waitress import serve
        serve(app, host=HOST, port=PORT, threads=8)
    except ImportError:
        log.warning("waitress not installed, falling back to Flask's development server.")
        app.run(host=HOST, port=PORT, debug=False, threaded=True)
