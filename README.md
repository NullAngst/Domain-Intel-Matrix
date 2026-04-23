# Domain Intel Matrix

A self-hosted, web-based domain intelligence tool powered by a Python Flask backend. This application provides a comprehensive overview of a domain's configuration, including WHOIS data, DNS records, SSL certificate information, HTTP headers, CDN/technology detection, and email security records — all presented in a clean, dark-themed interface.

---

## Features

- **WHOIS Lookup** — Registrar, creation date, expiration date, and name servers.
- **Comprehensive DNS Records** — A, AAAA, CNAME, NS, MX, SOA, and rDNS.
- **Email Security Auditing** — SPF, DMARC, DKIM (10 common selectors), and PTR records for MX hosts.
- **Security Record Checks** — CAA, DNSSEC, and PTR.
- **SSL Certificate Info** — Issuer, subject, expiration date, issuer org, and Subject Alternative Names (SANs).
- **Security Header Analysis** — Colour-coded badges for HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, CORP, and COOP.
- **Technology & CDN Detection** — Identifies WordPress, Next.js, Nuxt, Ghost, Joomla, Drupal, Shopify, and CDN providers (Cloudflare, CloudFront, Fastly, Akamai, Varnish).
- **Full HTTP Header Inspection** — Protocol, status code, final URL (after redirects), and raw headers.
- **Reverse IP Lookup** — Finds hostnames sharing an IP (IPv4 only). Click any hostname to run a full domain scan on it.
- **Custom DNS Resolver** — Supports custom nameservers with optional port (e.g. `127.0.0.1:5335`) and IPv6 resolvers.
- **Query History** — Persists the last 10 queries in your browser's `localStorage`.
- **Export Results** — Copy to clipboard or download as a JSON file.
- **Modern Dark UI** — Sticky search bar, colour-coded security badges, scrollable pre blocks, XSS-safe rendering.
- **Easy Deployment** — Runs as a systemd service or in Docker.

---

## Prerequisites

- Python 3.8 or newer
- `python3-venv` for creating virtual environments ([or run in Docker](#optionally-run-this-in-docker))
- `sudo` privileges (required for systemd setup only)

---

## Setup Instructions

These instructions set up the application in `/home/$USER/checker` and run it as a systemd service.

### 1. Prepare the System and Project Files

```bash
sudo apt update
sudo apt install python3-venv -y
```

Create the project directory and place the application files inside it:

```bash
mkdir -p /home/$USER/checker
cd /home/$USER/checker
# Copy checker_backend.py and checker_frontend.html here
```

### 2. Create `requirements.txt`

```bash
cat > requirements.txt << 'EOF'
Flask
Flask-Cors
dnspython
python-whois
requests
ipaddress
EOF
```

### 3. Set Up the Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. (Optional) Configure an API Key

For reverse IP lookups, create a `config.py` in the project directory:

```python
HACKERTARGET_API_KEY = "your_api_key_here"
```

Without a key the free HackerTarget tier is used (rate-limited). See [API Key](#api-key) for details.

---

## Running as a Systemd Service (Recommended)

### 1. Create the Service File

```bash
sudo nano /etc/systemd/system/checker.service
```

Paste the following, replacing `$USER` with your actual username:

```ini
[Unit]
Description=Domain Intel Matrix Flask Application
After=network.target

[Service]
User=$USER
Group=$USER
WorkingDirectory=/home/$USER/checker
ExecStart=/home/$USER/checker/venv/bin/python /home/$USER/checker/checker_backend.py
Restart=always

[Install]
WantedBy=multi-user.target
```

### 2. Enable and Start the Service

```bash
sudo systemctl daemon-reload
sudo systemctl start checker.service
sudo systemctl enable checker.service
```

### 3. Verify

```bash
sudo systemctl status checker.service
```

You should see `active (running)`. Press `q` to exit.

---

## Firewall Configuration

If you use UFW, allow port 4500:

```bash
sudo ufw allow 4500/tcp
```

---

## Usage

Once running, open a browser and navigate to:

```
http://<your_server_ip>:4500
```

Replace `<your_server_ip>` with the machine's local IP address (`ip addr show`). On the same machine you can use `http://127.0.0.1:4500`.

**Supported query types:**
- `example.com` — full domain scan
- `https://example.com/some/path` — URL is automatically stripped to the hostname
- `192.0.2.1` — reverse IP lookup (IPv4 only)

---

## Optionally, Run This in Docker

*This assumes Docker is already installed.*

### 1. Clone or download the project files into a directory.

### 2. Create a `Dockerfile` in the same directory:

```dockerfile
FROM python:3.13-slim

WORKDIR /usr/src/app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 4500

CMD ["python", "./checker_backend.py"]
```

### 3. Build the image:

```bash
docker build -t domain-intel-matrix:latest .
```

### 4. Run the container:

```bash
docker run -p 4500:4500 --restart unless-stopped domain-intel-matrix:latest
```

### 5. (Optional) Docker Compose

Create a `docker-compose.yml`:

```yaml
services:
  dim:
    image: domain-intel-matrix:latest
    ports:
      - "4500:4500"
    restart: unless-stopped
```

Then run:

```bash
docker compose up -d
```

---

## API Key

Reverse IP lookups use the [HackerTarget API](https://hackertarget.com/ip-tools/). Without a key, the free tier applies (limited requests per day).

To add a key, create `config.py` in the project directory:

```python
HACKERTARGET_API_KEY = "your_api_key_here"
```

The backend loads this file automatically on startup. If the file is absent or the key is the placeholder value, the free tier is used and a warning is logged.

---

## Configuration

The backend has a single toggle at the top of `checker_backend.py`:

| Variable         | Default | Description                                      |
|------------------|---------|--------------------------------------------------|
| `VERBOSE_LOGGING`| `False` | Set to `True` for detailed debug output to stdout |

---

## Security Notes

- **Network exposure** — By default the server binds to `0.0.0.0:4500`, making it reachable on your local network. Do **not** expose this port to the public internet without adding authentication.
- **SSRF mitigations** — The backend validates domain inputs and rejects `localhost`, `.local`, and `.internal` hostnames.
- **Output escaping** — All data returned by the API is HTML-escaped in the frontend before being inserted into the DOM, preventing XSS.
- **No persistent storage** — The backend stores nothing. All query history lives in your browser's `localStorage`.

---

## Changelog

### v2.0
- **Bug fixes**
  - Fixed URL parsing: scheme, path, query string, and port are now all correctly stripped before DNS/HTTP queries.
  - Fixed WHOIS `name_servers` field: lists/sets are now normalised and deduplicated before JSON serialisation.
  - Fixed MX PTR resolution: trailing dots are stripped from MX hostnames before A-record lookups.
  - Fixed `performCheck` IP detection: tighter regex prevents non-IP strings matching.
  - Fixed `renderIpLookupResults` back button: button is now correctly toggled for IP scan context.
  - Fixed session cache key collision: cache keys are now prefixed with `dim:`.
- **Security**
  - All dynamic values are HTML-escaped in the frontend (`esc()` helper) to prevent XSS.
  - Domain input validation on the backend rejects `localhost` and RFC-reserved local names.
- **New features**
  - SOA records now include Refresh, Retry, Expire, and Minimum TTL fields.
  - SSL info now includes Issuer Organisation and Subject Alternative Names (capped at 10).
  - Security headers now show colour-coded badges (green ✓ / red ✗) with value previews.
  - Technology detection extended: Next.js, Nuxt.js, Ghost, Shopify, Cloudflare, CloudFront, Fastly, Akamai, Varnish, and more.
  - Added 5 more DKIM selectors: `protonmail`, `zoho`.
  - Added 2 new security headers: `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`.
  - Loader message now reflects the query type (domain vs IP).
  - Scan button is disabled while a request is in flight.
  - HTTP requests now use a shared session with a descriptive User-Agent.
  - `downloadButton` uses `URL.createObjectURL` (avoids data-URI length limits on large results).
  - Added `autocomplete="off"`, `autocapitalize="off"`, `spellcheck="false"` to query inputs.
