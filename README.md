# Domain Intel Matrix

A self-hosted, web-based domain intelligence tool powered by a Python Flask backend. This application provides a comprehensive overview of a domain's configuration, including WHOIS data, DNS records, SSL certificate information, HTTP headers, CDN/technology detection, and email security records: all presented in a clean, dark-themed interface.

---

## Features

- **WHOIS Lookup**: Registrar, creation date, expiration date, and name servers.
- **Comprehensive DNS Records**: A, AAAA, CNAME, NS, MX, SOA, and rDNS.
- **Email Security Auditing**: SPF, DMARC, DKIM (10 common selectors), and PTR records for MX hosts.
- **Security Record Checks**: CAA, DNSSEC, and PTR.
- **SSL Certificate Info**: Issuer, subject, expiration date, issuer org, and Subject Alternative Names (SANs).
- **Security Header Analysis**: Colour-coded badges for HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, CORP, and COOP.
- **Technology & CDN Detection**: Identifies WordPress, Next.js, Nuxt, Ghost, Joomla, Drupal, Shopify, and CDN providers (Cloudflare, CloudFront, Fastly, Akamai, Varnish).
- **Full HTTP Header Inspection**: Protocol, status code, final URL (after redirects), and raw headers.
- **Reverse IP Lookup**: Finds hostnames sharing an IP (IPv4 only). Click any hostname to run a full domain scan on it.
- **Custom DNS Resolver**: Supports custom nameservers with optional port (e.g. `127.0.0.1:5335`) and IPv6 resolvers.
- **Query History**: Persists the last 10 queries in your browser's `localStorage`.
- **Export Results**: Copy to clipboard or download as a JSON file.
- **Modern Dark UI**: Sticky search bar, colour-coded security badges, scrollable pre blocks, XSS-safe rendering.
- **Easy Deployment**: Runs as a systemd service or in Docker.

---

## Prerequisites

- Python 3.9 or newer
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
# Copy checker_backend.py, checker_frontend.html, and requirements.txt here
```

### 2. Set Up the Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. (Optional) Configure an API Key

For reverse IP lookups, set `HACKERTARGET_API_KEY` in the environment, or create a `config.py` in the project directory:

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
- `example.com`: full domain scan
- `https://example.com/some/path`: URL is automatically stripped to the hostname
- `192.0.2.1`: reverse IP lookup (IPv4 only)

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
docker build -t nullangst/domain-intel-matrix:latest .
```

### 4. Run the container:

```bash
docker run -p 4500:4500 --restart unless-stopped nullangst/domain-intel-matrix:latest
```

### 5. (Optional) Docker Compose

Create a `docker-compose.yml`:

```yaml
services:
  dim:
    image: nullangst/domain-intel-matrix:latest
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

To add a key, either set the `HACKERTARGET_API_KEY` environment variable (preferred for Docker and systemd), or create `config.py` in the project directory:

```python
HACKERTARGET_API_KEY = "your_api_key_here"
```

The environment variable wins if both are set. The key is read once at startup, so restart the service after changing it. If neither is present, or the key is the placeholder value, the free tier is used and a warning is logged.

---

## Configuration

All settings are environment variables. Nothing needs editing in the source.

| Variable                    | Default   | Description |
| --------------------------- | --------- | ----------- |
| `DIM_HOST`                  | `0.0.0.0` | Bind address. Use `127.0.0.1` to keep it off the network. |
| `DIM_PORT`                  | `4500`    | Listen port. |
| `DIM_DEFAULT_NAMESERVER`    | `9.9.9.9` | Resolver used when the request doesn't specify one. |
| `DIM_ALLOW_PRIVATE_TARGETS` | `false`   | Allow HTTP/TLS probes to private, loopback, and link-local addresses. See Security Notes. |
| `DIM_VERBOSE`               | `false`   | Debug logging to stdout. |
| `HACKERTARGET_API_KEY`      | unset     | Reverse IP API key (overrides `config.py`). |

For systemd, add lines such as `Environment=DIM_HOST=127.0.0.1` under `[Service]`. For Docker, pass `-e DIM_PORT=...` or use an `environment:` block in compose.

The server runs under [waitress](https://docs.pylonsproject.org/projects/waitress/) when it is installed (it is in `requirements.txt`) and falls back to Flask's development server otherwise.

---

## Security Notes

- **Network exposure.** By default the server binds to `0.0.0.0:4500`, making it reachable on your local network. There is no authentication. Do **not** expose this port to the public internet; put it behind a reverse proxy with auth if you need remote access, or set `DIM_HOST=127.0.0.1`.
- **What the server serves.** Only `/` (the UI) and `/check`. The project directory is not exposed, so `config.py` and the source can't be downloaded.
- **Cross-origin access.** CORS is not enabled. Other websites open in your browser can't read `/check` responses from your instance.
- **SSRF mitigations.** Obvious local names (`localhost`, `.local`, `.internal`, `.lan`, `.home.arpa`, and similar) are rejected. Separately, every outbound HTTP and TLS connection, including each redirect hop, is checked against the address it actually connected to, and refused if that address is private, loopback, link-local, or otherwise non-public. Checking the connected address rather than a pre-resolved one means DNS rebinding doesn't get around it. Set `DIM_ALLOW_PRIVATE_TARGETS=true` if you want to scan internal hosts.
- **What the SSRF guard does not cover.** DNS queries go to whatever resolver IP and port the request names, including private ones, because pointing at a local resolver (`127.0.0.1:5335`) is a supported use. Anyone who can reach the UI can therefore make the server send DNS packets to arbitrary host:port pairs on your network. WHOIS lookups go to public WHOIS servers chosen by `python-whois`.
- **Output escaping.** All data returned by the API is HTML-escaped before it reaches the DOM, and error messages are inserted as text nodes. The page also sends a Content-Security-Policy that blocks external scripts. The inline script requires `'unsafe-inline'`, which limits how much the CSP adds on top of the escaping.
- **No persistent storage.** The backend stores nothing. Query history lives in your browser's `localStorage`.
