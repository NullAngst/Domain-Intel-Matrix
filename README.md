# Domain Intel Matrix

A self-hosted, web-based domain intelligence tool powered by a Python Flask backend. This application provides a comprehensive overview of a domain's configuration, including WHOIS data, DNS records, SSL certificate information, and server headers, all presented in a clean, dark-themed interface.

---

## Features

- **WHOIS Lookup**: Get registrar, creation date, and expiration date.
- **Comprehensive DNS Records**: A, AAAA, CNAME, NS, MX, SOA, and rDNS.
- **Security Auditing**: Checks for SPF, DMARC, CAA, DNSSEC, DKIM, and PTR records.
- **SSL Certificate Info**: Displays the certificate issuer, subject, and expiration date.
- **Server Headers**: Inspects HTTP headers from the target server.
- **Web Interface**: A modern, dark-themed UI for easy viewing of results.
- **Pick a custom DNS server**: Also supports ports! (eg. 127.0.0.1:5335)
- **Reverse IP lookups**: Currently limited to IPv4 due to API limitations. Lookups use the free endpoint by default but can optionally [use an API key](https://github.com/NullAngst/Domain-Intel-Matrix/edit/main/README.md#api-key).
- **Systemd Service**: Can be configured to run as a background service that starts on boot.
- **Easy to run in Docker**

---

## Prerequisites

- Python 3.8 or newer
- `python3-venv` package for creating virtual environments ([or run it in Docker](https://github.com/NullAngst/Domain-Intel-Matrix/edit/main/README.md#optionally-run-this-in-docker_)).
- `sudo` privileges.

---

## Setup Instructions

These instructions will guide you through setting up the application in the `/home/$USER/checker` directory and running it as a systemd service.

### 1. Prepare the System and Project Files

First, update your package list and install the Python virtual environment package.

```
sudo apt update
sudo apt install python3-venv -y
```

Next, create the project directory and navigate into it.
```
mkdir -p /home/$USER/checker
cd /home/$USER/checker
```
Place the two application files, checker_backend.py and checker_frontend.html, inside this directory.
### 2. Create `requirements.txt`

Create a file to list the Python dependencies.

`nano requirements.txt`

Add the following lines to the file, then save and exit (Ctrl+X, then Y, then Enter):
```
Flask
Flask-Cors
dnspython
python-whois
requests
ipaddress
```
### 3. Set Up the Virtual Environment
`python3 -m venv venv`

### Activate the environment
`source venv/bin/activate`

### Install dependencies
`pip install -r requirements.txt`

## Running as a Systemd Service (Recommended)

This setup will ensure the application starts automatically on boot and runs reliably in the background.
### 1. Create the Systemd Service File

Use a text editor to create a service configuration file for systemd.

`sudo nano /etc/systemd/system/checker.service`

Copy and paste the following configuration into the file. This defines how the service should be run.
```
[Unit]
Description=Domain Intel Matrix Flask Application
After=network.target

[Service]
# Replace '$USER' with your actual username if it's different
User=$USER
Group=$USER

# The directory where your files are located
WorkingDirectory=/home/$USER/checker

# The command to start the application
# Note: We use the Python executable from our virtual environment
ExecStart=/home/$USER/checker/venv/bin/python /home/$USER/checker/checker_backend.py

# Restart the service if it fails
Restart=always

[Install]
WantedBy=multi-user.target
```
Save and exit the editor.
### 2. Manage and Enable the Service

Reload the systemd daemon to recognize the new service, then start and enable it.

### Reload systemd to apply changes
`sudo systemctl daemon-reload`

### Start the service now
`sudo systemctl start checker.service`

### Enable the service to start automatically on boot
`sudo systemctl enable checker.service`

### 3. Verify the Service Status

Check that the service is running correctly.

`sudo systemctl status checker.service`

You should see an output with active (running). Press q to exit.

## Firewall Configuration

If you are using a firewall like UFW, you must allow traffic on the port the application uses (port 4500 in this case).

`sudo ufw allow 4500/tcp`

Usage

Once the service is running, you can access the Domain Intel Matrix from any device on your local network by navigating to:

`http://<your_server_ip>:4500`

Replace <your_server_ip> with the local IP address of the machine running the application. You can find this IP by running `ip addr show` on the server.

## Optionally, run this in Docker
*This assumes you are already running Docker and have at least some working knowledge of it.*

### 1. Clone the contents of this repo (or just download each file) to the location where you'd like to run it.

### 2. In the same directory, make a Dockerfile with the following contents (adjust to your environment as needed).
```
# Use an official Python runtime as a parent image
FROM python:3.13-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the current directory contents into the container at /usr/src/app
COPY . .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 4500 available to the world outside this container.
EXPOSE 4500

# Run checker_backend.py when the container launches
CMD ["python", "./checker_backend.py"]
```

### 3. Create a new text file named requirements.txt with the same contents [as listed above](https://github.com/NullAngst/Domain-Intel-Matrix#2-create-requirementstxt).

### 4. While in the directory with the files, run `docker build -t domain-intel-matrix/latest .`
*domain-intel-matrix/latest can be replaced with whatever name you like.*

This command will build a simple Docker image that contains the files in the current directory, a copy of Python (and this app's dependencies). The container will start the python file at startup.

### 5. Use Docker run or Docker Compose to create a container based on the image that was just created.
`docker run -p 4500:4500 --restart unless-stopped domain-intel-matrix/latest`

```
services:
  dim:
    image: domain-intel-matrix/latest
    ports:
      - 4500:4500
    restart: unless-stopped
```
You may want to attach it to a network you have already configured also. If you changed the name specified in the build command, you'll need to change it here too.

## API Key
If you have an API key for Hacker Target insert it into a file named config.py with the following syntax:

`HACKERTARGET_API_KEY = "YOUR_API_KEY_HERE"`

If we assume your API key is key123 the file should look like this:

`HACKERTARGET_API_KEY = "key123"`
