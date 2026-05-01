# Cisco CUCM HTTPS Migration (Ubuntu 24.04)

This guide moves the site from HTTP to HTTPS with Nginx while keeping FastAPI/Uvicorn on localhost.

Deployment scope:
- Internal network access only
- No internet exposure

Certificate model:
- Internal enterprise-signed certificate

## Target Architecture

- Public traffic: HTTPS on 443 (Nginx)
- Redirect HTTP 80 -> HTTPS 443
- App process: Uvicorn on 127.0.0.1:8000 (not exposed publicly)

## Prerequisites

- Ubuntu Server 24.04
- DNS A record for `lascrtmp01.ahs.int` pointing to `10.241.18.15`
- App code deployed and runnable (main:app)
- Sudo access

Current target values:
- Hostname: `lascrtmp01.ahs.int`
- Server IP: `10.241.18.15`

## 1) Install Nginx and certificate tooling

```bash
sudo apt update
sudo apt install -y nginx openssl
```

## 2) Allow firewall traffic

If UFW is enabled:

```bash
sudo ufw allow OpenSSH
sudo ufw allow from 10.0.0.0/8 to any port 443 proto tcp
sudo ufw allow from 172.16.0.0/12 to any port 443 proto tcp
sudo ufw allow from 192.168.0.0/16 to any port 443 proto tcp
sudo ufw status
```

Note:
- Keep port 80 restricted unless temporary validation requires it.
- Adjust allowed CIDRs to your actual enterprise subnets.

## 3) Create systemd service for Uvicorn

Create service file:

```bash
sudo nano /etc/systemd/system/cisco-cucm.service
```

Service content:

```ini
[Unit]
Description=Cisco CUCM FastAPI Service
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/cisco_cucm
Environment="PATH=/opt/cisco_cucm/venv/bin"
ExecStart=/opt/cisco_cucm/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cisco-cucm
sudo systemctl start cisco-cucm
sudo systemctl status cisco-cucm
```

## 4) Create Nginx site config (HTTP first)

Create file:

```bash
sudo nano /etc/nginx/sites-available/cisco-cucm
```

Config content (current target host):

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name lascrtmp01.ahs.int;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable site and validate:

```bash
sudo ln -s /etc/nginx/sites-available/cisco-cucm /etc/nginx/sites-enabled/cisco-cucm
sudo nginx -t
sudo systemctl reload nginx
```

## 5) Apply TLS certificate (internal enterprise-signed)

When your internal PKI team provides files (server cert, private key, and CA chain), place them in a protected location:

```bash
sudo mkdir -p /etc/nginx/ssl/cisco-cucm
sudo cp server.crt /etc/nginx/ssl/cisco-cucm/
sudo cp server.key /etc/nginx/ssl/cisco-cucm/
sudo cp ca-chain.crt /etc/nginx/ssl/cisco-cucm/
sudo chown root:root /etc/nginx/ssl/cisco-cucm/*
sudo chmod 600 /etc/nginx/ssl/cisco-cucm/server.key
sudo chmod 644 /etc/nginx/ssl/cisco-cucm/server.crt /etc/nginx/ssl/cisco-cucm/ca-chain.crt
```

If your server cert and chain are separate files, create a full chain file:

```bash
sudo sh -c 'cat /etc/nginx/ssl/cisco-cucm/server.crt /etc/nginx/ssl/cisco-cucm/ca-chain.crt > /etc/nginx/ssl/cisco-cucm/fullchain.crt'
sudo chmod 644 /etc/nginx/ssl/cisco-cucm/fullchain.crt
```

Update Nginx config:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name lascrtmp01.ahs.int;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name lascrtmp01.ahs.int;

    ssl_certificate /etc/nginx/ssl/cisco-cucm/fullchain.crt;
    ssl_certificate_key /etc/nginx/ssl/cisco-cucm/server.key;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Validate and reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## 6) Verify HTTPS

```bash
curl -I http://lascrtmp01.ahs.int
curl -I https://lascrtmp01.ahs.int
```

Expected:
- HTTP returns 301/308 redirect to HTTPS
- HTTPS returns 200 (or expected app response)

## 7) Confirm renewal / expiration

For internal certificates, track expiration and coordinate rotation with PKI before expiry:

```bash
openssl x509 -in /etc/nginx/ssl/cisco-cucm/fullchain.crt -noout -dates -issuer -subject
```

## Optional hardening

Add security headers in the SSL server block created by Certbot:

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

Then reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

Optional internal-only access control in Nginx SSL server block:

```nginx
allow 10.0.0.0/8;
allow 172.16.0.0/12;
allow 192.168.0.0/16;
deny all;
```

## Day-2 operations

After code updates:

```bash
cd /opt/cisco_cucm
git pull
sudo systemctl restart cisco-cucm
sudo systemctl status cisco-cucm --no-pager
```

If Nginx config or cert changes:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

If internal cert files are replaced during rotation:

```bash
sudo systemctl reload nginx
```

## Troubleshooting

- App service logs:

```bash
sudo journalctl -u cisco-cucm -n 200 --no-pager
```

- Nginx error logs:

```bash
sudo tail -n 200 /var/log/nginx/error.log
```

- Check bound ports:

```bash
sudo ss -tulpn | grep -E '(:80|:443|:8000)'
```

## Rollback (HTTPS -> HTTP)

Use this if HTTPS cutover fails and you need quick service restoration.

1) Back up current Nginx site config:

```bash
sudo cp /etc/nginx/sites-available/cisco-cucm /etc/nginx/sites-available/cisco-cucm.bak.$(date +%Y%m%d_%H%M%S)
```

2) Replace with HTTP-only config:

```bash
sudo tee /etc/nginx/sites-available/cisco-cucm > /dev/null <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name lascrtmp01.ahs.int;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
```

3) Validate and reload Nginx:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

4) Verify HTTP is back and HTTPS is disabled:

```bash
curl -I http://lascrtmp01.ahs.int
curl -k -I https://lascrtmp01.ahs.int
```

Expected:
- HTTP returns 200 (or expected app response)
- HTTPS fails or returns no active TLS server

5) Keep app service running:

```bash
sudo systemctl status cisco-cucm --no-pager
sudo journalctl -u cisco-cucm -n 100 --no-pager
```
