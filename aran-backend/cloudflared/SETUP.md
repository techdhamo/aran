# Cloudflared Setup for Aran Security Platform

This directory contains the Cloudflared tunnel configuration for mapping aran.mazhai.org subdomains to internal services.

## Prerequisites

1. A Cloudflare account with the domain `mazhai.org`
2. Cloudflare Zero Trust tunnel created

## Setup Instructions

### 1. Create a Cloudflare Tunnel

1. Log in to Cloudflare Zero Trust dashboard
2. Navigate to: Networks > Tunnels
3. Click "Create a tunnel"
4. Name it: `aran-tunnel`
5. Copy the **Tunnel ID** (looks like: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)

### 2. Download Tunnel Credentials

1. After creating the tunnel, click "Configure"
2. Choose your platform (Docker/Linux)
3. Download the credentials file (it will be named `<TUNNEL_ID>.json`)

### 3. Update config.yaml

Edit `config.yaml` and replace the placeholder values:

```yaml
tunnel: <YOUR_TUNNEL_ID>
credentials-file: /etc/cloudflared/<YOUR_TUNNEL_ID>.json
```

### 4. Mount Credentials in Docker Compose

Update the docker-compose.yml cloudflared service:

```yaml
cloudflared:
  image: cloudflare/cloudflared:latest
  container_name: aran-cloudflared
  volumes:
    - ../aran-website:/usr/share/nginx/html:ro
    - ./cloudflared/config.yaml:/etc/cloudflared/config.yaml:ro
    - ./cloudflared/<YOUR_TUNNEL_ID>.json:/etc/cloudflared/<YOUR_TUNNEL_ID>.json:ro
  command: ["tunnel", "--config", "/etc/cloudflared/config.yaml", "run"]
```

### 5. Configure DNS Records

In Cloudflare DNS settings for `mazhai.org`, add these CNAME records:

- `aran` → CNAME → `<YOUR_TUNNEL_ID>.cfargotunnel.com`
- `api.aran` → CNAME → `<YOUR_TUNNEL_ID>.cfargotunnel.com`
- `iam.aran` → CNAME → `<YOUR_TUNNEL_ID>.cfargotunnel.com`
- `tenant.aran` → CNAME → `<YOUR_TUNNEL_ID>.cfargotunnel.com`
- `telemetry.aran` → CNAME → `<YOUR_TUNNEL_ID>.cfargotunnel.com`
- `gateway.aran` → CNAME → `<YOUR_TUNNEL_ID>.cfargotunnel.com`

### 6. Restart Services

```bash
cd aran-backend
docker-compose down
docker-compose up -d
```

## Subdomain Mappings

- `aran.mazhai.org` → Official website (nginx on port 11007)
- `api.aran.mazhai.org` → WAF/Envoy (port 11004)
- `iam.aran.mazhai.org` → IAM Service (port 11000)
- `tenant.aran.mazhai.org` → Tenant Service (port 11001)
- `telemetry.aran.mazhai.org` → Telemetry Service (port 11002)
- `gateway.aran.mazhai.org` → API Gateway (port 11003)

## Current Status

The official website is running on port 11007 and can be accessed at:
- http://localhost:11007

Cloudflared tunnel setup requires manual configuration with Cloudflare credentials.
