# Aran WAAP — Web Application and API Protection Edge Proxy

**Version:** 1.0.0  
**Go Version:** 1.22+

## Overview

Aran WAAP is an edge proxy layer deployed between mobile RASP clients and the Mazhai Central backend. It provides:

- **BOLA Protection**: Broken Object Level Authorization detection
- **IDOR Prevention**: Insecure Direct Object Reference blocking  
- **Rate Limiting**: Token bucket per-IP throttling
- **Request Inspection**: Aran telemetry payload validation
- **TLS 1.3 Termination**: With cipher suite enforcement

## Architecture

```
Mobile RASP ──▶ Aran WAAP (port 33100) ──▶ Mazhai Central (port 33100)
                    │
                    ├─ BOLA/IDOR detection
                    ├─ Rate limiting
                    ├─ Auth validation
                    └─ Metrics (Prometheus)
```

## Quick Start

### Development

```bash
cd aran-waap
go run main.go --upstream http://localhost:33100
```

### Production

```bash
# Build
go build -o aran-waap main.go

# Run with config
./aran-waap --config config.yaml --port 33100
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ARAN_WAAP_PORT` | Listen port | 33100 |
| `ARAN_WAAP_UPSTREAM` | Backend URL | http://localhost:33100 |
| `ARAN_WAAP_ENV` | Environment | production |
| `DEBUG` | Enable debug logs | false |

### Config File (config.yaml)

```yaml
environment: production
port: 33100
upstream: http://mazhai-central:33100

rate_limit:
  requests_per_second: 1000
  burst_size: 1500
  block_duration_minutes: 10

ar_auth_keys:
  - "prod-license-key-hash-1"
  - "prod-license-key-hash-2"

tls:
  enabled: true
  cert_file: /etc/aran/server.crt
  key_file: /etc/aran/server.key
  min_version: "1.3"
  cipher_suites:
    - TLS_AES_256_GCM_SHA384
    - TLS_AES_128_GCM_SHA256
```

## Features

### BOLA Detection

Detects path traversal and ID enumeration attacks:
- `../` patterns in URLs
- Sequential ID access from unauthorized devices
- Suspicious request patterns

### IDOR Prevention

Validates resource ownership:
- Extracts device fingerprint from request
- Validates against resource ownership records
- Blocks unauthorized access attempts

### Telemetry Inspection

Validates Aran RASP requests:
- Checks for required E2EE headers
- Validates nonce freshness
- Verifies HMAC signatures

### Rate Limiting

Token bucket algorithm per IP:
- Default: 1000 req/s with 1500 burst
- Automatic blocking for 10 minutes on violation

## Metrics

Prometheus metrics exposed at `/metrics`:

```
aran_waap_requests_total{method,endpoint,status}
aran_waap_request_duration_seconds{method,endpoint}
aran_waap_threats_detected_total{threat_type}
aran_waap_active_connections
```

## Deployment

### Docker

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o aran-waap main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/aran-waap /usr/local/bin/
EXPOSE 33100
CMD ["aran-waap"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aran-waap
spec:
  replicas: 3
  selector:
    matchLabels:
      app: aran-waap
  template:
    metadata:
      labels:
        app: aran-waap
    spec:
      containers:
      - name: waap
        image: ghcr.io/techdhamo/aran-waap:v1.0.0
        ports:
        - containerPort: 33100
        env:
        - name: ARAN_WAAP_UPSTREAM
          value: "http://mazhai-central:33100"
        - name: ARAN_WAAP_ENV
          value: "production"
```

## Security

### Threat Response

When BOLA/IDOR detected:
1. Request blocked with 403 Forbidden
2. Event logged to SIEM
3. Client fingerprint added to watchlist (if repeat offender)
4. Metrics incremented for monitoring

### TLS Configuration

Minimum TLS 1.3 with strong cipher suites:
- `TLS_AES_256_GCM_SHA384`
- `TLS_AES_128_GCM_SHA256`

## License

Apache 2.0 — See [LICENSE](../LICENSE)
