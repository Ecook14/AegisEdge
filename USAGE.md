# AegisEdge Usage Guide

## ⚡ Rapid Deployment (The 60-Second Shield)

To instantly protect any server (WHM, Plesk, or Baremetal) without manual configuration:

```bash
sudo bash scripts/takeover.sh
```

---

This guide provides instructions on how to run, test, and manage the AegisEdge security proxy.

### 0. Start the Demo Upstream (Optional)
To test the proxy without an external website, run the included demo server:
```bash
go run cmd/demo_server/main.go
```
This server listens on `localhost:3000`.

## 1. Run AegisEdge

To start the proxy with the default configuration:

```bash
# Important: Run the entire package (.), not just the main.go file
go run .
```

By default, the proxy listens on port `8080` and proxies traffic to `http://localhost:3000`.

### Configuration
You can customize the behavior by editing `config.json` or setting environment variables:
- `AEGISEDGE_REDIS_ADDR`: Address of the Redis server (e.g., `localhost:6379`) for distributed state.
- `AEGISEDGE_PORT`: Port for the proxy to listen on.

> [!NOTE]
> **GeoIP Support**: To enable country-level blocking, download the `GeoLite2-Country.mmdb` file from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and place it in the root directory. If the file is missing, the GeoIP filter will be automatically bypassed.

---

## 2. Simulating Attacks

AegisEdge includes a specialized stress testing tool to verify security filters. Usage:

### WAF: SQL Injection
```bash
go run cmd/stress_tool/main.go -mode sqli -n 10
```

### WAF: Cross-Site Scripting (XSS)
```bash
go run cmd/stress_tool/main.go -mode xss -n 10
```

### WAF: Command Injection
```bash
go run cmd/stress_tool/main.go -mode cmd -n 10
```

### L7: Rate Limiting
Run a large number of requests to trigger the rate limiter:
```bash
go run cmd/stress_tool/main.go -mode clean -n 200 -c 20
```

---

## 3. Management API

AegisEdge provides a management API on port `9091` for administrative tasks.

### Check Status & Active Blocks
```bash
curl http://localhost:9091/api/status
```

### Manually Block an IP
```bash
curl -X POST http://localhost:9091/api/block \
     -H "Content-Type: application/json" \
     -d '{"ip": "1.2.3.4", "duration": "1h"}'
```

### Manually Unblock an IP
```bash
curl -X DELETE "http://localhost:9091/api/block?ip=1.2.3.4"
```

---

## 4. Monitoring & Metrics

AegisEdge exports Prometheus metrics on port `9090`.

### View Metrics
```bash
curl http://localhost:9090/metrics
```

Key metrics to watch:
- `aegisedge_blocked_requests_total`: Total requests blocked, partitioned by `layer` and `reason`.
- `aegisedge_active_connections`: Currently active proxied connections.
- `aegisedge_request_duration_seconds`: Latency histogram for proxied requests.
