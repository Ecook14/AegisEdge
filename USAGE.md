# AegisEdge Usage Guide

## ⚡ Rapid Deployment (The 60-Second Shield)

To instantly protect any server (WHM, Plesk, or Baremetal) without manual configuration:

```bash
sudo bash scripts/takeover.sh
```

---

### 0. Start the Demo Upstream (Optional)
To test the proxy without an external service, run the included demo server:
```bash
go run cmd/demo_server/main.go
```
Starts a lightweight upstream at `localhost:3000`.

---

## 1. Run AegisEdge

```bash
# Run the full package (required — main.go alone won't compile)
go run .

# Pass a custom config file path
go run . /path/to/custom-config.json
```

**Default behavior**: listens on ports `80` and `8080`, proxies to `http://127.0.0.1:3000`.

### Configuration (`config.json`)

```json
{
    "listen_ports": [80, 8080],
    "tcp_ports": [],
    "upstream_addr": "http://127.0.0.1:3000",
    "l3_blacklist": ["1.2.3.4"],
    "l4_conn_limit": 10,
    "l7_rate_limit": 5.0,
    "l7_burst_limit": 10,
    "geoip_db_path": "GeoLite2-Country.mmdb",
    "blocked_countries": ["CN", "RU", "IR"],
    "hot_takeover": false,
    "hypervisor_mode": false,
    "ssl_cert_path": "",
    "ssl_key_path": "",
    "toggles": {
        "waf": true,
        "geoip": true,
        "challenge": true,
        "anomaly": true,
        "stats": true
    }
}
```

**Key config fields:**
- `l7_rate_limit` / `l7_burst_limit`: Per-IP token bucket rate (req/sec) and burst ceiling.
- `l4_conn_limit`: Max concurrent connections per IP (idle timeout: **5 minutes**).
- `tcp_ports`: Raw TCP ports (e.g., SSH 22, DB 3306) to shield with the L4 limiter.
- `hot_takeover`: Uses OS-level port redirection to intercept an already-occupied port — zero downtime.
- `hypervisor_mode`: Extends idle → 300s, read → 30s for high-density VM environments.
- `toggles`: Each security layer can be disabled individually **at startup or live** via the Management API.

### Environment Variable Overrides

| Variable | Description |
|---|---|
| `AEGISEDGE_PORT` | Single port to add to the listen list |
| `AEGISEDGE_PORTS` | Comma-separated ports (e.g., `80,443,8080`) |
| `AEGISEDGE_TCP_PORTS` | Comma-separated raw TCP ports to L4-shield |
| `AEGISEDGE_UPSTREAM` | Override upstream address |
| `AEGISEDGE_L7_RATE_LIMIT` | Override token bucket rate (float req/sec) |
| `AEGISEDGE_L4_CONN_LIMIT` | Override L4 connection cap (int) |
| `AEGISEDGE_HOT_TAKEOVER` | Set `true` or `1` to enable |
| `AEGISEDGE_HYPERVISOR_MODE` | Set `true` or `1` to enable |
| `AEGISEDGE_SSL_CERT` | Path to TLS certificate |
| `AEGISEDGE_SSL_KEY` | Path to TLS private key |
| `AEGISEDGE_REDIS_ADDR` | Redis address for distributed state (e.g., `localhost:6379`) |
| `AEGISEDGE_REDIS_PASSWORD` | Redis password |
| `AEGISEDGE_SECRET` | HMAC secret for `ae_clearance` challenge cookies |

> [!NOTE]
> **GeoIP Support**: Download `GeoLite2-Country.mmdb` from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and place it in the project root. If the file is absent, the GeoIP filter degrades gracefully with a warning log.

> [!NOTE]
> **SSL**: Port `443` triggers automatic TLS. AegisEdge auto-discovers certificates from common system paths. Falls back to HTTP with a warning if no cert is found.

---

## 2. How the Browser Challenge Works

Every request that lacks a valid `ae_clearance` cookie is automatically gated — no opt-in required.

```
Request (no cookie)
    │
    ▼
AegisEdge serves 503 challenge page
    │
    ▼
Browser JS fires → redirects to ?ae_token=<timestamp.HMAC-SHA256>
    │
    ▼
Server verifies HMAC, sets HttpOnly ae_clearance cookie (1 hour TTL)
    │
    ▼
Clean redirect → request proceeds normally
```

Headless clients with no JS engine are permanently gated at the 503 step.

---

## 3. Simulating Attacks

```bash
go run cmd/stress_tool/main.go [flags]
```

| Flag | Default | Description |
|---|---|---|
| `-target` | `http://localhost:8080` | Target URL |
| `-n` | `100` | Total requests |
| `-c` | `10` | Parallel goroutines |
| `-mode` | `clean` | Test mode (see below) |

### Modes

| Mode | Payload Injected | Expected Response |
|---|---|---|
| `clean` | None | `200 OK` |
| `sqli` | `?id=1' OR '1'='1` | `400` — WAF SQLi |
| `xss` | `?q=<script>alert(1)</script>` | `400` — WAF XSS |
| `cmd` | `?exec=;cat /etc/passwd` | `400` — WAF CMDi |
| `traversal` | `/../../../etc/passwd` in path | `400` — WAF Path Traversal |
| `challenge` | No `ae_clearance` cookie | `503` — Browser Challenge gate |
| `bot` | No `User-Agent` header | `403` — Tarpit + L7 headless block |
| `flood` | Max-speed, 50 goroutines, 5 seconds | `429` — L7 Token Bucket shed |

> [!NOTE]
> Non-bot modes send real browser-like headers (`Accept`, `Accept-Language`, `Sec-Fetch-*`) so WAF tests don't false-positive on missing headers.

### Example Commands

```bash
# Baseline throughput
go run cmd/stress_tool/main.go -n 1000 -c 50

# WAF verification
go run cmd/stress_tool/main.go -mode sqli -n 100
go run cmd/stress_tool/main.go -mode xss -n 100
go run cmd/stress_tool/main.go -mode cmd -n 100
go run cmd/stress_tool/main.go -mode traversal -n 100

# Token bucket stress (ignores -n and -c, runs 5 seconds at max speed)
go run cmd/stress_tool/main.go -mode flood

# Headless bot detection
go run cmd/stress_tool/main.go -mode bot -n 50 -c 5
```

### Reading the Output
```
━━━ Throughput & Timing ━━━━━━━━━━━━━━━━━━━━━━━━━━
  Requests/sec:    12400
  Avg Latency:     ...

━━━ Latency Percentiles ━━━━━━━━━━━━━━━━━━━━━━━━━━
  p50 / p90 / p95 / p99

━━━ Mitigation Breakdown ━━━━━━━━━━━━━━━━━━━━━━━━━
  ✅  Legitimate (Allowed)                   :   890  (89.0%)
  ⏱️  Shed (L7 Token Bucket Rate Limiter)    :   100  (10.0%)
  🚫  Blocked (WAF: SQLi/XSS/CMDi/Traversal):    10   (1.0%)
```

---

## 4. Management API (Port `9091`)

### GET `/api/status` — Proxy Status & Active Blocks
```bash
curl http://localhost:9091/api/status
```
Returns active block list, **current toggle state**, and timestamp.

### POST `/api/block` — Block an IP
`duration` accepts Go duration strings (`"1h"`, `"30m"`, `"24h"`) or `"permanent"` (10-year hard block). Default if omitted: **24 hours**.
```bash
# Temporary block
curl -X POST http://localhost:9091/api/block \
     -H "Content-Type: application/json" \
     -d '{"ip": "1.2.3.4", "duration": "1h"}'

# Hard block
curl -X POST http://localhost:9091/api/block \
     -H "Content-Type: application/json" \
     -d '{"ip": "1.2.3.4", "duration": "permanent"}'
```

### DELETE `/api/block` — Unblock an IP
```bash
curl -X DELETE "http://localhost:9091/api/block?ip=1.2.3.4"
```

### PATCH `/api/config` — Toggle Features Live
Changes apply **immediately on the next request** — no restart required.
```bash
# Disable WAF, keep everything else
curl -X PATCH http://localhost:9091/api/config \
     -H "Content-Type: application/json" \
     -d '{"waf": false}'

# Enable anomaly detection, disable challenge
curl -X PATCH http://localhost:9091/api/config \
     -H "Content-Type: application/json" \
     -d '{"anomaly": true, "challenge": false}'
```

> [!NOTE]
> When `stats.IsUnderAttack()` is true (volumetric flood detected), the challenge is **force-enabled for all traffic** regardless of the `challenge` toggle, and clears automatically after 3 calm EMA windows.

---

## 5. Monitoring & Metrics (Port `9090`)

```bash
curl http://localhost:9090/metrics
```

| Metric | Labels | Description |
|---|---|---|
| `aegisedge_blocked_requests_total` | `layer`, `reason` | Blocked requests, by layer and reason |
| `aegisedge_active_connections` | — | Currently active proxied connections (gauge) |
| `aegisedge_request_duration_seconds` | `method`, `path` | Latency histogram for proxied requests |

**`reason` label values:** `rate_limit`, `no_user_agent`, `sqli`, `xss`, `cmd_injection`, `traversal`, `geoip`, `anomaly_heavy_url`, `low_entropy`, `fingerprint`, `stat_anomaly`, `active_block`, `blacklist`, `conn_limit`
