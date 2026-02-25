AegisEdge (goshield) - Stakeholder QA Handbook
This document provides a technical and operational breakdown of AegisEdge, aimed at assisting SREs, System Admins, and decision-makers during evaluation or deployment.

🛠️ For SREs & System Administrators
Focus: Operability, Performance, and Troubleshooting

Q: What is the "Hot Takeover" feature and is it safe for production?
A: Hot Takeover allows AegisEdge to protect a port that is already in use (e.g., by Apache or Nginx) without stopping the original service. It uses iptables NAT redirection (PREROUTING) or Windows netsh portproxy to hijack traffic.

Safety Note: It is designed for emergency mitigation. For long-term production, we recommend the "Standard Deployment": binding AegisEdge directly to 80/443 and moving upstream services to backend ports.
Q: How does the system handle high-concurrency spikes?
A: AegisEdge is built in Go and utilizes a non-blocking architecture with Goroutines.

L4 Protection: Limits concurrent TCP connections per IP (configured via L4ConnLimit).
L7 Rate Limiting: Uses a Token Bucket algorithm (golang.org/x/time/rate) which allows for "burstiness" while maintaining a strict average rate.
Memory Safety: Stale IP limiters are automatically purged every 5 minutes to prevent unbounded memory growth.
Q: What happens if the Redis state store becomes unavailable?
A: AegisEdge features a Local Fallback mechanism. If AEGISEDGE_REDIS_ADDR is not reachable, the system defaults to in-memory state management. Once Redis is restored, you can restart the proxy to re-enable distributed state.

Q: Where can I find observability data?
A:

Metrics: A Prometheus metrics engine is active on port 9090 at /metrics. It tracks active connections, block counts per filter (L3, WAF, GeoIP), and request latency.
Logs: Structured JSON logs are sent to stdout. You can set the log level using the AEGISEDGE_LOG_LEVEL environment variable.
🛡️ For Security Engineers
Focus: Detection Logic, Threat Mitigation, and Hardening

Q: How does the WAF handle sophisticated SQLi or XSS?
A: The WAF uses high-performance regular expressions to scan Query Parameters, Path, and the first 4KB of POST/PUT bodies. It looks for tautologies (e.g., '1'='1'), union selects, event handlers (e.g., onerror=), and sensitive file paths (e.g., /etc/passwd).

Q: What is "Challenge Mode" and when does it trigger?
A: Challenge Mode is a progressive defense layer. It triggers automatically when:

Z-Score Anomaly: The statistical engine detects a traffic spike significantly above the 60-second moving average.
High Load: Concurrent connections exceed 200 (default).
Manual Toggle: Forced via the Management API.
It serves a JS-based challenge to differentiate between real browsers and simple scripts/bots.
Q: Does the system protect against Layer 4 DDoS like SYN floods?
A: Yes, but it does so at the Kernel Level. Upon startup, the 
HardenOS
 function optimizes Linux kernel parameters:

Enables TCP Syncookies (net.ipv4.tcp_syncookies=1).
Enables Reverse Path Filtering (rp_filter) to prevent IP spoofing.
Applies iptables rules to rate-limit ICMP (ping) traffic.
👔 For Managers & Decision Makers
Focus: Integration, Maintenance, and Business Value

Q: Can we adjust security postures without downtime?
A: Yes. AegisEdge includes a LiveToggles feature. Using the Management API (port 9091), you can enable/disable WAF, GeoIP blocking, or Challenge Mode in real-time. Changes take effect on the very next request without requiring a service restart.

Q: How does this reduce our "Blast Radius" during an attack?
A: By using Behavioral Fingerprinting and Reputation Management, the system isolates malicious actors without affecting legitimate users. If an IP is flagged, its rate limits are automatically tightened (multiplied by a penalty factor), while legitimate traffic continues at full speed.

Q: What are the maintenance requirements?
A: The "Zero-Dependency Core" means that in its basic form, it's a single binary with no external requirements other than the MaxMind GeoIP database file. Maintenance primarily involves updating the GeoIP database and monitoring the Prometheus dashboard for attack trends.