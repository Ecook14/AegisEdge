graph TD
    %% ================================
    %% Root Architecture
    %% ================================
    subgraph "AegisEdge Security Proxy Architecture"
        A["main.go<br><b>Entry Point</b>"] --> B["config.go<br><b>Configuration Loader</b>"]
        A --> C["logger/logger.go<br><b>Logger Init</b>"]
        A --> D["store/<br><b>State & Persistence</b>"]
        A --> E["<b>Security Pipeline</b><br>Layered Middleware"]
        %% ======================================
        %% PIPELINE: Fast Rejection (L3/L4)
        %% ======================================
        subgraph "Pipeline: Fast Rejection & L3/L4"
            E --> F["filter/l3.go, fastpath.go<br><b>Fast-Reject Gate</b>"]
            F --> G["middleware/realip.go<br>util/proxywatcher.go<br><b>Real IP Resolution</b>"]
        end
        %% ======================================
        %% PIPELINE: L7 Layers
        %% ======================================
        subgraph "Pipeline: L7 Security Layers"
            G --> H["middleware/security.go<br><b>Security Headers</b>"]
            H --> I["middleware/challenge.go<br><b>Challenge / Bot Verification</b>"]
            I --> J["filter/waf.go<br><b>WAF</b>"]
            J --> K["filter/l7.go<br><b>Rate Limiting</b>"]
            K --> L["filter/geoip.go<br><b>GeoIP Filtering</b>"]
            L --> M["filter/fingerprint.go<br><b>Behavioral Fingerprinting</b>"]
            M --> N["filter/statistical.go<br><b>Statistical Anomaly Detection</b>"]
            N --> O["filter/reputation.go<br><b>Reputation Engine</b>"]
        end
        %% ======================================
        %% Post-Pipeline Routing
        %% ======================================
        O --> P["middleware/logger.go<br><b>Request Logging</b>"]
        O --> Q["filter/metrics.go<br><b>Metrics Collection</b>"]
        O --> R["proxy.NewReverseProxy<br><b>Upstream Reverse Proxy</b>"]
        %% ======================================
        %% Management & Ops
        %% ======================================
        subgraph "Management & Operations"
            S["manager/api.go<br><b>Management API</b>"] --> T["manager/auth.go<br><b>API Auth</b>"]
            U["util/proxywatcher.go<br><b>Trusted Proxy Discovery</b>"]
            V["filter/stream.go<br><b>Stream Proxying</b>"]
            W["filter/orchestration_firewall.go<br><b>OS Hardening / Port Control</b>"]
            X["notifier/webhook.go<br><b>External Notifications</b>"]
        end
        %% ======================================
        %% Testing & Tools
        %% ======================================
        subgraph "Testing & Tools (cmd/)"
            Y["demo_server/main.go"]
            Z["ping/main.go"]
            AA["stress_tool/main.go"]
        end
        %% ======================================
        %% Supporting Modules
        %% ======================================
        subgraph "Supporting Modules"
            AB["settings/"]
            AC["store/"]
            AD["logger/"]
            AE["util/"]
        end
        %% Interconnections
        B -.-> E
        C -.-> P
        D -.-> O
        U -.-> G
        V -.-> R
        W -.-> F
        X -.-> N
        X -.-> O
        Q -.-> S
        S -.-> B
        S -.-> W
        Y -.-> R
        Z -.-> R
        AA -.-> J
        AA -.-> K
        AA -.-> M
        AB -.-> B
        AC -.-> D
        AD -.-> C
        AE -.-> U
    end
