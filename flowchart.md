graph TD
    subgraph "AegisEdge Security Proxy Architecture"
        A["main.go<br>Entry Point"] --> B["Configuration<br>config.go"]
        A --> C["Logging<br>logger/logger.go"]
        A --> D["Storage<br>store/"]
        A --> E["Security Pipeline<br>Layered Middleware"]

        subgraph "Pipeline: Fast Rejection & L3/L4"
            E --> F["Fast-Reject Gate<br>filter/l3.go, filter/fastpath.go"]
            F --> G["Real IP Resolution<br>middleware/realip.go<br>util/proxywatcher.go"]
        end

        subgraph "Pipeline: L7 Security Layers"
            G --> H["Security Headers<br>middleware/security.go"]
            H --> I["Challenge/Verification<br>middleware/challenge.go"]
            I --> J["WAF<br>filter/waf.go"]
            J --> K["Rate Limiting<br>filter/l7.go"]
            K --> L["GeoIP Filtering<br>filter/geoip.go"]
            L --> M["Behavioral Fingerprinting<br>filter/fingerprint.go"]
            M --> N["Statistical Anomaly Detection<br>filter/statistical.go"]
            N --> O["Reputation Engine<br>filter/reputation.go"]
        end

        O --> P["Logging<br>middleware/logger.go"]
        O --> Q["Metrics<br>filter/metrics.go"]
        O --> R["Reverse Proxy<br>proxy.NewReverseProxy"]

        subgraph "Management & Operations"
            S["Management API<br>manager/api.go"] --> T["API Auth<br>manager/auth.go"]
            U["Trusted Proxy Discovery<br>util/proxywatcher.go"]
            V["Stream Proxying<br>filter/stream.go"]
            W["Port Takeover / OS Hardening<br>filter/orchestration_firewall.go"]
            X["External Notifications<br>notifier/webhook.go"]
        end

        subgraph "Testing & Tools (cmd/)"
            Y["demo_server/main.go"]
            Z["ping/main.go"]
            AA["stress_tool/main.go"]
        end

        subgraph "Supporting Modules"
            AB["settings/"]
            AC["store/"]
            AD["logger/"]
            AE["util/"]
        end

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
