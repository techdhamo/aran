# Technical Architecture — Aran Ecosystem

## System Architecture Document (SAD)

### The Code-to-Cloud Flow

# 

The Aran ecosystem operates on a zero-trust, continuous telemetry loop:

1.  **The Edge Sensor (Mobile/Browser):** The Aran RASP (C++/Wasm) detects a threat locally (e.g., Magisk hide or DOM tampering).
    
2.  **The Edge Proxy (WAAP):** The telemetry payload hits the Aran WAAP (Go/Rust). The WAAP inspects the payload and forwards traffic.
    
3.  **The Brain (Mazhai Central):** The Java 21 Spring Boot backend ingests the payload via gRPC/REST. Virtual Threads push data to Kafka.
    
4.  **The eFRM Engine:** Kafka streams data to AI workers calculating a real-time `FraudRiskScore` based on behavioral biometrics.
    
5.  **The Observability Fusion (ASPM):** Scored events are logged in TimescaleDB and pushed to Dynatrace/AppDynamics APIs.
    

### Java 21 / Loom Ingestion Layer

# 

*   **Ingestion Service:** `mazhai-central`
    
*   **Concurrency:** Utilizing Project Loom (Virtual Threads) to handle 50,000+ concurrent SDK heartbeat requests per node.
    
*   **Configuration:** `spring.threads.virtual.enabled: true`
    

### C++ JNI RASP Layer

# 

*   **Native Core:** Hardened C++ core executing low-level `syscalls`.
    
*   **Integrity Checks:** Scans `/proc/self/maps` for Frida, checks Mach-O encryption (iOS), and utilizes `ptrace` blocking.
    
*   **JNI Bridge:** Kotlin/Swift interface using White-Box Cryptography to encrypt payloads before transmission.
    
*   **Obfuscation:** Protected by O-LLVM Control Flow Flattening.
    

### Database Architecture

# 

*   **TimescaleDB:** Optimized for hyper-fast time-series inserts of threat logs.
    
*   **PostgreSQL:** Stores relational metadata (Tenants, Policies, User IDs).