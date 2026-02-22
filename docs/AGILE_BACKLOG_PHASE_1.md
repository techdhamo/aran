# Agile Backlog — Phase 1

## Android C++ Core (Epic 1)

### User Story 1.1: Deep Frida / Hooking Detection

**As the** Aran C++ Native Core, I want to scan the application's memory map continuously, so that I can detect if dynamic instrumentation frameworks (like Frida) have injected malicious libraries.

- **AC 1:** Must parse `/proc/self/maps` at runtime.
- **AC 2:** Must detect patterns like `frida-agent.so` or `frida-gadget.so`.
- **AC 3:** Scan must complete in under **10ms**.

### User Story 1.2: Anti-Debugging (ptrace Blocking)

**As the** Aran C++ Native Core, I want to block external debuggers, so that reverse engineers cannot step through the application logic.

- **AC 1:** Invoke `ptrace(PTRACE_TRACEME, 0, 0, 0)` upon initialization.
- **AC 2:** Crash or alert if syscall returns -1.

## Mazhai Central Backend (Epic 2)

### User Story 2.1: High-Concurrency Telemetry Ingestion

**As the** Mazhai Central API, I want to utilize Java Virtual Threads to ingest threat payloads, so that the backend can handle 50,000+ simultaneous connections.

- **AC 1:** Use `Executors.newVirtualThreadPerTaskExecutor()`.
- **AC 2:** Endpoint `http://localhost:33100/api/v1/telemetry/ingest` must return 202 Accepted in under **30ms**.

### User Story 2.2: Real-Time eFRM Risk Scoring

**As the** Mazhai Central AI Worker, I want to calculate a real-time Risk Score (0-100), so that the client application knows whether to allow a high-value transaction.

- **AC 1:** If `is_rooted: true`, base score jumps to **90/100**.

## Domain & Package Standards

- **Domains:** mazhai.org, aran.mazhai.org
- **Package namespace:** `org.mazhai.central`

## Mazhai Port Range Standard

- **Mazhai/Aran ecosystem port range:** `33100-33199`
- **Mazhai Central (Phase 1) default port:** `33100`
