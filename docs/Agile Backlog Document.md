# Agile Backlog — Phase 1 (Iron Core)

## Epic 1: Android C++ Core (Weeks 1-4)

# 

**Goal:** Build the C++ JNI sensor for environment integrity.

### User Stories & Acceptance Criteria

# 

*   **Story 1.1: Frida Detection**
    
    *   _AC:_ Parse `/proc/self/maps` via C++.
        
    *   _AC:_ Detect `frida-agent.so` or `frida-gadget.so`.
        
    *   _AC:_ Execution time < 10ms.
        
*   **Story 1.2: Anti-Debugging**
    
    *   _AC:_ Implement `ptrace(PTRACE_TRACEME)`.
        
    *   _AC:_ Crash or notify on `-1` return code.
        
*   **Story 1.3: Root Integrity**
    
    *   _AC:_ Check for `su` binaries and Magisk hidden directories.
        

## Epic 2: Mazhai Central (Weeks 1-4)

# 

**Goal:** High-concurrency ingestion and telemetry backbone.

### User Stories & Acceptance Criteria

# 

*   **Story 2.1: Telemetry Ingest**
    
    *   _AC:_ POST `/api/v1/telemetry/ingest` accepts `TelemetryPayload`.
        
    *   _AC:_ Endpoint runs on Mazhai Standard Port **33100**.
        
    *   _AC:_ Must log `isVirtual() == true` for Loom verification.
        
    *   _AC:_ Respond with 202 Accepted in < 30ms.
        

## Epic 3: Infrastructure & Automation

# 

**Goal:** Setup unique networking and CI/CD.

### Standards

# 

*   **Domains:** mazhai.org, aran.mazhai.org
    
*   **Package namespace:** `org.mazhai`
    
*   **Mazhai Port Range:** `33100 - 33199` (Central Ingestion: 33100)
    

### User Stories

# 

*   **Story 3.1: Jenkins Pipeline**
    
    *   _AC:_ Root `Jenkinsfile` executes builds and tests on every commit.