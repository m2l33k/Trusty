# BlockGuard — Process-Based File Access Security Agent

## Architecture Overview

> [!IMPORTANT]
> This document describes the design of **BlockGuard**, a Windows process-based DLP agent built in C# (.NET 8) that protects sensitive files by gating access based on the calling process identity.

---

## 1. Threat Model

| Threat | Mitigation |
|---|---|
| Unauthorized process reads a protected file | ACL enforcement + ETW real-time monitoring |
| Attacker renames a trusted process to bypass policy | Authenticode signature verification + PE hash validation |
| Memory injection into a trusted process | Parent process chain validation + integrity level checks |
| DPAPI key theft via process impersonation | Strict SID + session ID comparison before decryption |
| Tampering with the agent's own config | Config file protected by DPAPI + signature validation |

---

## 2. Architecture Layers

```mermaid
graph TD
    subgraph "Layer 1: Monitoring & Interception"
        ETW["ETW File Trace Provider"]
        FSW["FileSystemWatcher (Backup)"]
        ACL["ACL Enforcement Engine"]
    end

    subgraph "Layer 2: Policy & Identity Engine"
        PE["Process Identity Validator"]
        POL["Policy Evaluator"]
        CACHE["Identity Cache"]
    end

    subgraph "Layer 3: Decryption & Handle Manager"
        DPAPI["DPAPI Wrapper"]
        HM["Secure Handle Manager"]
        AUDIT["Audit Logger"]
    end

    ETW --> PE
    FSW --> PE
    PE --> CACHE
    PE --> POL
    POL -->|Authorized| HM
    POL -->|Denied| AUDIT
    HM --> DPAPI
    HM --> ACL
    AUDIT --> AUDIT
```

### Layer 1 — Monitoring & Interception (Real-Time Detection)
- **ETW (Event Tracing for Windows)**: Subscribes to `Microsoft-Windows-Kernel-File` provider for real-time file I/O events (Create, Read, Write, Delete). This gives us process ID, file path, and operation type with *minimal* performance overhead.
- **ACL Enforcement**: At startup, the agent strips `GENERIC_READ` from all non-authorized SIDs on protected files. This is the *hard enforcement* — even if ETW misses an event, the OS kernel enforces the ACL.
- **FileSystemWatcher (Backup)**: Secondary detection for file renames, deletions, or attribute changes that might indicate tampering.

### Layer 2 — Policy & Identity Engine (Decision)
- **Process Identity Validator**: Given a PID from ETW, validates the process via:
  1. Executable path (full canonical path)
  2. Authenticode digital signature verification
  3. PE file hash (SHA-256)
  4. Parent process chain (up to 3 levels)
  5. Process integrity level (must be ≥ Medium)
- **Policy Evaluator**: Matches the validated identity against the policy configuration.
- **Identity Cache**: LRU cache (configurable TTL) to avoid repeated expensive crypto operations for the same process.

### Layer 3 — Decryption & Handle Manager (Response)
- **DPAPI Wrapper**: Uses Windows DPAPI (`CryptProtectData`/`CryptUnprotectData`) to encrypt/decrypt protected file content at rest. Scoped to machine or user.
- **Secure Handle Manager**: When an authorized process is confirmed, temporarily grants a restricted file handle with *read-only* access and revokes it after a configurable timeout.
- **Audit Logger**: Structured JSON logging of all access attempts (authorized and denied) with full process context.

---

## 3. Project Structure

```
BlockGuard/
├── src/
│   ├── BlockGuard.Core/           # Shared models, interfaces, configuration
│   │   ├── Models/
│   │   ├── Interfaces/
│   │   └── Configuration/
│   ├── BlockGuard.Monitoring/     # Layer 1: ETW + FSW + ACL
│   │   ├── EtwFileTraceSession.cs
│   │   ├── FileSystemMonitor.cs
│   │   └── AclEnforcer.cs
│   ├── BlockGuard.Policy/         # Layer 2: Identity + Policy
│   │   ├── ProcessIdentityValidator.cs
│   │   ├── PolicyEvaluator.cs
│   │   └── IdentityCache.cs
│   ├── BlockGuard.Protection/     # Layer 3: DPAPI + Handles + Audit
│   │   ├── DpapiWrapper.cs
│   │   ├── SecureHandleManager.cs
│   │   └── AuditLogger.cs
│   └── BlockGuard.Agent/          # Windows Service entry point
│       ├── Program.cs
│       └── BlockGuardService.cs
└── tests/
    ├── BlockGuard.Core.Tests/
    ├── BlockGuard.Policy.Tests/
    └── BlockGuard.Integration.Tests/
```

---

## 4. Technology Choices

| Component | Technology | Why |
|---|---|---|
| Runtime | .NET 8 (LTS) | Native Windows interop, AOT support, modern C# features |
| ETW Consumer | `Microsoft.Diagnostics.Tracing.TraceEvent` | Best-in-class managed ETW library |
| Authenticode | `System.Security.Cryptography.Pkcs` + P/Invoke | Kernel32 `WinVerifyTrust` for real chain validation |
| DPAPI | P/Invoke to `Crypt32.dll` | Native Windows data protection, no key management |
| ACL Management | `System.Security.AccessControl` | Built-in .NET ACL manipulation |
| Hosting | `Microsoft.Extensions.Hosting.WindowsServices` | Production-grade Windows Service with DI |
| Logging | `Serilog` → JSON files + Windows Event Log | Structured, auditable logging |
| Configuration | `appsettings.json` + DPAPI-encrypted secrets | Standard .NET config with encrypted overlays |

---

## 5. Security Warnings

> [!CAUTION]
> **No Kernel-Mode Component**: This agent operates entirely in user-mode. It **cannot** block a file read *in-flight* like a minifilter driver. Instead, it uses **preventive ACL lockdown** (deny-by-default) combined with **detective ETW monitoring**. For true kernel-level interception, a certified minifilter driver is required — which needs WHQL signing and can cause BSOD if implemented incorrectly.

> [!WARNING]
> **Admin Privileges Required**: The agent must run as `NT AUTHORITY\SYSTEM` or an administrator account to:
> - Modify file ACLs on protected resources
> - Start ETW kernel trace sessions
> - Query process information for arbitrary PIDs
> Running with lower privileges will cause silent failures in enforcement.
