# Vision & Strategy

## Aran Executive Manifesto

In an era where digital ecosystems are borderless, the traditional approach to cybersecurity—stitching together fragmented, siloed defenses—has fundamentally failed modern enterprises. Today’s threats do not respect the artificial boundaries between mobile endpoints, network edges, and cloud infrastructure; they exploit the seams between them.

Enter **Mazhai Technologies**, a visionary cybersecurity pioneer built on a profound philosophy of duality: the fluid, all-seeing, omnipresent intelligence of the cloud (**Mazhai**—The Rain) empowering an unbreakable, tactical, and deeply rooted edge defense (**Aran**—The Fortress).

Aran is not merely a product; it is a unified, 24-month enterprise-grade "Code-to-Cloud" security ecosystem engineered to render legacy patchwork solutions entirely obsolete. At its foundation, the Aran Mobile RASP embeds a hardened C++ JNI core directly into Android and iOS applications, neutralizing advanced reverse-engineering frameworks like Frida and Magisk from the inside out, while extending this exact protection to cross-platform hybrid apps via deep WebView hardening.

## Master PRD

### Target Audience & Buyer Personas

- **The CISO (Chief Information Security Officer):** Cares about risk reduction, compliance (RBI, DPDP, GDPR), and consolidating vendor sprawl.
- **The VP of Engineering / DevSecOps Lead:** Cares about CI/CD integration and SDK performance (latency/app size).
- **The Head of Fraud / Risk:** Cares about reducing financial losses from Account Takeovers (ATO).

### Core Ecosystem Tracks

1. **Aran Mobile RASP:** Detects advanced root/jailbreak (Magisk, Zygisk, KernelSU) and blocks dynamic instrumentation (Frida, Xposed).
2. **Mazhai Central & eFRM:** High-throughput ingestion pipeline using Java 21 Virtual Threads (Project Loom) and behavioral biometrics.
3. **Aran Cross-Platform Bridges:** Plug-and-play wrappers for Flutter, React Native, and Capacitor with WebView hardening.
4. **Aran Hardening & CI/CD:** O-LLVM obfuscation and automated build pipeline injection.
5. **Aran ASPM:** Application Security Posture Management correlating static code flaws with live runtime drops.
6. **Aran WAAP:** Next-gen edge proxy protecting microservices from BOLA/IDOR attacks.
7. **Aran Client-Side Defender:** WebAssembly sensors monitor the DOM in real-time to block Magecart/Skimming.
8. **Aran AI-Guard:** LLM Firewall to sanitize inputs and mask PII for GenAI integrations.

## Branding Duality (Mazhai / Aran)

This repository standardizes the ecosystem domains:

- **mazhai.org** (The Rain - Cloud Intelligence)
- **aran.mazhai.org** (The Fortress - Edge Defense)

All Java package namespaces are standardized under `org.mazhai`.
