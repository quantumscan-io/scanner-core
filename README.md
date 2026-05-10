# scanner-core

> Open-source post-quantum cryptography (PQC) vulnerability scanner core.
> MIT licensed · TypeScript · Reproducible builds · Privacy-first by design.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status: Active Development](https://img.shields.io/badge/status-active%20development-yellow.svg)](#roadmap)
[![DORA](https://img.shields.io/badge/compliance-DORA-purple.svg)](#compliance)
[![NIS2](https://img.shields.io/badge/compliance-NIS2-purple.svg)](#compliance)
[![NIST PQC](https://img.shields.io/badge/standard-NIST%20PQC-green.svg)](#compliance)

---

## What this is

`scanner-core` is the open-source detection engine behind [QuantumScan](https://quantumscan.io) — a service that helps engineering teams identify cryptography vulnerable to quantum computing attacks across their codebases.

The core scanner is released as MIT-licensed open source so that:

- **Customers can audit it.** Compliance teams (banks, fintechs, govtech) can read every line, fork it, and verify that the binary running in their CI matches the published source.
- **The scan can run client-side.** The same engine runs inside the user's GitHub Actions runner — source code never leaves the customer's infrastructure.
- **The community can extend it.** Detection patterns, language support, and PQC mapping rules evolve with public review and contribution.

The hosted SaaS, dashboard, dataset tooling, and customer-facing reports live in a separate (private) repository. This repository contains only the detection engine.

## What it detects

The scanner identifies cryptographic primitives that are either already broken or vulnerable to quantum-era attacks, across multiple programming languages.

| Severity | Examples |
|---|---|
| **CRITICAL** | TLS < 1.2, SSLv3, MD5, SHA1 (standalone), DES, 3DES, RC4, RSA < 2048 |
| **HIGH** (quantum-vulnerable) | RSA, ECDSA, ECDH, DSA, DH, NIST P-256/384/521, secp curves, Curve25519, X25519, Ed25519 |
| **MEDIUM** | AES-128 (Grover-weakened), OpenSSL < 1.1, deprecated crypto libraries |
| **LOW** | HMAC-SHA1, hardcoded keys in string literals |

For each finding, the engine maps a recommended **NIST PQC standardized alternative**:

- **ML-KEM** (FIPS 203) — key encapsulation
- **ML-DSA** (FIPS 204) — digital signatures
- **SLH-DSA** (FIPS 205) — hash-based signature fallback

## Languages supported (target)

TypeScript / JavaScript · Python · Go · Java · Kotlin · Swift · Rust · C / C++ · C# · Ruby · PHP

## Architecture (privacy-first)

The scanner is built around four layers, all of which are auditable:

1. **Client-side execution.** The scanner runs inside the user's CI runner via GitHub Actions. Source code never leaves their infrastructure. Only structured findings (file path, line number, algorithm) are returned to the dashboard.
2. **Memory-only fallback.** When server-side processing is unavoidable for a public repo demo, the code is held in RAM, scanned, and the container is destroyed. No disk write, no logs, no caches.
3. **Reproducible builds.** Every release has a SHA-256 hash. Anyone can compile from source and verify that the binary matches the one running in production.
4. **Audit log per access.** Every internal access generates a public audit entry visible to the customer.

A more detailed architectural document is published on the QuantumScan landing page under "Privacy by architecture".

## Roadmap

The project is in early active development. Initial release planned for **Q2 2026**.

- [ ] **v0.1** — Core regex engine, 50+ patterns, TS/JS support, CLI runner
- [ ] **v0.2** — Multi-language support (Python, Go, Java, Rust)
- [ ] **v0.3** — GitHub Actions integration (client-side scan, GitHub-native UX)
- [ ] **v0.4** — CycloneDX 1.7 CBOM output (audit-ready format)
- [ ] **v0.5** — DORA / NIS2 / ISO 27001 compliance mapping
- [ ] **v1.0** — Reproducible builds, SBOM publishing, security review

Detailed milestones and active issues live in the [GitHub Projects board](https://github.com/orgs/quantumscan-io/projects).

## Compliance

The scanner output is designed to be auditor-ready for the following frameworks:

- **DORA** (EU Digital Operational Resilience Act) — Article 50 cryptographic risk management
- **NIS2** (EU Network and Information Systems Directive)
- **NIST SP 800-208** / **NIST PQC standards** (FIPS 203/204/205)
- **BSI TR-02102** (German Federal Office for Information Security)
- **ISO 27001** Annex A.10 (cryptographic controls)
- **SOC 2** CC6.7 (encryption of data in transit and at rest)

## Sponsorship & funding

QuantumScan is in **Phase 1**: free for all design partners while we build a public LATAM crypto-inventory dataset. Each scan costs roughly **US$0.20** in Anthropic API fees.

If you find this tool useful and would like to help cover the API costs that keep scans free for the community, you can sponsor the project:

- **Open Collective:** [opencollective.com/quantumscan](https://opencollective.com/quantumscan) *(application pending fiscal host approval)*
- **GitHub Sponsors:** [github.com/sponsors/quantumscan-io](https://github.com/sponsors/quantumscan-io) *(coming soon)*

Every cent received is tracked publicly and converted to API credits within seven days. Monthly transparency reports are published on [quantumscan.io](https://quantumscan.io) showing: received from sponsors / converted to API credits / scans funded for the community.

## Contributing

Contributions, issues, and feature requests are welcome. The project is in early development — the most useful contributions right now are:

- Reporting false positives or missed patterns
- Adding language-specific detection rules
- Improving the PQC alternative mapping for your stack
- Reviewing the threat model and architecture

A `CONTRIBUTING.md` and code of conduct will be published alongside v0.1.

## License

[MIT](LICENSE) © 2026 QuantumScan contributors.

## Links

- **Website:** [quantumscan.io](https://quantumscan.io)
- **LinkedIn:** [linkedin.com/company/quantumscan](https://linkedin.com/company/quantumscan)
- **Org:** [github.com/quantumscan-io](https://github.com/quantumscan-io)
- **Privacy architecture:** detailed on the QuantumScan landing page
