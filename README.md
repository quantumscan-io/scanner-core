# scanner-core

> Open-source post-quantum cryptography (PQC) vulnerability scanner.
> MIT licensed · JavaScript (ESM) · Privacy-first by design.

[![CI](https://github.com/quantumscan-io/scanner-core/actions/workflows/ci.yml/badge.svg)](https://github.com/quantumscan-io/scanner-core/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/badge/npm-quantumscan-red.svg)](https://www.npmjs.com/package/quantumscan)
[![DORA](https://img.shields.io/badge/compliance-DORA-purple.svg)](#compliance)
[![NIS2](https://img.shields.io/badge/compliance-NIS2-purple.svg)](#compliance)
[![NIST PQC](https://img.shields.io/badge/standard-NIST%20PQC-green.svg)](#compliance)

---

## Quick start

No install required. Run directly with npx:

```bash
npx quantumscan .
npx quantumscan ./src
npx quantumscan . --json
npx quantumscan . --no-fail
```

Example output:

```
QuantumScan v1.0.0  Post-Quantum Cryptography Scanner
https://quantumscan.io
──────────────────────────────────────────────────────────
Path     /your/project
Files    312 total · 87 scannable

🔴 CRITICAL   3 findings
  auth/session.js:14      MD5        `md5(`
  lib/crypto.js:88        AES-ECB    `AES/ECB/`
  config/tls.js:5         TLS 1.0    `TLSv1.0`

🟠 HIGH        5 findings
  auth/jwt.js:22          RSA        `RSA.generate(`
  lib/keys.js:41          ECDSA      `ECDSA`
  ...

──────────────────────────────────────────────────────────
Risk Score  68/100  High Risk

Migrate to: ML-KEM (FIPS 203) · ML-DSA (FIPS 204)
Required by NIST, DORA, NIS2, CNSA 2.0 — deadline 2030.

Full AI analysis + migration guides → https://quantumscan.io
```

## Add a badge to your repo

Show your quantum-safety score directly in your README:

```markdown
![QuantumScan](https://quantumscan.io/api/badge/YOUR_USERNAME/YOUR_REPO.svg)
```

Example:
```markdown
[![QuantumScan](https://quantumscan.io/api/badge/openssl/openssl.svg)](https://quantumscan.io)
```

---

## What this is

`scanner-core` is the open-source detection engine behind [QuantumScan](https://quantumscan.io).

The core scanner is released as MIT-licensed open source so that:

- **Customers can audit it.** Compliance teams (banks, fintechs, govtech) can read every line, fork it, and verify that the binary running in their CI matches the published source.
- **The scan can run client-side.** The same engine runs inside the user's GitHub Actions runner — source code never leaves the customer's infrastructure.
- **The community can extend it.** Detection patterns, language support, and PQC mapping rules evolve with public review and contribution.

The hosted SaaS, dashboard, and customer-facing reports live in a separate (private) repository. This repository contains only the detection engine.

## What it detects

| Severity | Examples |
|---|---|
| **CRITICAL** | TLS < 1.2, SSLv3, MD5, SHA1, DES, 3DES, RC4, RSA < 2048 |
| **HIGH** (quantum-vulnerable) | RSA, ECDSA, ECDH, DSA, DH, NIST P-256/384/521, secp curves, Curve25519, X25519, Ed25519 |
| **MEDIUM** | AES-128, OpenSSL < 1.1, CBC mode |
| **LOW** | HMAC-SHA1, hardcoded keys in string literals |

For each finding, the engine maps a recommended NIST PQC standardized alternative:

- **ML-KEM** (FIPS 203) — key encapsulation
- **ML-DSA** (FIPS 204) — digital signatures
- **SLH-DSA** (FIPS 205) — hash-based signature fallback

## Languages supported

TypeScript / JavaScript · Python · Go · Java · Kotlin · Swift · Rust · C / C++ · C# / .NET · Ruby · PHP

## Roadmap

- [x] **v1.0** — Core regex engine, 50+ patterns, multi-language support, `npx quantumscan` CLI — **LIVE**
- [x] **SaaS** — full dashboard, drift detection, DORA/NIS2 PDF reports — **LIVE at quantumscan.io**
- [x] **GitHub PR Bot** — automatic PQC scan on every pull request — **submitted to GitHub Marketplace**
- [x] **Multi-platform** — GitHub + GitLab + Bitbucket + ZIP upload
- [x] **CBOM export** — CycloneDX 1.7 format
- [x] **BYOK** — Bring Your Own Anthropic/OpenAI/Gemini key
- [x] **.NET / C# detection** — `System.Security.Cryptography` + BouncyCastle.NET — community contribution
- [ ] **v1.1** — GitHub Actions client-side scan (code never leaves your infra)
- [ ] **v1.2** — SBOM publishing + reproducible builds
- [ ] **v1.3** — DORA / NIS2 / ISO 27001 compliance mapping per finding + LATAM (LGPD, BACEN)

Contributions wanted:

- Language patterns: Go (`crypto/rsa`, `x/crypto`), Java (Bouncy Castle, `javax.crypto`)
- LATAM compliance mappings: BACEN 4.658, LGPD Art. 46, SFC Colombia, CNBV Mexico

Open an issue with label `language-patterns` or `compliance-mapping` to start.

## Contributors

Thanks to everyone who has contributed code or patterns to scanner-core:

- [@ChisaTocris](https://github.com/ChisaTocris) — .NET / C# detection patterns + BouncyCastle.NET

## Compliance

- **DORA** — Article 50 cryptographic risk management
- **NIS2** — EU Network and Information Systems Directive
- **NIST PQC** — FIPS 203/204/205
- **ISO 27001** — Annex A.10 (cryptographic controls)
- **SOC 2** — CC6.7

## Contributing

Contributions, issues, and feature requests are welcome. Most useful right now:

- Reporting false positives or missed patterns
- Adding language-specific detection rules
- Reviewing the threat model and architecture

## License

[MIT](LICENSE) © 2026 QuantumScan contributors.

## Links

- **Website:** [quantumscan.io](https://quantumscan.io)
- **Ko-fi:** [ko-fi.com/quantumscan](https://ko-fi.com/quantumscan)
- **LinkedIn:** [linkedin.com/company/quantumscan](https://linkedin.com/company/quantumscan)
- **Org:** [github.com/quantumscan-io](https://github.com/quantumscan-io)
