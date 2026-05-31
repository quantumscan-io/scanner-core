# scanner-core

> Open-source post-quantum cryptography (PQC) vulnerability scanner.
> MIT licensed · JavaScript (ESM) · Privacy-first by design.

[![CI](https://github.com/quantumscan-io/scanner-core/actions/workflows/ci.yml/badge.svg)](https://github.com/quantumscan-io/scanner-core/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/badge/npm-quantumscan-red.svg)](https://www.npmjs.com/package/quantumscan)
[![DORA](https://img.shields.io/badge/compliance-DORA-purple.svg)](#compliance)
[![NIS2](https://img.shields.io/badge/compliance-NIS2-purple.svg)](#compliance)
[![NIST PQC](https://img.shields.io/badge/standard-NIST%20PQC-green.svg)](#compliance)
[![Stars](https://img.shields.io/github/stars/quantumscan-io/scanner-core?style=social)](https://github.com/quantumscan-io/scanner-core/stargazers)

> **Help us reach 1,000 ⭐** — every star helps scanner-core get listed in security awesome-lists and reach more developers before Q-day.

---

## Quick start

No install required. Run directly with npx:

```bash
npx quantumscan .               # scan current directory
npx quantumscan ./src           # scan specific path
npx quantumscan . --json        # JSON output for CI/CD
npx quantumscan . --badge       # print README badge markdown
npx quantumscan . --no-fail     # exit 0 even with findings
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

Show your quantum-safety score directly in your README. The badge auto-updates every time you run a cloud scan at [quantumscan.io](https://quantumscan.io).

**Option 1 — Auto-generate from CLI (detects your GitHub remote):**

```bash
npx quantumscan . --badge
```

Outputs:
```
README badge (add to your README.md):
[![QuantumScan](https://quantumscan.io/api/badge/owner/repo.svg)](https://quantumscan.io/en/scan)
```

**Option 2 — Manually:**

```markdown
[![QuantumScan](https://quantumscan.io/api/badge/YOUR_USERNAME/YOUR_REPO.svg)](https://quantumscan.io)
```

---

## Real-world scans — 2026-05-29 batch

Scanned 30 public repos today across GitHub, GitLab, Bitbucket, and ZIP uploads:

| Repository | Platform | Risk Score | Key Finding |
|---|---|---|---|
| [tlsfuzzer/python-ecdsa](https://quantumscan.io/en/share/b8debd2c-8af8-4052-ab24-134fe4b348a8) | GitHub | **95/100** | 171 ECDSA patterns · 9 critical SHA-1 usages |
| [bitcoin/bitcoin](https://quantumscan.io/en/share/12c86aea-2652-455f-ae23-958cd92fc714) | GitHub | **89/100** | secp256k1 ECDSA in every transaction |
| [bcgit/bc-java](https://quantumscan.io/en/share/17ba30c8-d148-4f89-bcdd-8fbdc9fee588) | GitHub | **78/100** | #1 Java crypto library |
| [gnutls/gnutls](https://quantumscan.io/en/share/ef777d8a-eeae-4870-bf04-c4688e4e7804) | GitLab | **78/100** | Linux TLS stack |
| [hashicorp/vault](https://quantumscan.io/en/share/6184cf79-9dfa-4556-b524-e4789382bced) | GitHub | **73/100** | Enterprise secrets manager |
| [jpadilla/pyjwt](https://quantumscan.io/en/share/740a40df-fd8e-4700-befb-a422b3b1e69e) | GitHub | **72/100** | 36M+ PyPI downloads/month |
| [oscrypto](https://quantumscan.io/en/share/065d3505-e0ca-4e8b-9fcd-99a672e2f4fa) | ZIP | **72/100** | OS crypto bindings |
| [paragonie/halite](https://quantumscan.io/en/share/0477e2a0-6a41-45e7-9c9b-37fc711b1295) | GitHub | 72/100 | PHP high-level crypto |
| [curl/curl](https://quantumscan.io/en/share/8ac0abfb-e26d-4988-843b-5a6a0e5a776a) | GitHub | 12/100 | Mostly clean |
| spring-projects/spring-security | GitHub | 8/100 | Low exposure |
| inkscape/inkscape | GitLab | 8/100 | Low exposure |
| libvirt/libvirt · dolfin (Bitbucket) | GitLab/BB | 0/100 | Clean |

→ [Full leaderboard: quantumscan.io/leaderboard](https://quantumscan.io/leaderboard)

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
