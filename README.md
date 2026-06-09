# scanner-core

[![CI](https://github.com/quantumscan-io/scanner-core/actions/workflows/ci.yml/badge.svg)](https://github.com/quantumscan-io/scanner-core/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/quantumscan.svg)](https://www.npmjs.com/package/quantumscan)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/quantumscan-io/scanner-core?style=social)](https://github.com/quantumscan-io/scanner-core/stargazers)

**Open-source CLI that finds quantum-vulnerable cryptography in your codebase.**

RSA, ECDSA, DH, SHA-1, DES — algorithms that a large-enough quantum computer breaks in hours. NIST, DORA and NIS2 mandate migration by 2030. This tool tells you where you stand today.

```bash
npx quantumscan .
```

No install. No account. No code leaves your machine. MIT licensed.

---

## What it finds

We scanned some of the most-used crypto libraries in the world:

| Repository | Risk Score | Key Finding |
|---|---|---|
| [tlsfuzzer/python-ecdsa](https://quantumscan.io/en/share/b8debd2c-8af8-4052-ab24-134fe4b348a8) | **95/100** | 171 ECDSA patterns — a library built entirely on an algorithm Shor's can break |
| [bitcoin/bitcoin](https://quantumscan.io/en/share/12c86aea-2652-455f-ae23-958cd92fc714) | **89/100** | secp256k1 ECDSA in every transaction |
| [bcgit/bc-java](https://quantumscan.io/en/share/17ba30c8-d148-4f89-bcdd-8fbdc9fee588) | **78/100** | #1 Java crypto library — RSA and ECDSA throughout |
| [hashicorp/vault](https://quantumscan.io/en/share/6184cf79-9dfa-4556-b524-e4789382bced) | **73/100** | Enterprise secrets manager using secp256k1 |
| [jpadilla/pyjwt](https://quantumscan.io/en/share/740a40df-fd8e-4700-befb-a422b3b1e69e) | **72/100** | 36M+ PyPI downloads/month — RS256/ES256 default |
| curl/curl | **12/100** | Mostly clean — good reference |

→ [Full leaderboard](https://quantumscan.io/leaderboard)

---

## Quick start

```bash
# Scan the current directory
npx quantumscan .

# Scan a specific path
npx quantumscan ./src

# JSON output for CI/CD pipelines
npx quantumscan . --json

# SARIF output for GitHub Security tab
npx quantumscan . --sarif > results.sarif

# Print a README badge for your repo
npx quantumscan . --badge

# Skip dependency scanning
npx quantumscan . --no-deps
```

Example output:

```
QuantumScan v1.3.0  Post-Quantum Cryptography Scanner
──────────────────────────────────────────────────────────
Path     /your/project
Files    312 total · 87 scannable

🔴 CRITICAL   2 findings
  config/tls.js:5         TLS 1.0    TLSv1.0
  auth/session.js:14      MD5        md5(

🟠 HIGH        4 findings
  auth/jwt.js:22          RSA        RSA.generate(
  lib/keys.js:41          ECDSA      ECDSA

──────────────────────────────────────────────────────────
Risk Score  68/100  High Risk

Migrate to: ML-KEM (FIPS 203) · ML-DSA (FIPS 204)
Required by NIST, DORA, NIS2, CNSA 2.0 — deadline 2030.

Full AI analysis + migration guides → https://quantumscan.io

If this was useful → ⭐ github.com/quantumscan-io/scanner-core
```

---

## What it detects

| Severity | Algorithms |
|---|---|
| **CRITICAL** | TLS < 1.2, SSLv3, MD5, SHA-1, DES, 3DES, RC4, AES-ECB, RSA ≤ 2048-bit |
| **HIGH** | RSA, ECDSA, ECDH, DSA, DH, P-256/384/521, secp256k1, Ed25519, X25519 |
| **HIGH** | Blockchain: ethers.js Wallet, web3.js accounts, bitcoinjs-lib ECPair, Solana Keypair, BIP32/HD wallets |
| **MEDIUM** | AES-128, CBC mode, HMAC-SHA1, PBKDF2 low iterations, Math.random in crypto |
| **LOW** | Hardcoded keys, CRC32 for integrity, SHA-256 as KDF |

For each finding the engine maps a NIST PQC replacement:
- **ML-KEM** (FIPS 203) — key encapsulation
- **ML-DSA** (FIPS 204) — digital signatures  
- **SLH-DSA** (FIPS 205) — hash-based signature fallback

---

## Languages

TypeScript · JavaScript · Python · Go · Java · Kotlin · Swift · Rust · C · C++ · C# / .NET · Ruby · PHP · Solidity

---

## Dependency scanning

Scans package manifests for crypto libraries that are quantum-vulnerable:

```
📦 DEPENDENCIES  2 vulnerable package(s)
  package.json    elliptic     Elliptic curve crypto (secp256k1, P-256)
                    → ml-kem / ml-dsa
  requirements.txt  ecdsa==0.19.0  Pure ECDSA
                    → pqcrypto (dilithium)
```

Supported: `package.json` · `requirements.txt` · `go.mod` · `Cargo.toml` · `pom.xml`

---

## GitHub Actions integration

```yaml
- name: Scan for quantum-vulnerable crypto
  run: npx quantumscan . --sarif --no-fail > results.sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Findings appear under **Security → Code scanning** after the workflow runs.

---

## Suppressing false positives

```python
REJECTED_ALGO = "RS256"  # quantumscan-ignore

# quantumscan-ignore
legacy_hash = hashlib.sha1(nonce)  # test vector only
```

Works in all supported languages. Suppresses the specific line, not the whole file.

---

## Add a badge to your README

```bash
npx quantumscan . --badge
```

Outputs ready-to-paste Markdown. The badge auto-updates on every cloud scan at [quantumscan.io](https://quantumscan.io).

---

## Architecture

`scanner-core` is the detection engine behind [quantumscan.io](https://quantumscan.io). Released as MIT so that:

- **You can audit every line.** No trust required — the engine is the same one running in our CI.
- **Scans stay local.** The same binary runs inside your GitHub Actions runner. Source code never leaves your infra.
- **The community extends it.** Detection patterns, language support, and PQC mappings evolve with public contribution.

The hosted SaaS (AI migration guides, CBOM CycloneDX export, DORA/NIS2 PDF reports, drift detection) lives in a separate private repo.

---

## Contributing

Most useful right now:

- **Go patterns** — `crypto/rsa`, `x/crypto`, `golang.org/x/crypto` (`good first issue` label)
- **Java patterns** — Bouncy Castle, `javax.crypto`
- **LATAM compliance mappings** — BACEN 4.658, LGPD Art. 46, SFC Colombia, CNBV Mexico
- **False positive reports** — run the scanner on your codebase and tell us what's wrong

Open an issue with label `language-patterns` or `compliance-mapping`.

```bash
git clone https://github.com/quantumscan-io/scanner-core.git
cd scanner-core
node index.js /path/to/your/project
```

---

## Contributors

- [@ChisaTocris](https://github.com/ChisaTocris) — C# / .NET patterns: `System.Security.Cryptography` + BouncyCastle.NET

---

## Roadmap

- [x] v1.0 — Core regex engine, 50+ patterns, 12 languages, `npx quantumscan` CLI
- [x] v1.1 — Dependency scanning (npm, pip, Go, Rust, Maven)
- [x] v1.2 — SARIF output, `quantumscan-ignore`, `--badge` flag, blockchain patterns (Web3/DeFi)
- [x] v1.3 — OpenSSL C / Java JCA implementation patterns, coverage disclosure, README.rst support, .NET community contribution
- [ ] v1.4 — GitHub Actions client-side scan (code never leaves infra)
- [ ] v1.5 — SBOM publishing + reproducible builds
- [ ] v2.0 — WASM browser build (zero-server scan from the landing page)

---

## Compliance mapping

| Standard | Requirement |
|---|---|
| **NIST FIPS 203/204/205** | Use ML-KEM / ML-DSA / SLH-DSA |
| **DORA** Art. 50 | Cryptographic risk management for financial entities |
| **NIS2** Art. 21 | Cryptographic controls for critical infrastructure |
| **CNSA 2.0** | US NSA mandate — full PQC by 2030 |
| **ISO 27001** | Annex A.10 cryptographic controls |
| **SOC 2** | CC6.7 encryption requirements |

---

## License

[MIT](LICENSE) © 2026 QuantumScan contributors

---

## Links

- **SaaS (AI guides, CBOM, DORA PDF):** [quantumscan.io](https://quantumscan.io)
- **npm:** [npmjs.com/package/quantumscan](https://www.npmjs.com/package/quantumscan)
- **Ko-fi:** [ko-fi.com/quantumscan](https://ko-fi.com/quantumscan)
- **LinkedIn:** [linkedin.com/company/quantumscan](https://linkedin.com/company/quantumscan)
