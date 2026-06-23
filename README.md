# QuantumScan — scanner-core

> **Find quantum-vulnerable cryptography in your codebase — before it becomes a compliance problem.**

[![Live Stats](https://img.shields.io/badge/live%20stats-STATS.md-blue)](./STATS.md)
[![Website](https://img.shields.io/badge/web-quantumscan.io-0ea5e9)](https://quantumscan.io)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

QuantumScan detects classical cryptographic algorithms (RSA, ECDSA, AES-128, SHA-1…) that are vulnerable to quantum computers and maps them to their post-quantum replacements from [NIST FIPS 203/204/205](https://csrc.nist.gov/publications/detail/fips/203/final).

## Quick Start

```bash
# Scan any public GitHub repo — free, no login required
curl -X POST https://quantumscan.io/api/scan \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","repoUrl":"https://github.com/owner/repo"}'
```

Or use the web UI at **[quantumscan.io](https://quantumscan.io)** — paste a repo URL and get a full risk report in seconds.

## What gets detected

| Severity | Examples |
|---|---|
| CRITICAL | MD5, SHA-1, DES, SSLv3/TLS<1.2 |
| HIGH | RSA, ECDSA, ECDH, DSA (all quantum-broken) |
| MEDIUM | AES-128 (needs upgrade to AES-256) |
| LOW | HMAC-SHA1, hardcoded key literals |

Most recently detected in the wild: **`ECDSA`** — appearing in 515 scans.

→ See [STATS.md](./STATS.md) for live numbers updated every 24h.

## Why post-quantum now?

NIST finalized **ML-KEM** (key encapsulation) and **ML-DSA** (signatures) in August 2024. DORA, NIS2, and ISO 27001:2022 compliance frameworks are already referencing PQC readiness. The migration window is 3–7 years — planning starts today.

## PQC replacements

| Classical | Quantum replacement |
|---|---|
| RSA / ECDSA | ML-DSA (FIPS 204) |
| ECDH / DH | ML-KEM (FIPS 203) |
| SHA-1 | SHA-3 / SHA-256+ |
| AES-128 | AES-256 |

## Contributing

Open issues for new patterns you'd like detected. PRs welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md) if it exists, or just open a PR with:
1. The regex pattern
2. Which algorithm it targets
3. Severity (critical/high/medium/low)
4. A PQC alternative

The [inbound-pr-agent](https://quantumscan.io) reviews PRs daily and will respond within 24h.

---

*Stats auto-updated: 2026-06-23 17:03 UTC | [quantumscan.io](https://quantumscan.io)*
