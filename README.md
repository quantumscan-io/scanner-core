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

## Substrate / Polkadot

Use `--substrate` to enable 19 Substrate-specific PQC patterns covering BABE/GRANDPA consensus keys, custom pallet crypto, XCM signing, and ink! smart contracts.

```bash
npx quantumscan ./my-parachain --substrate
```

**What gets detected with `--substrate`:**

| Pattern group | Covered APIs |
|---|---|
| BABE/GRANDPA keys | `BabeId`, `GrandpaId`, `sr25519::Pair`, `ed25519::Pair`, `impl_opaque_keys!`, `LocalKeystore::open`, `KeystorePtr` |
| Pallet crypto | `sp_runtime::traits::Verify`, `MultiSignature`, `sp_core::sr25519/ed25519`, `sp_io::crypto::*` |
| XCM signing | `OriginKind::SovereignAccount`, `xcm::prelude::*`, `Junction::AccountId32`, `xcm_executor::XcmExecutor` |
| ink! contracts | `ink::env::ecdsa_recover`, `ink::env::sr25519_verify`, `self.env().caller()` |
| Rust crates | `schnorrkel`, `ed25519-dalek`, `x25519-dalek`, `libp2p-noise` |

**Example output:**

```
QuantumScan v1.9.0  Substrate/Polkadot PQC Analysis
──────────────────────────────────────────────────────────
Workspace  Substrate/Polkadot detected
Pallets    3 found (pallets/staking, pallets/identity, pallets/session)
ink!       2 contract(s) found
Crates     frame-support, sp-core, sp-runtime, schnorrkel… +4
Patterns   19 Substrate-specific PQC patterns active

🟠 HIGH     12 findings
  pallets/staking/src/lib.rs:42    BABE Authority Key (sr25519)      `BabeId`
  pallets/staking/src/lib.rs:89    Substrate Session Keys            `impl_opaque_keys! {`
  contracts/token/src/lib.rs:31    ink! ECDSA Recovery (secp256k1)   `self.env().ecdsa_recover`
  ...

Risk Score  85/100  High Risk
```

**Migration paths:**

| Algorithm | PQC replacement |
|---|---|
| sr25519 / BABE | ML-DSA (CRYSTALS-Dilithium) — await sp-core PQC RFC |
| ed25519 / GRANDPA | ML-DSA or SLH-DSA — await Substrate PQC pallets |
| x25519 / libp2p-noise | ML-KEM (CRYSTALS-Kyber) — await libp2p PQC KEX |
| ink! ECDSA | ML-DSA when ink! adds PQC host functions |

**Running tests:**

```bash
npm test
# → 60 tests pass, 6 groups, 0 failures
# Node.js built-in test runner — no extra dependencies
```

**Docker:**

```bash
docker run --rm -v $(pwd):/target quantumscan/scanner /target --substrate
```

## EVM / Solidity support

Use `--solidity` (or scan any `.sol` file) to enable 14 Solidity/EVM-specific PQC patterns:

| Pattern ID | What it detects |
|---|---|
| `EVM-PQC-001` | `ecrecover` — secp256k1 ECDSA signature recovery |
| `EVM-PQC-002` | EIP-712 typed data signatures |
| `EVM-PQC-003` | ERC-2612 `permit()` — HNDL-exposed off-chain ECDSA |
| `EVM-PQC-004` | Gnosis Safe N-of-M ECDSA multisig |
| `EVM-PQC-005` | Chainlink oracle ECDSA DON |
| `EVM-PQC-006` | ERC-4337 UserOperation ECDSA validation |
| `EVM-PQC-007` | Uniswap Permit2 ECDSA batch approval |
| `EVM-PQC-010` | Bridge/Sequencer/Relayer HNDL exposure |
| `EVM-PQC-011` | BLS12-381 pairing (Ethereum PoS) |
| `EVM-PQC-012` | LayerZero / Wormhole cross-chain ECDSA relay |
| + 4 more | ZK-ECDSA circuits, ERC-1271, assembly ecrecover, replay attack |

Full pattern database: [quantumscan-io/evm-pqc-db](https://github.com/quantumscan-io/evm-pqc-db)

### On-chain CBOM (EIP-7789)

QuantumScan scan reports now include an **EIP-7789 CBOM manifest** — a machine-readable cryptographic inventory of every primitive detected.

- EIP draft: [quantumscan-io/eip-cbom](https://github.com/quantumscan-io/eip-cbom)
- Interface: `ICBOM.sol` — implement it in your contract for on-chain PQC discoverability

### ML-DSA on Arbitrum Stylus

Deploy quantum-safe signature verification today without waiting for an EVM protocol upgrade:

- [quantumscan-io/stylus-ml-dsa](https://github.com/quantumscan-io/stylus-ml-dsa) — ML-DSA-65 (NIST FIPS 204) as an Arbitrum Stylus WASM contract
- `mlDsaVerify(pubkey, message, signature)` callable from any Solidity contract on Arbitrum
- Gas: ~112,000 (vs ecrecover ~3,000 — 37× overhead, feasible for high-value operations)

## Contributing

Open issues for new patterns you'd like detected. PRs welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md) if it exists, or just open a PR with:
1. The regex pattern
2. Which algorithm it targets
3. Severity (critical/high/medium/low)
4. A PQC alternative

The [inbound-pr-agent](https://quantumscan.io) reviews PRs daily and will respond within 24h.

---

*Stats auto-updated: 2026-06-29 UTC | [quantumscan.io](https://quantumscan.io)*
