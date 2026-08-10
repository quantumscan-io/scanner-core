# QuantumScan — scanner-core

> **Find quantum-vulnerable cryptography in your codebase — before it becomes a compliance problem.**

[![Live Stats](https://img.shields.io/badge/live%20stats-STATS.md-blue)](./STATS.md)
[![Website](https://img.shields.io/badge/web-quantumscan.io-0ea5e9)](https://quantumscan.io)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![npm](https://img.shields.io/npm/v/elizaos-plugin-quantumscan)](https://www.npmjs.com/package/elizaos-plugin-quantumscan)

QuantumScan builds a cryptographic inventory of a codebase, works out what each primitive is actually used for, and maps it to the post-quantum replacement from [NIST FIPS 203/204/205](https://csrc.nist.gov/publications/detail/fips/203/final).

**A detected primitive is not a vulnerability.** Two occurrences of `ecrecover` can have completely different consequences: one may protect a bridge administrator or a treasury, the other may be an unused library definition or a test. Since v2.0 the scanner therefore produces three separate outputs and never merges them into a single number:

| Report | Question it answers | Flag |
|---|---|---|
| **Cryptographic inventory** | What primitive or construction exists here? | `--inventory` |
| **PQC migration exposure** | What must eventually be replaced? | `--exposure` |
| **Security-critical quantum risk** | What could an attacker actually authorize, forge or decrypt? | `--security` |

Severity is assigned **last**, after execution context and authority are established — never read from the pattern table. Only the security layer feeds the risk score and the CI exit code.

```bash
npx quantumscan .            # all three reports
npx quantumscan . --matrix   # full context matrix, one row per finding
npx quantumscan . --security # only what an attacker could actually do
```

### The context chain

A pattern match alone yields `detected`. Everything downstream is `derived`, and the report says so — static analysis never claims `confirmed`.

```
detected primitive → cryptographic function → reachable use → authority controlled
  → key/exposure state → attack preconditions → affected assets → upgrade path
  → residual classical bypass → severity
```

Each finding carries: cryptographic function, execution plane, reachability, authority,
public-key exposure, authority lifetime, upgradeability, quantum threat model, residual
bypass, migration status, evidence class, and only then severity.

## Quick Start

```bash
# Scan any public GitHub repo — free, no login required
curl -X POST https://quantumscan.io/api/scan \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","repoUrl":"https://github.com/owner/repo"}'
```

Or use the web UI at **[quantumscan.io](https://quantumscan.io)** — paste a repo URL and get a full risk report in seconds.

## What gets detected — classified by threat model

Quantum computing does not affect every primitive the same way. Lumping them together is what produces overstated severity.

| Cryptographic function | Quantum threat | Replacement |
|---|---|---|
| Key establishment / confidentiality (ECDH, DH, X25519, TLS KEX) | **Harvest now, decrypt later** — recorded ciphertext decrypted once the KEM breaks | ML-KEM (FIPS 203) |
| Digital signature / authorization (ECDSA, EdDSA, secp256k1, DSA) | **Future forgery** — the signing authority is compromised, not decrypted | ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) |
| Symmetric / hash (AES-128, SHA-256) | **Search-speed reduction** (Grover) — halved margin, not a break | AES-256, SHA-384+ |
| Encoding & domain separation (EIP-712) | **Migration debt** — no direct quantum break; reusable under a PQ scheme | unchanged; rebind to a PQ validator |
| Already broken today (MD5, SHA-1, DES, RC4, SSLv3) | **Classical break** — quantum is irrelevant to these | SHA-3/SHA-256, AES-GCM, TLS 1.3 |

**HNDL applies to confidentiality, not to signatures.** A public transaction or a recorded `permit` signature is not encrypted payload waiting to be decrypted — it is a signature artifact whose risk is future authorization forgery, bounded by nonce, replay domain, validity period and whether the same authority is still usable.

→ See [STATS.md](./STATS.md) for live numbers updated every 24h.

## Residual classical bypass

The check most scanners miss. A contract is **not** post-quantum authorized just because it verifies ML-DSA somewhere. If an ECDSA owner, proxy admin, module manager, guardian, recovery key, EIP-7702 residual EOA key or `ecrecover` path can replace the validator or authorize the same state transition, the classical root of authority is still there.

QuantumScan reports this at repository level:

```
🧭 MIGRATION STATE  hybrid
   PQ capability   ML-DSA (FIPS 204)

   ⚠ RESIDUAL CLASSICAL BYPASS
     · ECDSA owner / Ownable             src/PQAccount.sol
     · proxy admin / upgrade path        src/PQAccount.sol
     · module manager (Safe/4337)        src/PQAccount.sol

   Hybrid composition
     src/PQAccount.sol:30  OR — classical branch still authorizes
       unbound: chain id, nonce, expiry / deadline, domain separator — downgrade/replay risk
```

### Hybrid composition is not automatically safe

- **AND** (`ECDSA valid && ML-DSA valid`) — holds while either scheme is secure; costs size, gas and key lifecycle complexity.
- **OR** (`ECDSA valid || ML-DSA valid`) — backward compatible and **still fully breakable through the classical branch**. This is a downgrade path, not a migration.

Both branches must be bound to the same message, chain id, account, nonce, action, expiry and domain separator. QuantumScan reports which of those bindings are missing.

## Regulatory mapping

Run `npx quantumscan --regulatory` for what each instrument actually says. Summary:

| Instrument | What it actually does |
|---|---|
| NIST FIPS 203/204/205 | Standardises ML-KEM, ML-DSA, SLH-DSA (Aug 2024). No private-sector deadline. |
| EU coordinated PQC roadmap | Member States begin by end of **2026**; critical infrastructure no later than end of **2030**. |
| DORA (EU 2022/2554) | ICT risk-management framework. **Article 50 is "Administrative penalties and remedial measures"** — it defines supervisory and sanctioning powers. It does **not** create a quantum-risk assessment duty and sets **no 2030 PQC deadline**. |
| NSA CNSA 2.0 | Timelines for US national security systems — not DeFi protocols generally. |

> **Correction (v2.0):** earlier QuantumScan material cited DORA Article 50 as the source of a 2030 PQC assessment requirement for financial entities including DeFi protocols. That mapping was wrong. The 2030 date comes from the EU coordinated PQC transition roadmap, a separate policy instrument, and is addressed to Member States and critical infrastructures.

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

| Pattern ID | What it detects | Correct reading |
|---|---|---|
| `EVM-PQC-001` | `ecrecover` — secp256k1 signature recovery | Signature/authorization. Severity depends on what the recovered address authorizes. |
| `EVM-PQC-002` | EIP-712 signing surface | **Encoding and domain separation, not a signature algorithm.** Resolve the actual validator and authority path. |
| `EVM-PQC-003` | ERC-2612 `permit()` | Signature artifact — **future forgery**, not HNDL. Risk bounded by nonce, deadline and replay domain. |
| `EVM-PQC-004` | Safe / MultiSig signature check | Safe supports ECDSA, pre-validated **and** EIP-1271 contract signatures. Signature type must be resolved, not assumed. |
| `EVM-PQC-005` | Chainlink oracle DON | Oracle report authority (secp256k1 threshold signatures). |
| `EVM-PQC-006` | ERC-4337 account validation | ERC-4337 leaves the signature field's meaning to the account. Both an ECDSA location **and** the best migration surface. |
| `EVM-PQC-007` | Uniswap Permit2 batch approval | Signature/authorization. |
| `EVM-PQC-010` | Bridge / sequencer / relayer keys | Separate confidentiality (HNDL on transport) from ordering/authorization keys — they are not interchangeable findings. |
| `EVM-PQC-011` | BLS12-381 pairing | Consensus/proof primitive. **No NIST PQC pairing standard exists** — monitor, do not promise a replacement. |
| `EVM-PQC-012` | LayerZero / Wormhole relay | Cross-chain message authorization. |
| `EVM-PQC-013` | EIP-7702 delegation | Places programmable code in the account's path but **does not remove the classical EOA root key** — the authorization tuple is still recovered with `ecrecover`. See draft EIP-7851. |
| + 4 more | ZK-ECDSA circuits, ERC-1271, assembly ecrecover, replay attack | |

Full pattern database: [quantumscan-io/evm-pqc-db](https://github.com/quantumscan-io/evm-pqc-db)

### On-chain CBOM (EIP-7789)

QuantumScan scan reports now include an **EIP-7789 CBOM manifest** — a machine-readable cryptographic inventory of every primitive detected.

- EIP draft: [quantumscan-io/eip-cbom](https://github.com/quantumscan-io/eip-cbom)
- Interface: `ICBOM.sol` — implement it in your contract for on-chain PQC discoverability

### ML-DSA on Arbitrum Stylus

Stylus is a WASM execution environment interoperable with Solidity and suited to compute-intensive cryptography, so **application-level** post-quantum signature verification can run on Arbitrum today:

- [quantumscan-io/stylus-ml-dsa](https://github.com/quantumscan-io/stylus-ml-dsa) — ML-DSA-65 (NIST FIPS 204) as an Arbitrum Stylus WASM contract
- `mlDsaVerify(pubkey, message, signature)` callable from any Solidity contract on Arbitrum
- Gas: ~112,000 (vs ecrecover ~3,000 — 37× overhead, feasible for high-value operations)

**What this does and does not mean.** It means a contract can require a PQ signature before authorizing an action. It does **not** mean Arbitrum transactions, EOAs, bridges, sequencer operation, governance or Ethereum settlement have become post-quantum secure. The Stylus verifier is a migration component, not an end-to-end quantum-safety proof.

ML-DSA is a *cryptographic-role* replacement for ECDSA, not an implementation-level drop-in: public-key representation, signature size, calldata, storage, domain binding, verification cost, ABI, validator logic, key rotation, recovery policy and wallet/hardware support all change. Draft [EIP-8051](https://eips.ethereum.org/) proposes ML-DSA verification precompiles precisely because efficient EVM verification is a separate engineering problem — and it is still a draft.

### Migration planes

Arbitrum is not one cryptographic boundary. QuantumScan classifies findings by execution plane because these migrate separately:

| Plane | Scope | Can migrate now? |
|---|---|---|
| Application / smart account | ERC-4337 validators, EIP-1271, Safe modules, Stylus verification | **Yes** |
| Residual classical authority | owner, proxy admin, guardian, recovery, EIP-7702 EOA key | Yes — must be explicitly disabled |
| L2 transaction envelope | protocol-level account authentication | No — chain still accepts classical envelopes |
| Sequencer / transport | feed auth, RPC, TLS key establishment, operational keys | Partly (TLS hybrid KEX) |
| Bridge / governance / oracle | cross-chain and upgrade authority | Per-authority migration |
| Ethereum settlement | hard finality, rollup assertions | No — parent-chain dependency |

An application can become PQ-authorized before the settlement stack does. QuantumScan reports the settlement dependency explicitly rather than letting an application-level result imply end-to-end coverage.

## AI Agent Integration (ElizaOS)

[![npm](https://img.shields.io/npm/v/elizaos-plugin-quantumscan)](https://www.npmjs.com/package/elizaos-plugin-quantumscan)

Use QuantumScan directly from any [ElizaOS](https://elizaos.ai) agent:

```bash
npm install elizaos-plugin-quantumscan
```

```ts
import { quantumscanPlugin } from "elizaos-plugin-quantumscan";

// Register in your agent character
character.plugins = [quantumscanPlugin];
```

Three actions are available to your agent:
- `SCAN_REPOSITORY` — submit a GitHub/GitLab/Bitbucket repo for PQC analysis
- `GET_SCAN_RESULT` — retrieve a completed scan by ID
- `CHECK_PQC_RISK` — instant risk check for a named algorithm (ECDSA, RSA, AES-128…)

Set `QUANTUMSCAN_API_KEY` in your agent env for priority access and more daily scans.

## LangChain / LangGraph / CrewAI / AutoGen

[![PyPI](https://img.shields.io/pypi/v/langchain-quantumscan)](https://pypi.org/project/langchain-quantumscan/)

```bash
pip install langchain-quantumscan
```

```python
from langchain_quantumscan import get_quantumscan_tools

tools = get_quantumscan_tools()  # scan_repository, get_scan_result, check_pqc_risk, scan_contract
agent = create_react_agent(llm, tools)
```

`ScanContractTool` verifies a smart contract is safe to sign a transaction with — honeypot,
drainer, rug-pull, and uncapped-mint detection — **before** the agent acts, not after. Also
works with CrewAI (`QuantumScanCrewTool`) and AutoGen (`AUTOGEN_TOOLS`). No server to run.

## CLI: instant wallet check

```bash
npx quantumscan-agent-doctor 0xYourAgentWallet
```

Zero signup. Checks open ERC-20 approvals + ECDSA nonce reuse (a mathematically certain key
compromise, not a heuristic) against any wallet in one shot. Non-zero exit code on real risk —
usable as a CI gate before deploying an agent. See
[quantumscan-io/quantumscan-agent-doctor](https://github.com/quantumscan-io/quantumscan-agent-doctor).

## Contributing

Open issues for new patterns you'd like detected. PRs welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md).

A pattern contribution needs five things, not four. **Severity is no longer one of them** — it is computed from context:
1. The regex pattern
2. Which algorithm or construction it targets
3. Its **cryptographic function** (key establishment / signature / symmetric / hash / encoding / consensus proof / ambiguous)
4. Its **quantum threat model** (HNDL / future forgery / Grover / migration debt / classical break)
5. The next step for a migration (which may be "resolve the actual validator", not an algorithm)

The [inbound-pr-agent](https://quantumscan.io) reviews PRs daily and will respond within 24h.

---

*Stats auto-updated: 2026-06-29 UTC | [quantumscan.io](https://quantumscan.io)*
