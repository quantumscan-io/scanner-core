# Contributing to scanner-core

Thanks for your interest. Contributions take 3 forms:

## 1. Language patterns (easiest — good first issue)

Add or improve detection patterns for a language. No crypto expertise needed.

**Open issues ready to pick up:**
- See all [`good first issue`](https://github.com/quantumscan-io/scanner-core/labels/good%20first%20issue) issues — usually one per language with missing pattern coverage

A pattern contribution has **two halves**. The regex says what was found; the
context entry says what kind of thing it is. Without the second half the scanner
cannot tell a migration surface from a real vulnerability, so both are required.

**1. The detection** (in `index.js`). `sev` is only a *prior* — the reported
severity is computed from reachability and authority, so do not tune it:

```js
{ id: "ruby-openssl-rsa", name: "Ruby OpenSSL RSA/EC keygen", sev: "high", re: /OpenSSL::PKey::(?:RSA|EC)\.(?:new|generate)\s*\(/i, alt: "Resolve whether the key signs or encrypts, then ML-DSA (FIPS 204) or ML-KEM (FIPS 203)" }, // quantumscan-ignore
```

**2. The context entry** (in `context.js`, `FUNCTION_MAP`), keyed by the same id:

```js
"ruby-openssl-rsa": { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
```

Pick `fn` from what the primitive *does*, and `threat` from how quantum
computing actually affects that function:

| `fn` | `threat` | Why |
|---|---|---|
| `KEY_ESTABLISHMENT`, `ASYM_ENCRYPTION` | `HNDL` | Recorded ciphertext can be decrypted later |
| `SIGNATURE`, `CONSENSUS_PROOF` | `FORGERY` | The authority is forged, not decrypted |
| `SYMMETRIC`, `HASH`, `KDF` | `GROVER` | Halved margin, not a break |
| `ENCODING` | `MIGRATION_DEBT` | Not an algorithm — cannot be a security finding on its own |
| anything already broken today | `CLASSICAL_BREAK` | MD5, RC4, SSLv3 — quantum is irrelevant |
| API serves both signing and encryption | `AMBIGUOUS` / `UNRESOLVED` | **Do not guess.** Unresolved is a valid, honest answer |

Optionally add `plane` (`PLANE.WALLET`, `PLANE.BRIDGE`, `PLANE.ORACLE`…) when the
pattern is inherently tied to one execution plane.

**3. A test** in `test/context-model.test.js` asserting the function and threat
mapping. A pattern with no context entry defaults to `UNKNOWN`/`UNRESOLVED` and
is reported as unresolved rather than assumed critical — that is intentional,
but a mapped pattern is far more useful.

## 2. False positives / missed detections

Open an issue with:
- The code snippet that triggered the false positive (or was missed)
- The language and framework
- Expected severity

Label: `bug`

## 3. Compliance mappings

Help map findings to regional frameworks:
- BACEN 4.658 (Brazil)
- CNBV (Mexico)
- SFC (Colombia)
- LGPD Art. 46

Label: `compliance-mapping`

## Pull request process

1. Fork → branch → PR
2. Keep PRs small and focused (one language or one fix per PR)
3. We review within 48 hours

## License

By contributing, you agree your contributions are licensed under [MIT](LICENSE).
