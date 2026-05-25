# Contributing to scanner-core

Thanks for your interest. Contributions take 3 forms:

## 1. Language patterns (easiest — good first issue)

Add or improve detection patterns for a language. No crypto expertise needed.

**Open issues ready to pick up:**
- [Go patterns — crypto/rsa, x/crypto](https://github.com/quantumscan-io/scanner-core/issues/1)
- [Java/Kotlin — Bouncy Castle, javax.crypto](https://github.com/quantumscan-io/scanner-core/issues/2)
- [.NET / C# — System.Security.Cryptography](https://github.com/quantumscan-io/scanner-core/issues/3)

Pattern format (in `src/index.js`):
```js
{ pattern: /RSA\.generate\(/gi, severity: 'HIGH', algorithm: 'RSA', pqcAlternative: 'ML-KEM (FIPS 203)' }
```

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
