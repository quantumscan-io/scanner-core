# Contributing to scanner-core

Thanks for your interest. Contributions take 3 forms:

## 1. Language patterns (easiest — good first issue)

Add or improve detection patterns for a language. No crypto expertise needed.

**Open issues ready to pick up:**
- See all [`good first issue`](https://github.com/quantumscan-io/scanner-core/labels/good%20first%20issue) issues — usually one per language with missing pattern coverage

Pattern format (in `index.js`):
```js
{ id: "ruby-openssl-rsa", name: "Ruby OpenSSL RSA/EC keygen", sev: "high", re: /OpenSSL::PKey::(?:RSA|EC)\.(?:new|generate)\s*\(/i, alt: "Migrate to ML-KEM (FIPS 203) / ML-DSA (FIPS 204) when available" }, // quantumscan-ignore
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
