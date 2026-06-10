## What does this PR add or fix?

<!-- e.g. "Adds Ruby OpenSSL::PKey patterns (RSA/DSA/EC keygen)" -->

## Pattern checklist (for new/changed detection patterns)

- [ ] Pattern follows the existing format: `{ id, name, sev, re, alt }`
- [ ] `re` is anchored enough to avoid matching comments/strings broadly
- [ ] `alt` field gives a concrete PQC migration hint (e.g. ML-KEM, ML-DSA)
- [ ] Tested against at least one real-world repo (link a scan result if possible)
- [ ] No existing pattern already covers this case (checked `index.js`)

## How was this tested?

<!-- e.g. "Ran `npx . path/to/sample-repo` and confirmed N new findings, 0 false positives on curl/curl" -->

## Related issue

Fixes #
