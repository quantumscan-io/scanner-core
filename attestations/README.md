# Attestation Log

This directory contains an append-only log of all QuantumScan scan attestations.

## scan-log.jsonl

Each line is a JSON record anchored by the QuantumScan backend after a scan completes:

```json
{"hash":"<sha256>","scanId":"<uuid>","repoName":"org/repo","riskScore":72,"findingCount":14,"completedAt":"2026-06-28T...","scannerVersion":"1.5.0"}
```

**Verification:** Anyone can verify a scan report by querying:
```
curl https://quantumscan.io/api/verify/<hash>
```

The response re-computes the SHA-256 hash from the stored scan data and confirms it matches. If tampered, `verified: false` is returned.

Git history makes this log immutable — commits cannot be deleted from the public record.
