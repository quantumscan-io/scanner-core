# TEE (Trusted Execution Environment) Support

QuantumScan scanner-core can run inside hardware security enclaves for Tier 1
bank and government use cases where "runs on GitHub Actions" is not an acceptable
privacy guarantee.

## Supported TEE Platforms

| Platform | Hardware | Attestation Format |
|----------|----------|-------------------|
| AWS Nitro Enclaves | AWS EC2 (m5n, c5n, r5n families) | COSE_Sign1 CBOR |
| Intel SGX DCAP | Intel 3rd+ gen Xeon | ECDSA-P256 quote |
| Azure Confidential VM TDX | Intel TDX | EAT (JWT) |

## AWS Nitro Quickstart

```bash
# Build the enclave image
docker build -t quantumscan-enclave -f Dockerfile.nitro .
nitro-cli build-enclave --docker-uri quantumscan-enclave --output-file quantumscan.eif

# Run in enclave (on Nitro-capable instance)
nitro-cli run-enclave --enclave-cid 16 --memory 2048 --cpu-count 2 \
  --eif-path quantumscan.eif --debug-mode

# Get attestation document
nitro-cli describe-enclaves
# POST /api/tee/verify with the attestation document
```

## PCR Values

PCR (Platform Configuration Register) values are the cryptographic fingerprint
of the enclave image. They are published here after every release build.

| Version | PCR0 (Image Hash) | PCR1 (Kernel) | PCR2 (App) |
|---------|------------------|---------------|------------|
| 1.9.5 | `publish after Nitro build` | `publish after Nitro build` | `publish after Nitro build` |

## Verification

After running a scan inside a TEE, verify the attestation:

```bash
curl -X POST https://quantumscan.io/api/tee/verify \
  -H "Content-Type: application/json" \
  -d '{
    "attestationType": "aws-nitro",
    "attestationDocument": "<base64 document>",
    "scannerVersion": "1.9.5"
  }'
```

## Privacy Guarantees

With TEE attestation, QuantumScan provides:

1. **Code isolation** — Scanner binary runs in hardware-isolated memory
2. **Non-exportability** — Source code files passed to the enclave cannot be read by the host OS, cloud provider, or QuantumScan
3. **Cryptographic proof** — The attestation document is signed by the hardware manufacturer's root CA, proving no tampering
4. **Reproducibility** — PCR values are deterministic; anyone can rebuild the enclave image and verify they match
5. **Report-only egress** — Only the scan report (findings + risk score) leaves the enclave; source code stays inside

## Architecture

```
Client Codebase (secret)
    │
    ▼
Nitro Enclave (hardware-isolated)
    ├── scanner-core binary (PCR-measured)
    ├── Source files (NEVER leave enclave)
    └── Attestation: Hardware-signed proof of isolation
         │
         ▼
    QuantumScan API /api/tee/verify
         │
         ▼
    Scan Report (findings only) → returned to client
```

## Dockerfile.nitro

See `Dockerfile.nitro` in this repository for the enclave-optimized build.