FROM node:20-alpine
LABEL org.opencontainers.image.source="https://github.com/quantumscan-io/scanner-core"
LABEL org.opencontainers.image.description="QuantumScan — Post-Quantum Cryptography Scanner"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /scanner
COPY package.json index.js ./

# Mount target directory at /target and scan it
# Usage: docker run --rm -v $(pwd):/target quantumscan/scanner /target --substrate
ENTRYPOINT ["node", "/scanner/index.js"]
CMD ["--help"]
