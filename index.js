#!/usr/bin/env node
import { readdirSync, readFileSync, statSync } from "fs";
import { join, extname, relative, resolve } from "path";
import { argv, exit } from "process";

const VERSION = "1.0.0";
const APP_URL = "https://quantumscan.io";

// ── ANSI helpers ──────────────────────────────────────────────────────────────
const NO_COLOR = !!(process.env.NO_COLOR || !process.stdout.isTTY);

const C = NO_COLOR
  ? Object.fromEntries(
      ["reset","bold","dim","red","yellow","blue","cyan","orange","gray","green","white"].map(k => [k, ""])
    )
  : {
      reset: "\x1b[0m",
      bold: "\x1b[1m",
      dim: "\x1b[2m",
      red: "\x1b[31m",
      yellow: "\x1b[33m",
      blue: "\x1b[34m",
      cyan: "\x1b[36m",
      orange: "\x1b[38;5;208m",
      gray: "\x1b[90m",
      green: "\x1b[32m",
      white: "\x1b[97m",
    };

function sevColor(sev) {
  if (sev === "critical") return C.red;
  if (sev === "high") return C.orange;
  if (sev === "medium") return C.yellow;
  return C.blue;
}

// ── Crypto patterns (mirrors quantumscan.io detection engine) ────────────────
const PATTERNS = [
  // CRITICAL — broken / deprecated
  { id: "ssl-v2-v3",    name: "SSLv2 / SSLv3",    sev: "critical", re: /SSLv[23]|SSL_OP_NO_SSLv[23]|PROTOCOL_SSLv[23]/i },
  { id: "tls-old",      name: "TLS 1.0 / 1.1",    sev: "critical", re: /TLSv1(?:\.0|\.1)?\b|PROTOCOL_TLSv1(?:_1)?\b|ssl\.TLSv1\b|SslProtocols\.(?:Tls|Tls11)\b/i },
  { id: "md5",          name: "MD5",               sev: "critical", re: /\bMD5\b|md5\(|hashlib\.md5|MessageDigest\.getInstance\s*\(\s*["']MD5["']\)|new\s+MD5(?:CryptoServiceProvider)?\s*\(|MD5CryptoServiceProvider\b/i,  alt: "SHA3-256 or SHA-256" },
  { id: "sha1",         name: "SHA-1",             sev: "critical", re: /\bSHA1\b|\bsha1\s*\(|hashlib\.sha1\b|MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']\)|new\s+SHA1CryptoServiceProvider\s*\(|SHA1CryptoServiceProvider\b/i,    alt: "SHA-256" },
  { id: "des",          name: "DES",               sev: "critical", re: /\bDES\b(?!C?SHA|\s*ede)|DESKeySpec|DES\.new\b|DESCryptoServiceProvider\b|Cipher\.getInstance\s*\(\s*["']DES[/"']/i },
  { id: "3des",         name: "3DES / TripleDES",  sev: "critical", re: /3DES|TripleDES|DESede|DES_EDE|des3_cbc|des-ede3/i },
  { id: "rc4",          name: "RC4",               sev: "critical", re: /\bRC4\b|ARCFOUR|ARC4\b|arcfour|Cipher\.getInstance\s*\(\s*["']RC4/i },
  { id: "ecb",          name: "AES-ECB (no IV)",   sev: "critical", re: /\/ECB\/|AES\.MODE_ECB|CipherMode\.ECB\b|Cipher\.getInstance\s*\(\s*["']AES["']|["']AES\/ECB/i,                  alt: "AES-GCM or ChaCha20-Poly1305" },
  { id: "rc2",          name: "RC2",               sev: "critical", re: /\bRC2\b|RC2KeySpec|RC2ParameterSpec/i },
  { id: "nullcipher",   name: "NullCipher",        sev: "critical", re: /NullCipher|javax\.crypto\.NullCipher/i },
  // HIGH — quantum-vulnerable (Shor's algorithm)
  { id: "rsa",          name: "RSA",               sev: "high",     re: /RSA(?:Key(?:Pair)?|PublicKey|PrivateKey|Generator|Encryptor|Decryptor|Signature|CryptoServiceProvider)?(?:\s*\(|\s*\.\s*(?:generate|new|create|load|import))\b|RSACryptoServiceProvider\b|generateRSA|Rsa(?:Private|Public|Key|KeyPairGenerator)|PKCS1_(?:v1_5|OAEP)|import_rsa_key|openssl_pkey_new/i, alt: "ML-KEM (CRYSTALS-Kyber)" },
  { id: "rsa-small",    name: "RSA key ≤2048 bits",sev: "critical", re: /rsa.*\b(512|768|1024|1536|2048)\b|\bkey(?:_size|Size|Bits)\s*[=:]\s*(512|768|1024|1536|2048)\b|generateKeyPair\s*\(\s*(512|768|1024|1536|2048)/i },
  { id: "ecdsa",        name: "ECDSA",             sev: "high",     re: /\bECDSA\b|ECDsa\.Create\s*\(|ECDSASignature|ecdsa_(?:sign|verify)|ES(?:256|384|512)\b/i,                          alt: "ML-DSA (CRYSTALS-Dilithium)" },
  { id: "ecdh",         name: "ECDH / ECDHE",      sev: "high",     re: /\bECDH\b|\bECDHE\b|ECKeyAgreement|ecdh_(?:generate|compute)|TLS_ECDHE/i,                      alt: "ML-KEM (CRYSTALS-Kyber)" },
  { id: "dsa",          name: "DSA",               sev: "high",     re: /\bDSA\b(?!SHA|_KEY_SIZE|Version)|DSA\.Create\s*\(|DSAKeySpec|DSAPublicKey|DSAPrivateKey|DSASignature|DSACryptoServiceProvider\b|DsaKeyPairGenerator\b/i,         alt: "ML-DSA (CRYSTALS-Dilithium)" },
  { id: "dh",           name: "Diffie-Hellman",    sev: "high",     re: /\bDHKey\b|\bDiffieHellman\b|DHKeyExchange|DHParameterSpec|DH\.new\b/i,                         alt: "ML-KEM (CRYSTALS-Kyber)" },
  { id: "p256",         name: "NIST P-256",        sev: "high",     re: /\bP-?256\b|prime256v1|secp256r1|NamedCurve\.P_?256/i,                                          alt: "ML-KEM or ML-DSA" },
  { id: "p384",         name: "NIST P-384",        sev: "high",     re: /\bP-?384\b|secp384r1|NamedCurve\.P_?384/i,                                                     alt: "ML-KEM or ML-DSA" },
  { id: "p521",         name: "NIST P-521",        sev: "high",     re: /\bP-?521\b|secp521r1|NamedCurve\.P_?521/i },
  { id: "secp256k1",    name: "secp256k1",         sev: "high",     re: /secp256k1|SECP256K1/i },
  { id: "ed25519",      name: "Ed25519 / EdDSA",   sev: "high",     re: /\bEd25519\b|Edwards25519|EdDSA\b/i,                                                             alt: "ML-DSA or SLH-DSA" },
  { id: "x25519",       name: "X25519 / Curve25519",sev: "high",    re: /\bX25519\b|Curve25519|curve25519/i,                                                             alt: "ML-KEM (CRYSTALS-Kyber)" },
  { id: "jwt-alg",      name: "JWT quantum-vuln alg",sev: "high",   re: /algorithm["'\s:]+["'](RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA)["']/i,       alt: "HS256 or post-quantum signature" },
  { id: "pkcs1",        name: "PKCS#1 (RSA)",      sev: "high",     re: /PKCS1\b|pkcs#1|BEGIN RSA PRIVATE KEY|RSAPrivateKey_format/i },
  { id: "ecc",          name: "ECC generic",       sev: "high",     re: /EllipticCurve|ECGenParameterSpec|ECPublicKey|ECPrivateKey|ECKeyPairGenerator\b|EcKey\b|ec\.generate_private_key/i },
  { id: "x509-gen",     name: "X.509 cert generation",sev: "high",  re: /X509(?:Certificate)?Builder.*sign|createSelfSigned|makeCertificate|X509\.new\b/i },
  // MEDIUM — weak or concerning
  { id: "aes128",       name: "AES-128",           sev: "medium",   re: /AES[-_]?128|AES\b.*\b128\b|KeySize\s*\(\s*128\s*\)|aes_128/i,                                  alt: "AES-256" },
  { id: "cbc",          name: "CBC mode",          sev: "medium",   re: /\/CBC\/|AES\.MODE_CBC|aes_cbc\b|MODE_CBC/i,                                                     alt: "AES-GCM or ChaCha20-Poly1305" },
  { id: "hmacsha1",     name: "HMAC-SHA1",         sev: "medium",   re: /HMAC[-_]?SHA1|HmacSHA1|hmac_sha1|Mac\.getInstance\s*\(\s*["']HmacSHA1["']\)/i,                 alt: "HMAC-SHA256" },
  { id: "pbkdf2-low",   name: "PBKDF2 low iterations",sev: "medium",re: /PBKDF2.*\b(100|500|1000|5000|10000)\b|iterationCount\s*[=:]\s*\d{1,4}\b/i,                    alt: "Argon2id" },
  { id: "blowfish",     name: "Blowfish",          sev: "medium",   re: /\bBlowfish\b|bf_cbc|BF_KEY\b|AES\.MODE_BF/i },
  { id: "math-random",  name: "Math.random in crypto",sev: "medium",re: /Math\.random\(\)\s*.*(?:key|token|nonce|salt|iv|secret)|(?:key|token|nonce|salt|iv|secret).*Math\.random\(\)/i, alt: "crypto.getRandomValues()" },
  { id: "openssl-old",  name: "OpenSSL < 3.x",     sev: "medium",   re: /OpenSSL\s+1\.[01]\.|libssl\.so\.1\.|openssl-1\.[01]\./i },
  // BLOCKCHAIN — Web3 / DeFi / Wallet libraries (secp256k1 / Ed25519)
  { id: "ethers-wallet",       name: "ethers.js Wallet (secp256k1)",       sev: "high", re: /new\s+ethers\.Wallet\s*\(|Wallet\.createRandom\s*\(|Wallet\.fromMnemonic\s*\(|Wallet\.fromPhrase\s*\(/i,                            alt: "Monitor Ethereum PQC roadmap (EIP-7786)" },
  { id: "web3-accounts",       name: "web3.js / viem accounts (secp256k1)",sev: "high", re: /web3\.eth\.accounts\.|accounts\.create\s*\(|privateKeyToAccount\s*\(|createWalletClient\s*\(|generatePrivateKey\s*\(\)/i,             alt: "Monitor Ethereum PQC roadmap" },
  { id: "bitcoinjs-ecpair",    name: "bitcoinjs-lib ECPair (secp256k1)",   sev: "high", re: /ECPair\.fromPrivateKey\s*\(|ECPair\.makeRandom\s*\(|ECPair\.fromWIF\s*\(|bitcoin\.ECPair/i,                                           alt: "Follow Bitcoin PQC proposals (BIP-360 draft)" },
  { id: "solana-keypair",      name: "Solana Keypair (Ed25519)",           sev: "high", re: /Keypair\.generate\s*\(|Keypair\.fromSecretKey\s*\(|Keypair\.fromSeed\s*\(|web3\.Keypair\b/i,                                          alt: "Monitor Solana PQC roadmap" },
  { id: "solidity-ecrecover",  name: "Solidity ecrecover (secp256k1)",     sev: "high", re: /\becrecover\s*\(|ECDSA\.recover\s*\(|ECDSA\.tryRecover\s*\(/i,                                                                        alt: "Monitor EVM PQC precompile proposals" },
  { id: "bip32-hd-wallet",     name: "BIP32/BIP39 HD Wallet derivation",  sev: "high", re: /BIP32Factory\s*\(|hdkey\.fromMasterSeed\s*\(|HDKey\.fromMasterSeed\s*\(|EthereumHDKey|derivePath\s*\(\s*["']m\//i,                   alt: "No PQC BIP32 standard yet — monitor BIP proposals" },
  { id: "eth-account-python",  name: "eth-account / web3.py (secp256k1)", sev: "high", re: /from\s+eth_account\s+import|Account\.create\s*\(|Account\.from_key\s*\(|w3\.eth\.account\./i,                                        alt: "Monitor ethereum/py-evm PQC roadmap" },
  { id: "coincurve-secp256k1", name: "coincurve / python-bitcoin",        sev: "high", re: /import\s+coincurve\b|coincurve\.(?:PublicKey|PrivateKey)|from\s+bitcoinlib\s+import.*(?:Key|sign)/i,                                  alt: "ML-DSA (CRYSTALS-Dilithium)" },
  { id: "rust-secp256k1-crate",name: "Rust secp256k1 / k256 crate",      sev: "high", re: /use\s+secp256k1::|use\s+k256::|Secp256k1::new\s*\(|SecretKey::from_slice\s*\(|SigningKey::from_bytes\s*\(/i,                          alt: "ML-DSA via pqcrypto-dilithium crate" },
  { id: "tronweb-wallet",      name: "TronWeb wallet (secp256k1)",        sev: "high", re: /TronWeb\.createAccount\s*\(|tronWeb\.createAccount|tronWeb\.address\.fromPrivateKey|TronWeb\.address\.fromPrivateKey/i,                alt: "Monitor TRON PQC roadmap" },
  // LOW — informational
  { id: "hardcoded-key",name: "Hardcoded key",     sev: "low",      re: /(?:private_key|secret_key|encryption_key|aes_key|rsa_key)\s*=\s*["'][^"']{16,}["']|-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/i },
  { id: "crc32",        name: "CRC32 for integrity",sev: "low",     re: /crc32.*(?:integrity|verify|validate)|(?:integrity|verify|validate).*crc32|CRC32C?\.(?:compute|calculate|verify)/i, alt: "SHA-256 or BLAKE3" },
  { id: "sha256-kdf",   name: "SHA-256 as password KDF",sev: "low", re: /sha256.*(?:password|passphrase)\b|(?:password|passphrase).*sha256/i,                           alt: "Argon2id or bcrypt" },
  { id: "dh-1024",      name: "DH 1024-bit params",sev: "low",      re: /DHParameterSpec\s*\(\s*1024|generate_parameters.*1024|dhparam\s+1024/i,                        alt: "ML-KEM" },
];

const SCANNABLE_EXTS = new Set([
  ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
  ".go", ".java", ".rb", ".cs", ".rs",
  ".cpp", ".cc", ".cxx", ".c", ".h", ".hpp",
  ".php", ".kt", ".swift", ".scala", ".ex", ".exs",
  ".sol",
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".next", "dist", "build", "out", "bin",
  "coverage", ".cache", "__pycache__", "vendor", "target",
  ".gradle", ".idea", ".vscode", "venv", ".venv", ".tox",
  "tmp", "temp", ".turbo",
]);

// ── File walking ──────────────────────────────────────────────────────────────
function walkDir(dir, files = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); }
  catch { return files; }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const full = join(dir, e.name);
    if (e.isDirectory()) walkDir(full, files);
    else if (e.isFile()) files.push(full);
  }
  return files;
}

// ── Scanner ───────────────────────────────────────────────────────────────────
function scanFile(filePath, rootDir) {
  let content;
  try { content = readFileSync(filePath, "utf8"); }
  catch { return []; }
  if (content.length > 500_000) return [];

  const lines = content.split("\n");
  const findings = [];
  const relPath = relative(rootDir, filePath).replace(/\\/g, "/");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("#")) continue;
    for (const p of PATTERNS) {
      if (p.re.test(line)) {
        const m = line.match(p.re);
        findings.push({
          file: relPath,
          line: i + 1,
          id: p.id,
          name: p.name,
          sev: p.sev,
          match: (m?.[0] ?? "").substring(0, 60).trim(),
          alt: p.alt ?? null,
        });
        break; // one finding per line
      }
    }
  }
  return findings;
}

// ── Risk score ────────────────────────────────────────────────────────────────
const SEV_WEIGHT = { critical: 25, high: 15, medium: 8, low: 3 };
const SEV_ORDER  = ["critical", "high", "medium", "low"];
const SEV_ICON   = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵" };

function calcScore(findings) {
  return Math.min(100, findings.reduce((s, f) => s + (SEV_WEIGHT[f.sev] ?? 5), 0));
}

function riskLabel(score) {
  if (score === 0)  return `${C.green}Quantum-Safe ✓${C.reset}`;
  if (score <= 20)  return `${C.green}Low Risk${C.reset}`;
  if (score <= 40)  return `${C.yellow}Low-Moderate${C.reset}`;
  if (score <= 60)  return `${C.yellow}Moderate ⚠${C.reset}`;
  if (score <= 80)  return `${C.orange}High Risk${C.reset}`;
  return `${C.red}Critical 🚨${C.reset}`;
}

// ── Output helpers ────────────────────────────────────────────────────────────
function visLen(str) { return str.replace(/\x1b\[[0-9;]*m/g, "").length; }
function padEnd(str, len) { return str + " ".repeat(Math.max(0, len - visLen(str))); }

function hr() { return "─".repeat(58); }

function printResults(findings, totalFiles, scannableCount, targetDir, score) {
  console.log(`\n${C.bold}QuantumScan v${VERSION}${C.reset}  Post-Quantum Cryptography Scanner`);
  console.log(`${C.cyan}${APP_URL}${C.reset}`);
  console.log(hr());
  console.log(`Path     ${C.bold}${targetDir}${C.reset}`);
  console.log(`Files    ${C.gray}${totalFiles} total · ${scannableCount} scannable${C.reset}\n`);

  if (findings.length === 0) {
    console.log(`${C.green}✓  No cryptographic vulnerabilities detected.${C.reset}`);
    console.log(`   Your codebase looks quantum-safe based on static patterns.\n`);
  } else {
    const grouped = {};
    for (const sev of SEV_ORDER) grouped[sev] = findings.filter(f => f.sev === sev);

    for (const sev of SEV_ORDER) {
      const group = grouped[sev];
      if (!group.length) continue;
      console.log(
        `${sevColor(sev)}${C.bold}${SEV_ICON[sev]} ${sev.toUpperCase().padEnd(9)}${C.reset}` +
        `${C.gray}${group.length} finding${group.length !== 1 ? "s" : ""}${C.reset}`
      );
      for (const f of group.slice(0, 25)) {
        const loc  = `  ${f.file}:${f.line}`;
        const name = sevColor(f.sev) + f.name + C.reset;
        const snip = f.match ? `  ${C.dim}\`${f.match}\`${C.reset}` : "";
        console.log(`${padEnd(loc, 44)}${padEnd(name, 28)}${snip}`);
      }
      if (group.length > 25) console.log(`  ${C.gray}… +${group.length - 25} more${C.reset}`);
      console.log("");
    }
  }

  console.log(hr());
  console.log(`Risk Score  ${C.bold}${score}/100${C.reset}  ${riskLabel(score)}`);

  if (findings.length > 0) {
    console.log(`\n${C.dim}Migrate to: ML-KEM (key encap, FIPS 203) · ML-DSA (signatures, FIPS 204)${C.reset}`);
    console.log(`${C.dim}Required by NIST, DORA, NIS2, CNSA 2.0 — deadline 2030.${C.reset}`);
    console.log(`\n${C.cyan}Full AI analysis + migration guides → ${APP_URL}${C.reset}`);
  }
  console.log("");
}

// ── JSON output ───────────────────────────────────────────────────────────────
function printJson(findings, totalFiles, scannableCount, targetDir, score) {
  const summary = { riskScore: score };
  for (const sev of SEV_ORDER) summary[sev] = findings.filter(f => f.sev === sev).length;
  console.log(JSON.stringify({
    version: VERSION,
    path: targetDir,
    stats: { totalFiles, scannableFiles: scannableCount },
    summary,
    findings: findings.map(f => ({
      file: f.file, line: f.line,
      algorithm: f.name, severity: f.sev,
      match: f.match, pqcAlternative: f.alt,
    })),
  }, null, 2));
}

// ── CLI ───────────────────────────────────────────────────────────────────────
const HELP = `
Usage: npx quantumscan [path] [options]

  path               Directory to scan (default: current directory)

Options:
  --json             Output results as JSON (for CI/CD pipelines)
  --no-fail          Exit 0 even when findings are found (default: exit 1)
  --version          Show version
  --help             Show this help

Examples:
  npx quantumscan .
  npx quantumscan ./src --json
  npx quantumscan /path/to/project --json | jq '.summary'

Exit codes:
  0   No findings (or --no-fail)
  1   Findings detected
  2   Error (path not found, etc.)

Full cloud analysis with AI migration guides:
  ${APP_URL}
`;

function main() {
  const args = argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) { console.log(HELP); exit(0); }
  if (args.includes("--version") || args.includes("-v")) { console.log(VERSION); exit(0); }

  const jsonMode = args.includes("--json");
  const noFail   = args.includes("--no-fail");
  const pathArg  = args.find(a => !a.startsWith("-")) ?? ".";

  let targetDir;
  try {
    targetDir = resolve(pathArg);
    statSync(targetDir);
  } catch {
    console.error(`Error: path not found — ${pathArg}`);
    exit(2);
  }

  if (!jsonMode) process.stdout.write(`Scanning ${targetDir} ...\r`);

  let allFiles;
  const st = statSync(targetDir);
  if (st.isFile()) {
    allFiles = [targetDir];
    targetDir = resolve(pathArg, "..");
  } else {
    allFiles = walkDir(targetDir);
  }

  const scannableFiles = allFiles.filter(f => SCANNABLE_EXTS.has(extname(f).toLowerCase()));
  const findings       = scannableFiles.flatMap(f => scanFile(f, targetDir));
  const score          = calcScore(findings);

  if (jsonMode) {
    printJson(findings, allFiles.length, scannableFiles.length, targetDir, score);
  } else {
    printResults(findings, allFiles.length, scannableFiles.length, targetDir, score);
  }

  exit(noFail || findings.length === 0 ? 0 : 1);
}

main();
