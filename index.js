#!/usr/bin/env node
import { readdirSync, readFileSync, statSync, existsSync } from "fs";
import { execSync } from "child_process";
import { join, extname, relative, resolve, basename } from "path";
import { argv, exit } from "process";

const VERSION = "1.2.0";
const APP_URL = "https://quantumscan.io";

// ── ANSI helpers ──────────────────────────────────────────────────────────────
const NO_COLOR = !!(process.env.NO_COLOR || !process.stdout.isTTY);
const C = NO_COLOR
  ? Object.fromEntries(
      ["reset","bold","dim","red","yellow","blue","cyan","orange","gray","green","white"].map(k => [k, ""])
    )
  : {
      reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
      red: "\x1b[31m", yellow: "\x1b[33m", blue: "\x1b[34m",
      cyan: "\x1b[36m", orange: "\x1b[38;5;208m",
      gray: "\x1b[90m", green: "\x1b[32m", white: "\x1b[97m",
    };

function sevColor(sev) {
  if (sev === "critical") return C.red;
  if (sev === "high") return C.orange;
  if (sev === "medium") return C.yellow;
  return C.blue;
}

// ── Crypto patterns ───────────────────────────────────────────────────────────
const PATTERNS = [
  // CRITICAL — broken / deprecated
  { id: "ssl-v2-v3",    name: "SSLv2 / SSLv3",           sev: "critical", re: /SSLv[23]|SSL_OP_NO_SSLv[23]|PROTOCOL_SSLv[23]/i },
  { id: "tls-old",      name: "TLS 1.0 / 1.1",           sev: "critical", re: /TLSv1(?:\.0|\.1)?\b|PROTOCOL_TLSv1(?:_1)?\b|ssl\.TLSv1\b|SslProtocols\.(?:Tls|Tls11)\b/i },
  { id: "md5",          name: "MD5",                      sev: "critical", re: /\bMD5\b|md5\(|hashlib\.md5|MessageDigest\.getInstance\s*\(\s*["']MD5["']\)|new\s+MD5(?:CryptoServiceProvider)?\s*\(|MD5CryptoServiceProvider\b/i, alt: "SHA3-256 or SHA-256" },
  { id: "sha1",         name: "SHA-1",                    sev: "critical", re: /\bSHA1\b|\bsha1\s*\(|hashlib\.sha1\b|MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']\)|new\s+SHA1CryptoServiceProvider\s*\(|SHA1CryptoServiceProvider\b/i, alt: "SHA-256" },
  { id: "des",          name: "DES",                      sev: "critical", re: /\bDES\b(?!C?SHA|\s*ede)|DESKeySpec|DES\.new\b|DESCryptoServiceProvider\b|Cipher\.getInstance\s*\(\s*["']DES[/"']/i },
  { id: "3des",         name: "3DES / TripleDES",         sev: "critical", re: /3DES|TripleDES|DESede|DES_EDE|des3_cbc|des-ede3/i },
  { id: "rc4",          name: "RC4",                      sev: "critical", re: /\bRC4\b|ARCFOUR|ARC4\b|arcfour|Cipher\.getInstance\s*\(\s*["']RC4/i },
  { id: "ecb",          name: "AES-ECB (no IV)",          sev: "critical", re: /\/ECB\/|AES\.MODE_ECB|CipherMode\.ECB\b|Cipher\.getInstance\s*\(\s*["']AES["']|["']AES\/ECB/i, alt: "AES-GCM or ChaCha20-Poly1305" },
  { id: "rc2",          name: "RC2",                      sev: "critical", re: /\bRC2\b|RC2KeySpec|RC2ParameterSpec/i },
  { id: "nullcipher",   name: "NullCipher",               sev: "critical", re: /NullCipher|javax\.crypto\.NullCipher/i },
  // HIGH — quantum-vulnerable (Shor's algorithm)
  { id: "rsa",          name: "RSA",                      sev: "high",     re: /RSA(?:Key(?:Pair)?|PublicKey|PrivateKey|Generator|Encryptor|Decryptor|Signature|CryptoServiceProvider)?(?:\s*\(|\s*\.\s*(?:generate|new|create|load|import))\b|RSACryptoServiceProvider\b|generateRSA|Rsa(?:Private|Public|Key|KeyPairGenerator)|PKCS1_(?:v1_5|OAEP)|import_rsa_key|openssl_pkey_new/i, alt: "ML-KEM (CRYSTALS-Kyber)" },
  { id: "rsa-small",    name: "RSA key ≤2048 bits",       sev: "critical", re: /rsa.*\b(512|768|1024|1536|2048)\b|\bkey(?:_size|Size|Bits)\s*[=:]\s*(512|768|1024|1536|2048)\b|generateKeyPair\s*\(\s*(512|768|1024|1536|2048)/i },
  { id: "ecdsa",        name: "ECDSA",                    sev: "high",     re: /\bECDSA\b|ECDsa\.Create\s*\(|ECDSASignature|ecdsa_(?:sign|verify)|ES(?:256|384|512)\b/i, alt: "ML-DSA (CRYSTALS-Dilithium)" },
  { id: "ecdh",         name: "ECDH / ECDHE",             sev: "high",     re: /\bECDH\b|\bECDHE\b|ECKeyAgreement|ecdh_(?:generate|compute)|TLS_ECDHE/i, alt: "ML-KEM (CRYSTALS-Kyber)" },
  { id: "dsa",          name: "DSA",                      sev: "high",     re: /\bDSA\b(?!SHA|_KEY_SIZE|Version)|DSA\.Create\s*\(|DSAKeySpec|DSAPublicKey|DSAPrivateKey|DSASignature|DSACryptoServiceProvider\b|DsaKeyPairGenerator\b/i, alt: "ML-DSA (CRYSTALS-Dilithium)" },
  { id: "dh",           name: "Diffie-Hellman",           sev: "high",     re: /\bDHKey\b|\bDiffieHellman\b|DHKeyExchange|DHParameterSpec|DH\.new\b/i, alt: "ML-KEM (CRYSTALS-Kyber)" },
  { id: "p256",         name: "NIST P-256",               sev: "high",     re: /\bP-?256\b|prime256v1|secp256r1|NamedCurve\.P_?256/i, alt: "ML-KEM or ML-DSA" },
  { id: "p384",         name: "NIST P-384",               sev: "high",     re: /\bP-?384\b|secp384r1|NamedCurve\.P_?384/i, alt: "ML-KEM or ML-DSA" },
  { id: "p521",         name: "NIST P-521",               sev: "high",     re: /\bP-?521\b|secp521r1|NamedCurve\.P_?521/i },
  { id: "secp256k1",    name: "secp256k1",                sev: "high",     re: /secp256k1|SECP256K1/i },
  { id: "ed25519",      name: "Ed25519 / EdDSA",          sev: "high",     re: /\bEd25519\b|Edwards25519|EdDSA\b/i, alt: "ML-DSA or SLH-DSA" },
  { id: "x25519",       name: "X25519 / Curve25519",      sev: "high",     re: /\bX25519\b|Curve25519|curve25519/i, alt: "ML-KEM (CRYSTALS-Kyber)" },
  { id: "jwt-alg",      name: "JWT quantum-vuln alg",     sev: "high",     re: /algorithm["'\s:]+["'](RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA)["']/i, alt: "HS256 or post-quantum signature" },
  { id: "pkcs1",        name: "PKCS#1 (RSA)",             sev: "high",     re: /PKCS1\b|pkcs#1|BEGIN RSA PRIVATE KEY|RSAPrivateKey_format/i },
  { id: "ecc",          name: "ECC generic",              sev: "high",     re: /EllipticCurve|ECGenParameterSpec|ECPublicKey|ECPrivateKey|ECKeyPairGenerator\b|EcKey\b|ec\.generate_private_key/i },
  { id: "x509-gen",     name: "X.509 cert generation",    sev: "high",     re: /X509(?:Certificate)?Builder.*sign|createSelfSigned|makeCertificate|X509\.new\b/i },
  // MEDIUM — weak or concerning
  { id: "aes128",       name: "AES-128",                  sev: "medium",   re: /AES[-_]?128|AES\b.*\b128\b|KeySize\s*\(\s*128\s*\)|aes_128/i, alt: "AES-256" },
  { id: "cbc",          name: "CBC mode",                 sev: "medium",   re: /\/CBC\/|AES\.MODE_CBC|aes_cbc\b|MODE_CBC/i, alt: "AES-GCM or ChaCha20-Poly1305" },
  { id: "hmacsha1",     name: "HMAC-SHA1",                sev: "medium",   re: /HMAC[-_]?SHA1|HmacSHA1|hmac_sha1|Mac\.getInstance\s*\(\s*["']HmacSHA1["']\)/i, alt: "HMAC-SHA256" },
  { id: "pbkdf2-low",   name: "PBKDF2 low iterations",    sev: "medium",   re: /PBKDF2.*\b(100|500|1000|5000|10000)\b|iterationCount\s*[=:]\s*\d{1,4}\b/i, alt: "Argon2id" },
  { id: "blowfish",     name: "Blowfish",                 sev: "medium",   re: /\bBlowfish\b|bf_cbc|BF_KEY\b|AES\.MODE_BF/i },
  { id: "math-random",  name: "Math.random in crypto",    sev: "medium",   re: /Math\.random\(\)\s*.*(?:key|token|nonce|salt|iv|secret)|(?:key|token|nonce|salt|iv|secret).*Math\.random\(\)/i, alt: "crypto.getRandomValues()" },
  { id: "openssl-old",  name: "OpenSSL < 3.x",            sev: "medium",   re: /OpenSSL\s+1\.[01]\.|libssl\.so\.1\.|openssl-1\.[01]\./i },
  // BLOCKCHAIN
  { id: "ethers-wallet",       name: "ethers.js Wallet (secp256k1)",       sev: "high", re: /new\s+ethers\.Wallet\s*\(|Wallet\.createRandom\s*\(|Wallet\.fromMnemonic\s*\(|Wallet\.fromPhrase\s*\(/i, alt: "Monitor Ethereum PQC roadmap (EIP-7786)" },
  { id: "web3-accounts",       name: "web3.js / viem accounts (secp256k1)",sev: "high", re: /web3\.eth\.accounts\.|accounts\.create\s*\(|privateKeyToAccount\s*\(|createWalletClient\s*\(|generatePrivateKey\s*\(\)/i, alt: "Monitor Ethereum PQC roadmap" },
  { id: "bitcoinjs-ecpair",    name: "bitcoinjs-lib ECPair (secp256k1)",   sev: "high", re: /ECPair\.fromPrivateKey\s*\(|ECPair\.makeRandom\s*\(|ECPair\.fromWIF\s*\(|bitcoin\.ECPair/i, alt: "Follow Bitcoin PQC proposals (BIP-360 draft)" },
  { id: "solana-keypair",      name: "Solana Keypair (Ed25519)",           sev: "high", re: /Keypair\.generate\s*\(|Keypair\.fromSecretKey\s*\(|Keypair\.fromSeed\s*\(|web3\.Keypair\b/i, alt: "Monitor Solana PQC roadmap" },
  { id: "solidity-ecrecover",  name: "Solidity ecrecover (secp256k1)",     sev: "high", re: /\becrecover\s*\(|ECDSA\.recover\s*\(|ECDSA\.tryRecover\s*\(/i, alt: "Monitor EVM PQC precompile proposals" },
  { id: "bip32-hd-wallet",     name: "BIP32/BIP39 HD Wallet derivation",  sev: "high", re: /BIP32Factory\s*\(|hdkey\.fromMasterSeed\s*\(|HDKey\.fromMasterSeed\s*\(|EthereumHDKey|derivePath\s*\(\s*["']m\//i, alt: "No PQC BIP32 standard yet — monitor BIP proposals" },
  { id: "eth-account-python",  name: "eth-account / web3.py (secp256k1)", sev: "high", re: /from\s+eth_account\s+import|Account\.create\s*\(|Account\.from_key\s*\(|w3\.eth\.account\./i, alt: "Monitor ethereum/py-evm PQC roadmap" },
  { id: "coincurve-secp256k1", name: "coincurve / python-bitcoin",        sev: "high", re: /import\s+coincurve\b|coincurve\.(?:PublicKey|PrivateKey)|from\s+bitcoinlib\s+import.*(?:Key|sign)/i, alt: "ML-DSA (CRYSTALS-Dilithium)" },
  { id: "rust-secp256k1-crate",name: "Rust secp256k1 / k256 crate",      sev: "high", re: /use\s+secp256k1::|use\s+k256::|Secp256k1::new\s*\(|SecretKey::from_slice\s*\(|SigningKey::from_bytes\s*\(/i, alt: "ML-DSA via pqcrypto-dilithium crate" },
  { id: "tronweb-wallet",      name: "TronWeb wallet (secp256k1)",        sev: "high", re: /TronWeb\.createAccount\s*\(|tronWeb\.createAccount|tronWeb\.address\.fromPrivateKey/i, alt: "Monitor TRON PQC roadmap" },
  // HIGH — Java JCA / SSH library false-negative fixes (2026-06-04)
  { id: "java-jca-rsa",        name: "Java JCA RSA getInstance",              sev: "high", re: /(?:KeyPairGenerator|KeyFactory|Cipher|KeyGenerator)\.getInstance\s*\(\s*["']RSA["']/i, alt: "ML-KEM-768 (NIST FIPS 203)" },
  { id: "java-jca-sig",        name: "Java JCA RSA/ECDSA Signature",          sev: "high", re: /Signature\.getInstance\s*\(\s*["'][^"']*(?:withRSA|withECDSA|withDSA)[^"']*["']/i, alt: "ML-DSA-65 (NIST FIPS 204)" },
  { id: "java-ssh-mina-jsch",  name: "Apache MINA SSHD / JSch client",        sev: "high", re: /SshClient\.setUpDefaultClient\s*\(|new\s+JSch\s*\(|\.setKeyPairProvider\s*\(|SshServer\.setUpDefaultServer\s*\(/i, alt: "Monitor OpenSSH PQC KEX: mlkem768x25519-sha256" },
  { id: "csharp-ssh-net",      name: "SSH.NET SshClient / PrivateKeyFile",     sev: "high", re: /new\s+SshClient\s*\(|new\s+SftpClient\s*\(|new\s+PrivateKeyFile\s*\(|new\s+RsaKey\s*\(/i, alt: "Monitor OpenSSH PQC roadmap" },
  { id: "csharp-rsa-cng",      name: "C# RSACng / ECDsaCng (CNG APIs)",        sev: "high", re: /new\s+RSACng\s*\(|new\s+ECDsaCng\s*\(|new\s+DSACng\s*\(|AsymmetricAlgorithm\.Create\s*\(/i, alt: "ML-KEM-768 or ML-DSA-65 via NIST FIPS 203/204" },
  { id: "go-crypto-rsa",       name: "Go stdlib RSA/ECDSA keygen",             sev: "high", re: /rsa\.GenerateKey\s*\(|ecdsa\.GenerateKey\s*\(|rsa\.EncryptPKCS1v15\s*\(|rsa\.SignPKCS1v15\s*\(|rsa\.DecryptPKCS1v15\s*\(/i, alt: "ML-KEM-768 via golang.org/x/crypto/mlkem (FIPS 203)" },
  { id: "rust-ring",           name: "Rust ring RSA/ECDSA signatures",         sev: "high", re: /ring::signature::(?:RSA_PKCS1|ECDSA_P(?:256|384))|RsaKeyPair::from_pkcs8\s*\(|EcdsaKeyPair::from_pkcs8\s*\(/i, alt: "pqcrypto-dilithium or ml-dsa crate" },
  { id: "python-paramiko-key", name: "Paramiko RSA/ECDSA key operations",      sev: "high", re: /paramiko\.RSAKey\b|paramiko\.ECDSAKey\b|RSAKey\.generate\s*\(|ECDSAKey\.generate\s*\(|paramiko\.DSSKey\b/i, alt: "Monitor OpenSSH PQC roadmap" },
  // LOW — informational
  { id: "hardcoded-key",name: "Hardcoded key",            sev: "low",      re: /(?:private_key|secret_key|encryption_key|aes_key|rsa_key)\s*=\s*["'][^"']{16,}["']|-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/i },
  { id: "crc32",        name: "CRC32 for integrity",      sev: "low",      re: /crc32.*(?:integrity|verify|validate)|(?:integrity|verify|validate).*crc32|CRC32C?\.(?:compute|calculate|verify)/i, alt: "SHA-256 or BLAKE3" },
  { id: "sha256-kdf",   name: "SHA-256 as password KDF",  sev: "low",      re: /sha256.*(?:password|passphrase)\b|(?:password|passphrase).*sha256/i, alt: "Argon2id or bcrypt" },
  { id: "dh-1024",      name: "DH 1024-bit params",       sev: "low",      re: /DHParameterSpec\s*\(\s*1024|generate_parameters.*1024|dhparam\s+1024/i, alt: "ML-KEM" },
];

// ── Vulnerable dependencies ───────────────────────────────────────────────────
const VULNERABLE_DEPS = [
  // npm / package.json
  { pkg: "node-forge",       eco: "npm",    sev: "high",     reason: "RSA/ECDSA/DH crypto library",               alt: "Web Crypto API + liboqs-js" },
  { pkg: "jsrsasign",        eco: "npm",    sev: "high",     reason: "RSA/ECDSA/DSA signatures",                  alt: "ml-dsa" },
  { pkg: "elliptic",         eco: "npm",    sev: "high",     reason: "Elliptic curve crypto (secp256k1, P-256)",   alt: "ml-kem / ml-dsa" },
  { pkg: "secp256k1",        eco: "npm",    sev: "high",     reason: "secp256k1 curve (Shor-vulnerable)",         alt: "ml-dsa for signatures" },
  { pkg: "bitcoinjs-lib",    eco: "npm",    sev: "high",     reason: "secp256k1 Bitcoin transactions",            alt: "Monitor BIP-360 draft" },
  { pkg: "@noble/secp256k1", eco: "npm",    sev: "high",     reason: "secp256k1 (Shor-vulnerable)",               alt: "ml-dsa" },
  { pkg: "noble-secp256k1",  eco: "npm",    sev: "high",     reason: "secp256k1",                                 alt: "ml-dsa" },
  { pkg: "@noble/curves",    eco: "npm",    sev: "high",     reason: "ECC curves including secp256k1 and P-256",  alt: "ml-kem / ml-dsa" },
  { pkg: "jose",             eco: "npm",    sev: "medium",   reason: "Supports RS256/ES256 JWT algorithms",       alt: "Use HS256 only until PQC JOSE RFC" },
  { pkg: "jsonwebtoken",     eco: "npm",    sev: "medium",   reason: "RS256/ES256 JWT by default",                alt: "Use HS256 algorithms only" },
  { pkg: "ssh2",             eco: "npm",    sev: "high",     reason: "RSA/ECDSA SSH host keys",                   alt: "Monitor OpenSSH PQC roadmap" },
  { pkg: "forge",            eco: "npm",    sev: "high",     reason: "Alias for node-forge — RSA/ECDSA",          alt: "Web Crypto API + liboqs-js" },
  // Python / requirements.txt
  { pkg: "ecdsa",            eco: "python", sev: "critical", reason: "Pure ECDSA — named after the broken algo",  alt: "pqcrypto (dilithium)" },
  { pkg: "python-ecdsa",     eco: "python", sev: "critical", reason: "Pure ECDSA implementation",                alt: "pqcrypto (dilithium)" },
  { pkg: "pyOpenSSL",        eco: "python", sev: "high",     reason: "RSA/ECDSA TLS operations",                 alt: "Monitor OpenSSL PQC roadmap" },
  { pkg: "pyjwt",            eco: "python", sev: "medium",   reason: "RS256/ES256/PS256 JWT support",            alt: "Use HS256 algorithms only" },
  { pkg: "python-jose",      eco: "python", sev: "medium",   reason: "RSA/ECDSA JWT",                            alt: "Use HS256 only" },
  { pkg: "paramiko",         eco: "python", sev: "high",     reason: "RSA/ECDSA SSH transport",                  alt: "Monitor OpenSSH PQC roadmap" },
  { pkg: "eth-account",      eco: "python", sev: "high",     reason: "secp256k1 Ethereum accounts",              alt: "Monitor ethereum PQC roadmap" },
  { pkg: "coincurve",        eco: "python", sev: "high",     reason: "secp256k1 Python bindings",                alt: "pqcrypto (dilithium)" },
  // Java / pom.xml (groupId prefix match)
  { pkg: "org.bouncycastle", eco: "maven",  sev: "high",     reason: "RSA/ECDSA/DSA — use bcpqc for PQC",        alt: "Upgrade to bcpqc jar (Bouncy Castle PQC)" },
  { pkg: "org.apache.sshd", eco: "maven",  sev: "high",     reason: "Apache MINA SSHD — RSA/ECDSA host keys & auth", alt: "Monitor Apache MINA PQC roadmap; prefer mlkem768x25519 KEX" },
  { pkg: "com.jcraft",      eco: "maven",  sev: "high",     reason: "JSch — RSA/ECDSA SSH transport",               alt: "Monitor OpenSSH PQC roadmap" },
  { pkg: "net.schmizz",     eco: "maven",  sev: "high",     reason: "sshj — RSA/ECDSA SSH transport",               alt: "Monitor PQC KEX support in sshj" },
  { pkg: "io.jsonwebtoken",  eco: "maven",  sev: "medium",   reason: "RS256/ES256 JWT",                          alt: "Use HS256 algorithms only" },
  { pkg: "com.auth0:java-jwt",eco: "maven", sev: "medium",   reason: "RSA/ECDSA JWT support",                    alt: "Use HMAC algorithms only" },
  // Go / go.mod
  { pkg: "golang.org/x/crypto", eco: "go", sev: "medium",   reason: "Contains Ed25519, x/crypto/ssh, ECDH",     alt: "stdlib crypto/ecdh; await Go stdlib ML-KEM" },
  // Rust / Cargo.toml
  { pkg: "rsa",              eco: "rust",   sev: "high",     reason: "RSA crate (Shor-vulnerable)",              alt: "pqcrypto-kyber or oqs-rs" },
  { pkg: "ecdsa",            eco: "rust",   sev: "high",     reason: "ECDSA crate",                              alt: "pqcrypto-dilithium" },
  { pkg: "secp256k1",        eco: "rust",   sev: "high",     reason: "secp256k1 crate",                          alt: "pqcrypto-dilithium" },
  { pkg: "k256",             eco: "rust",   sev: "high",     reason: "k256 (secp256k1) crate",                   alt: "pqcrypto-dilithium" },
  { pkg: "p256",             eco: "rust",   sev: "high",     reason: "p256 (NIST P-256) crate",                  alt: "pqcrypto-dilithium" },
  { pkg: "ed25519-dalek",    eco: "rust",   sev: "high",     reason: "Ed25519 (Shor-vulnerable)",                alt: "ML-DSA via pqcrypto-dilithium" },
  { pkg: "x25519-dalek",     eco: "rust",   sev: "high",     reason: "X25519 key exchange (Shor-vulnerable)",    alt: "ML-KEM via pqcrypto-kyber" },
  { pkg: "ring",             eco: "rust",   sev: "high",     reason: "ring crate — RSA/ECDSA/ECDH operations",   alt: "pqcrypto-kyber for KEM; pqcrypto-dilithium for signatures" },
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
const IGNORE_MARKER = "quantumscan-ignore";

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
    if (!trimmed) continue;

    // Skip pure comment lines (they're not executable)
    if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) continue;

    // quantumscan-ignore on this line or previous line
    if (line.includes(IGNORE_MARKER)) continue;
    if (i > 0 && lines[i - 1].includes(IGNORE_MARKER)) continue;

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
          type: "code",
        });
        break; // one finding per line
      }
    }
  }
  return findings;
}

// ── Dependency scanner ────────────────────────────────────────────────────────
function normPkg(name) { return name.trim().toLowerCase().replace(/_/g, "-"); }

function matchDep(pkg, eco) {
  const n = normPkg(pkg);
  return VULNERABLE_DEPS.filter(d => d.eco === eco && (
    normPkg(d.pkg) === n ||
    (eco === "maven" && n.startsWith(normPkg(d.pkg)))
  ));
}

function scanPackageJson(filePath, rootDir) {
  const findings = [];
  let json;
  try { json = JSON.parse(readFileSync(filePath, "utf8")); } catch { return []; }
  const relPath = relative(rootDir, filePath).replace(/\\/g, "/");
  const allDeps = { ...json.dependencies, ...json.devDependencies };
  for (const [pkg] of Object.entries(allDeps)) {
    for (const d of matchDep(pkg, "npm")) {
      findings.push({ file: relPath, line: 1, id: `dep/${d.pkg}`, name: `Dep: ${pkg}`, sev: d.sev, match: pkg, alt: d.alt, reason: d.reason, type: "dependency" });
    }
  }
  return findings;
}

function scanRequirementsTxt(filePath, rootDir) {
  const findings = [];
  let content;
  try { content = readFileSync(filePath, "utf8"); } catch { return []; }
  const relPath = relative(rootDir, filePath).replace(/\\/g, "/");
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].trim();
    if (!raw || raw.startsWith("#")) continue;
    // strip version specifier: pkg==1.0, pkg>=1.0, pkg[extra]
    const pkg = raw.replace(/\[.*?\]/, "").split(/[=<>!;@\s]/)[0].trim();
    if (!pkg) continue;
    for (const d of matchDep(pkg, "python")) {
      findings.push({ file: relPath, line: i + 1, id: `dep/${d.pkg}`, name: `Dep: ${pkg}`, sev: d.sev, match: raw.substring(0, 60), alt: d.alt, reason: d.reason, type: "dependency" });
    }
  }
  return findings;
}

function scanGoMod(filePath, rootDir) {
  const findings = [];
  let content;
  try { content = readFileSync(filePath, "utf8"); } catch { return []; }
  const relPath = relative(rootDir, filePath).replace(/\\/g, "/");
  const lines = content.split("\n");
  let inRequire = false;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].trim();
    if (raw === "require (") { inRequire = true; continue; }
    if (inRequire && raw === ")") { inRequire = false; continue; }
    if (raw.startsWith("require ") || inRequire) {
      const pkg = raw.replace(/^require\s+/, "").split(/\s/)[0].trim();
      if (!pkg) continue;
      for (const d of matchDep(pkg, "go")) {
        findings.push({ file: relPath, line: i + 1, id: `dep/${d.pkg}`, name: `Dep: ${pkg}`, sev: d.sev, match: raw.substring(0, 60), alt: d.alt, reason: d.reason, type: "dependency" });
      }
    }
  }
  return findings;
}

function scanCargoToml(filePath, rootDir) {
  const findings = [];
  let content;
  try { content = readFileSync(filePath, "utf8"); } catch { return []; }
  const relPath = relative(rootDir, filePath).replace(/\\/g, "/");
  const lines = content.split("\n");
  let inDeps = false;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].trim();
    if (raw === "[dependencies]" || raw === "[dev-dependencies]") { inDeps = true; continue; }
    if (raw.startsWith("[") && raw.endsWith("]")) { inDeps = false; continue; }
    if (inDeps && raw && !raw.startsWith("#")) {
      const pkg = raw.split(/\s*[=\s]/)[0].trim();
      for (const d of matchDep(pkg, "rust")) {
        findings.push({ file: relPath, line: i + 1, id: `dep/${d.pkg}`, name: `Dep: ${pkg}`, sev: d.sev, match: raw.substring(0, 60), alt: d.alt, reason: d.reason, type: "dependency" });
      }
    }
  }
  return findings;
}

function scanPomXml(filePath, rootDir) {
  const findings = [];
  let content;
  try { content = readFileSync(filePath, "utf8"); } catch { return []; }
  const relPath = relative(rootDir, filePath).replace(/\\/g, "/");
  // Extract groupId + artifactId pairs
  const depRe = /<dependency>[\s\S]*?<groupId>(.*?)<\/groupId>[\s\S]*?<artifactId>(.*?)<\/artifactId>[\s\S]*?<\/dependency>/g;
  let m;
  while ((m = depRe.exec(content)) !== null) {
    const coord = `${m[1].trim()}:${m[2].trim()}`;
    const lineNum = content.substring(0, m.index).split("\n").length;
    for (const d of matchDep(coord, "maven")) {
      findings.push({ file: relPath, line: lineNum, id: `dep/${d.pkg}`, name: `Dep: ${coord}`, sev: d.sev, match: coord.substring(0, 60), alt: d.alt, reason: d.reason, type: "dependency" });
    }
    // also check groupId alone for prefix matches
    for (const d of matchDep(m[1].trim(), "maven")) {
      if (!findings.find(f => f.name === `Dep: ${coord}` && f.id === `dep/${d.pkg}`)) {
        findings.push({ file: relPath, line: lineNum, id: `dep/${d.pkg}`, name: `Dep: ${coord}`, sev: d.sev, match: coord.substring(0, 60), alt: d.alt, reason: d.reason, type: "dependency" });
      }
    }
  }
  return findings;
}

// pyproject.toml (modern Python — PEP 517/518)
function scanPyprojectToml(filePath, rootDir) {
  const findings = [];
  let content;
  try { content = readFileSync(filePath, "utf8"); } catch { return []; }
  const relPath = relative(rootDir, filePath).replace(/\\/g, "/");
  const lines = content.split("\n");
  let inDeps = false;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (/^\s*dependencies\s*=/.test(raw)) { inDeps = true; continue; }
    if (inDeps && /^\s*\]/.test(raw)) { inDeps = false; continue; }
    if (inDeps && raw.trim() && !raw.trim().startsWith("#")) {
      const m = raw.match(/["']([A-Za-z0-9][A-Za-z0-9._-]*)/);
      if (m) {
        const pkg = m[1].replace(/_/g, "-").toLowerCase();
        for (const d of matchDep(pkg, "python")) {
          findings.push({ file: relPath, line: i + 1, id: `dep/${d.pkg}`, name: `Dep: ${m[1]}`, sev: d.sev, match: raw.trim().substring(0, 60), alt: d.alt, reason: d.reason, type: "dependency" });
        }
      }
    }
  }
  return findings;
}

// setup.py (legacy Python — install_requires=[...])
function scanSetupPy(filePath, rootDir) {
  const findings = [];
  let content;
  try { content = readFileSync(filePath, "utf8"); } catch { return []; }
  const relPath = relative(rootDir, filePath).replace(/\\/g, "/");
  const lines = content.split("\n");
  let inRequires = false;
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (/install_requires\s*=\s*\[/.test(raw)) { inRequires = true; }
    if (inRequires && /^\s*\]/.test(raw) && !raw.includes("[")) { inRequires = false; continue; }
    if (inRequires) {
      const m = raw.match(/["']([A-Za-z0-9][A-Za-z0-9._-]*)/);
      if (m) {
        const pkg = m[1].replace(/_/g, "-").toLowerCase();
        for (const d of matchDep(pkg, "python")) {
          findings.push({ file: relPath, line: i + 1, id: `dep/${d.pkg}`, name: `Dep: ${m[1]}`, sev: d.sev, match: raw.trim().substring(0, 60), alt: d.alt, reason: d.reason, type: "dependency" });
        }
      }
    }
  }
  return findings;
}

function scanDependencies(rootDir) {
  const allFindings = [];
  const manifests = [
    { name: "package.json",      fn: scanPackageJson },
    { name: "requirements.txt",  fn: scanRequirementsTxt },
    { name: "pyproject.toml",    fn: scanPyprojectToml },
    { name: "setup.py",          fn: scanSetupPy },
    { name: "go.mod",            fn: scanGoMod },
    { name: "Cargo.toml",        fn: scanCargoToml },
    { name: "pom.xml",           fn: scanPomXml },
  ];
  // Walk the directory to find manifest files (top-level + one level deep)
  const dirs = [rootDir];
  try {
    for (const e of readdirSync(rootDir, { withFileTypes: true })) {
      if (e.isDirectory() && !SKIP_DIRS.has(e.name)) dirs.push(join(rootDir, e.name));
    }
  } catch {}

  const seen = new Set();
  for (const dir of dirs) {
    for (const { name, fn } of manifests) {
      const fp = join(dir, name);
      if (!seen.has(fp) && existsSync(fp)) {
        seen.add(fp);
        allFindings.push(...fn(fp, rootDir));
      }
    }
  }
  return allFindings;
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

function printResults(findings, totalFiles, scannableCount, targetDir, score, depCount) {
  console.log(`\n${C.bold}QuantumScan v${VERSION}${C.reset}  Post-Quantum Cryptography Scanner`);
  console.log(`${C.cyan}${APP_URL}${C.reset}`);
  console.log(hr());
  console.log(`Path     ${C.bold}${targetDir}${C.reset}`);
  console.log(`Files    ${C.gray}${totalFiles} total · ${scannableCount} scannable${C.reset}`);
  if (depCount > 0) console.log(`Deps     ${C.gray}${depCount} vulnerable package(s) found${C.reset}`);
  console.log("");

  if (findings.length === 0) {
    console.log(`${C.green}✓  No cryptographic vulnerabilities detected.${C.reset}`);
    console.log(`   Your codebase looks quantum-safe based on static patterns.\n`);
  } else {
    const codeFindings = findings.filter(f => f.type !== "dependency");
    const depFindings  = findings.filter(f => f.type === "dependency");

    if (codeFindings.length > 0) {
      const grouped = {};
      for (const sev of SEV_ORDER) grouped[sev] = codeFindings.filter(f => f.sev === sev);
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

    if (depFindings.length > 0) {
      console.log(`${C.orange}${C.bold}📦 DEPENDENCIES  ${C.reset}${C.gray}${depFindings.length} vulnerable package(s)${C.reset}`);
      for (const f of depFindings.slice(0, 20)) {
        const loc  = `  ${f.file}`;
        const name = sevColor(f.sev) + f.match + C.reset;
        const why  = f.reason ? `  ${C.dim}${f.reason}${C.reset}` : "";
        console.log(`${padEnd(loc, 34)}${padEnd(name, 30)}${why}`);
        if (f.alt) console.log(`  ${C.gray}  → ${f.alt}${C.reset}`);
      }
      if (depFindings.length > 20) console.log(`  ${C.gray}… +${depFindings.length - 20} more${C.reset}`);
      console.log("");
    }
  }

  console.log(hr());
  console.log(`Risk Score  ${C.bold}${score}/100${C.reset}  ${riskLabel(score)}`);

  if (findings.length > 0) {
    console.log(`\n${C.dim}Migrate to: ML-KEM (key encap, FIPS 203) · ML-DSA (signatures, FIPS 204)${C.reset}`);
    console.log(`${C.dim}Required by NIST, DORA, NIS2, CNSA 2.0 — deadline 2030.${C.reset}`);
    console.log(`\n${C.cyan}Full AI analysis + migration guides → ${APP_URL}${C.reset}`);
    console.log(`${C.dim}Add ${C.reset}${C.bold}// quantumscan-ignore${C.reset}${C.dim} to suppress a false positive.${C.reset}`);
  }
  console.log("");
}

// ── JSON output ───────────────────────────────────────────────────────────────
function printJson(findings, totalFiles, scannableCount, targetDir, score) {
  const summary = { riskScore: score };
  for (const sev of SEV_ORDER) summary[sev] = findings.filter(f => f.sev === sev).length;
  summary.dependencies = findings.filter(f => f.type === "dependency").length;
  console.log(JSON.stringify({
    version: VERSION,
    path: targetDir,
    stats: { totalFiles, scannableFiles: scannableCount },
    summary,
    findings: findings.map(f => ({
      file: f.file, line: f.line,
      type: f.type ?? "code",
      algorithm: f.name, severity: f.sev,
      match: f.match, pqcAlternative: f.alt,
      reason: f.reason ?? undefined,
    })),
  }, null, 2));
}

// ── SARIF output ──────────────────────────────────────────────────────────────
function sevToSarif(sev) {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}

function printSarif(findings, targetDir) {
  // Build rules from unique pattern IDs
  const ruleMap = new Map();
  for (const p of PATTERNS) {
    ruleMap.set(p.id, {
      id: `QS/${p.id}`,
      name: p.name.replace(/[^a-zA-Z0-9]/g, ""),
      shortDescription: { text: p.name },
      fullDescription: { text: `${p.name} is quantum-vulnerable${p.alt ? `. Migrate to: ${p.alt}` : ""}.` },
      helpUri: `${APP_URL}/why-now`,
      defaultConfiguration: { level: sevToSarif(p.sev) },
      properties: { tags: ["security", "pqc", "quantum", p.sev], severity: p.sev },
    });
  }
  // Add dep rule
  ruleMap.set("dep", {
    id: "QS/dep",
    name: "VulnerableDependency",
    shortDescription: { text: "Quantum-vulnerable dependency" },
    fullDescription: { text: "A dependency uses quantum-vulnerable cryptography (RSA, ECDSA, or similar)." },
    helpUri: `${APP_URL}/why-now`,
    defaultConfiguration: { level: "warning" },
    properties: { tags: ["security", "pqc", "dependency"] },
  });

  const results = findings.map(f => {
    const ruleId = f.type === "dependency" ? "QS/dep" : `QS/${f.id}`;
    const msg = f.type === "dependency"
      ? `${f.match}: ${f.reason}${f.alt ? ` — migrate to: ${f.alt}` : ""}`
      : `${f.name} detected${f.match ? ` (\`${f.match}\`)` : ""}${f.alt ? `. Migrate to: ${f.alt}` : ""}. Deadline: NIST/DORA/NIS2 2030.`;
    return {
      ruleId,
      level: sevToSarif(f.sev),
      message: { text: msg },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: f.file, uriBaseId: "%SRCROOT%" },
          region: { startLine: f.line },
        },
      }],
    };
  });

  const sarif = {
    version: "2.1.0",
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "QuantumScan",
          version: VERSION,
          informationUri: APP_URL,
          rules: [...ruleMap.values()],
        },
      },
      originalUriBaseIds: { "%SRCROOT%": { uri: `file:///${targetDir.replace(/\\/g, "/")}/` } },
      results,
    }],
  };
  console.log(JSON.stringify(sarif, null, 2));
}

// ── Badge helper ──────────────────────────────────────────────────────────────
function detectRepoSlug(dir) {
  try {
    const remote = execSync("git remote get-url origin", { cwd: dir, stdio: ["pipe","pipe","pipe"] })
      .toString().trim();
    const m = remote.match(/github\.com[:/]([^/]+\/[^/]+?)(?:\.git)?$/i);
    return m ? m[1].toLowerCase() : null;
  } catch { return null; }
}

function printBadge(slug) {
  const badgeUrl = `https://quantumscan.io/api/badge/${slug}.svg`;
  const scanUrl  = `https://quantumscan.io/en/scan`;
  console.log(`\n${C.cyan}README badge (add to your README.md):${C.reset}`);
  console.log(`${C.bold}[![QuantumScan](${badgeUrl})](${scanUrl})${C.reset}`);
  console.log(`${C.dim}(score reflects last cloud scan at quantumscan.io)${C.reset}\n`);
}

// ── CLI ───────────────────────────────────────────────────────────────────────
const HELP = `
Usage: npx quantumscan [path] [options]

  path               Directory to scan (default: current directory)

Options:
  --json             Output results as JSON (for CI/CD pipelines)
  --sarif            Output results as SARIF 2.1.0 (GitHub Security tab)
  --no-deps          Skip dependency scanning (package.json, requirements.txt…)
  --badge            Print README badge markdown after scan
  --no-fail          Exit 0 even when findings are found (default: exit 1)
  --version          Show version
  --help             Show this help

Suppressing false positives:
  Add  // quantumscan-ignore  (or  # quantumscan-ignore  ) at end of a line
  to suppress that finding. Works in all supported languages.

Examples:
  npx quantumscan .
  npx quantumscan ./src --json
  npx quantumscan . --sarif > results.sarif
  npx quantumscan . --badge
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

  const jsonMode  = args.includes("--json");
  const sarifMode = args.includes("--sarif");
  const badgeMode = args.includes("--badge");
  const noDeps    = args.includes("--no-deps");
  const noFail    = args.includes("--no-fail");
  const pathArg   = args.find(a => !a.startsWith("-")) ?? ".";

  let targetDir;
  try {
    targetDir = resolve(pathArg);
    statSync(targetDir);
  } catch {
    console.error(`Error: path not found — ${pathArg}`);
    exit(2);
  }

  const silent = jsonMode || sarifMode;
  if (!silent) process.stdout.write(`Scanning ${targetDir} ...\r`);

  let allFiles;
  const st = statSync(targetDir);
  if (st.isFile()) {
    allFiles = [targetDir];
    targetDir = resolve(pathArg, "..");
  } else {
    allFiles = walkDir(targetDir);
  }

  const scannableFiles  = allFiles.filter(f => SCANNABLE_EXTS.has(extname(f).toLowerCase()));
  const codeFindings    = scannableFiles.flatMap(f => scanFile(f, targetDir));
  const depFindings     = noDeps ? [] : scanDependencies(targetDir);
  const allFindings     = [...codeFindings, ...depFindings];
  const score           = calcScore(allFindings);

  if (sarifMode) {
    printSarif(allFindings, targetDir);
  } else if (jsonMode) {
    printJson(allFindings, allFiles.length, scannableFiles.length, targetDir, score);
  } else {
    printResults(allFindings, allFiles.length, scannableFiles.length, targetDir, score, depFindings.length);
    if (badgeMode) {
      const slug = detectRepoSlug(targetDir);
      if (slug) printBadge(slug);
      else console.log(`\n${C.dim}--badge: could not detect GitHub remote.${C.reset}\n`);
    }
  }

  exit(noFail || allFindings.length === 0 ? 0 : 1);
}

main();
