import { readdirSync, readFileSync, statSync, existsSync } from "fs";
import { execSync } from "child_process";
import { join, extname, relative, resolve, basename } from "path";
import { argv, exit } from "process";

const VERSION = "1.9.0";
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
  { id: "ssl-v2-v3",    name: "SSLv2 / SSLv3",           sev: "critical", re: /SSLv[23]|SSL_OP_NO_SSLv[23]|PROTOCOL_SSLv[23]/i }, // quantumscan-ignore
  { id: "tls-old",      name: "TLS 1.0 / 1.1",           sev: "critical", re: /TLSv1(?:\.0|\.1)?\b|PROTOCOL_TLSv1(?:_1)?\b|ssl\.TLSv1\b|SslProtocols\.(?:Tls|Tls11)\b/i }, // quantumscan-ignore
  { id: "md5",          name: "MD5",                      sev: "critical", re: /\bMD5\b|md5\(|hashlib\.md5|MessageDigest\.getInstance\s*\(\s*["']MD5["']\)|new\s+MD5(?:CryptoServiceProvider)?\s*\(|MD5CryptoServiceProvider\b/i, alt: "SHA3-256 or SHA-256" }, // quantumscan-ignore
  { id: "sha1",         name: "SHA-1",                    sev: "critical", re: /\bSHA1\b|\bsha1\s*\(|hashlib\.sha1\b|MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']\)|new\s+SHA1CryptoServiceProvider\s*\(|SHA1CryptoServiceProvider\b/i, alt: "SHA-256" }, // quantumscan-ignore
  { id: "des",          name: "DES",                      sev: "critical", re: /\bDES\b(?!C?SHA|\s*ede)|DESKeySpec|DES\.new\b|DESCryptoServiceProvider\b|Cipher\.getInstance\s*\(\s*["']DES[/"']/i }, // quantumscan-ignore
  { id: "3des",         name: "3DES / TripleDES",         sev: "critical", re: /3DES|TripleDES|DESede|DES_EDE|des3_cbc|des-ede3/i }, // quantumscan-ignore
  { id: "rc4",          name: "RC4",                      sev: "critical", re: /\bRC4\b|ARCFOUR|ARC4\b|arcfour|Cipher\.getInstance\s*\(\s*["']RC4/i }, // quantumscan-ignore
  { id: "ecb",          name: "AES-ECB (no IV)",          sev: "critical", re: /\/ECB\/|AES\.MODE_ECB|CipherMode\.ECB\b|Cipher\.getInstance\s*\(\s*["']AES["']|["']AES\/ECB/i, alt: "AES-GCM or ChaCha20-Poly1305" }, // quantumscan-ignore
  { id: "rc2",          name: "RC2",                      sev: "critical", re: /\bRC2\b|RC2KeySpec|RC2ParameterSpec/i }, // quantumscan-ignore
  { id: "nullcipher",   name: "NullCipher",               sev: "critical", re: /NullCipher|javax\.crypto\.NullCipher/i }, // quantumscan-ignore
  // HIGH — quantum-vulnerable (Shor's algorithm)
  { id: "rsa",          name: "RSA",                      sev: "high",     re: /RSA(?:Key(?:Pair)?|PublicKey|PrivateKey|Generator|Encryptor|Decryptor|Signature|CryptoServiceProvider)?(?:\s*\(|\s*\.\s*(?:generate|new|create|load|import))\b|RSACryptoServiceProvider\b|generateRSA|Rsa(?:Private|Public|Key|KeyPairGenerator)|PKCS1_(?:v1_5|OAEP)|import_rsa_key|openssl_pkey_new/i, alt: "ML-KEM (CRYSTALS-Kyber)" }, // quantumscan-ignore
  { id: "rsa-small",    name: "RSA key ≤2048 bits",       sev: "critical", re: /rsa.*\b(512|768|1024|1536|2048)\b|\bkey(?:_size|Size|Bits)\s*[=:]\s*(512|768|1024|1536|2048)\b|generateKeyPair\s*\(\s*(512|768|1024|1536|2048)/i }, // quantumscan-ignore
  { id: "ecdsa",        name: "ECDSA",                    sev: "high",     re: /\bECDSA\b|ECDsa\.Create\s*\(|ECDSASignature|ecdsa_(?:sign|verify)|ES(?:256|384|512)\b/i, alt: "ML-DSA (CRYSTALS-Dilithium)" }, // quantumscan-ignore
  { id: "ecdh",         name: "ECDH / ECDHE",             sev: "high",     re: /\bECDH\b|\bECDHE\b|ECKeyAgreement|ecdh_(?:generate|compute)|TLS_ECDHE/i, alt: "ML-KEM (CRYSTALS-Kyber)" }, // quantumscan-ignore
  { id: "dsa",          name: "DSA",                      sev: "high",     re: /\bDSA\b(?!SHA|_KEY_SIZE|Version)|DSA\.Create\s*\(|DSAKeySpec|DSAPublicKey|DSAPrivateKey|DSASignature|DSACryptoServiceProvider\b|DsaKeyPairGenerator\b/i, alt: "ML-DSA (CRYSTALS-Dilithium)" }, // quantumscan-ignore
  { id: "dh",           name: "Diffie-Hellman",           sev: "high",     re: /\bDHKey\b|\bDiffieHellman\b|DHKeyExchange|DHParameterSpec|DH\.new\b/i, alt: "ML-KEM (CRYSTALS-Kyber)" }, // quantumscan-ignore
  { id: "p256",         name: "NIST P-256",               sev: "high",     re: /\bP-?256\b|prime256v1|secp256r1|NamedCurve\.P_?256/i, alt: "ML-KEM or ML-DSA" }, // quantumscan-ignore
  { id: "p384",         name: "NIST P-384",               sev: "high",     re: /\bP-?384\b|secp384r1|NamedCurve\.P_?384/i, alt: "ML-KEM or ML-DSA" }, // quantumscan-ignore
  { id: "p521",         name: "NIST P-521",               sev: "high",     re: /\bP-?521\b|secp521r1|NamedCurve\.P_?521/i }, // quantumscan-ignore
  { id: "secp256k1",    name: "secp256k1",                sev: "high",     re: /secp256k1|SECP256K1/i }, // quantumscan-ignore
  { id: "ed25519",      name: "Ed25519 / EdDSA",          sev: "high",     re: /\bEd25519\b|Edwards25519|EdDSA\b/i, alt: "ML-DSA or SLH-DSA" }, // quantumscan-ignore
  { id: "x25519",       name: "X25519 / Curve25519",      sev: "high",     re: /\bX25519\b|Curve25519|curve25519/i, alt: "ML-KEM (CRYSTALS-Kyber)" }, // quantumscan-ignore
  { id: "jwt-alg",      name: "JWT quantum-vuln alg",     sev: "high",     re: /algorithm["'\s:]+["'](RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA)["']/i, alt: "HS256 or post-quantum signature" }, // quantumscan-ignore
  { id: "pkcs1",        name: "PKCS#1 (RSA)",             sev: "high",     re: /PKCS1\b|pkcs#1|BEGIN RSA PRIVATE KEY|RSAPrivateKey_format/i }, // quantumscan-ignore
  { id: "ecc",          name: "ECC generic",              sev: "high",     re: /EllipticCurve|ECGenParameterSpec|ECPublicKey|ECPrivateKey|ECKeyPairGenerator\b|EcKey\b|ec\.generate_private_key/i }, // quantumscan-ignore
  { id: "x509-gen",     name: "X.509 cert generation",    sev: "high",     re: /X509(?:Certificate)?Builder.*sign|createSelfSigned|makeCertificate|X509\.new\b/i }, // quantumscan-ignore
  // MEDIUM — weak or concerning
  { id: "aes128",       name: "AES-128",                  sev: "medium",   re: /AES[-_]?128|AES\b.*\b128\b|KeySize\s*\(\s*128\s*\)|aes_128/i, alt: "AES-256" }, // quantumscan-ignore
  { id: "cbc",          name: "CBC mode",                 sev: "medium",   re: /\/CBC\/|AES\.MODE_CBC|aes_cbc\b|MODE_CBC/i, alt: "AES-GCM or ChaCha20-Poly1305" }, // quantumscan-ignore
  { id: "hmacsha1",     name: "HMAC-SHA1",                sev: "medium",   re: /HMAC[-_]?SHA1|HmacSHA1|hmac_sha1|Mac\.getInstance\s*\(\s*["']HmacSHA1["']\)/i, alt: "HMAC-SHA256" }, // quantumscan-ignore
  { id: "pbkdf2-low",   name: "PBKDF2 low iterations",    sev: "medium",   re: /PBKDF2.*\b(100|500|1000|5000|10000)\b|iterationCount\s*[=:]\s*\d{1,4}\b/i, alt: "Argon2id" }, // quantumscan-ignore
  { id: "blowfish",     name: "Blowfish",                 sev: "medium",   re: /\bBlowfish\b|bf_cbc|BF_KEY\b|AES\.MODE_BF/i }, // quantumscan-ignore
  { id: "math-random",  name: "Math.random in crypto",    sev: "medium",   re: /Math\.random\(\)\s*.*(?:key|token|nonce|salt|iv|secret)|(?:key|token|nonce|salt|iv|secret).*Math\.random\(\)/i, alt: "crypto.getRandomValues()" }, // quantumscan-ignore
  { id: "openssl-old",  name: "OpenSSL < 3.x",            sev: "medium",   re: /OpenSSL\s+1\.[01]\.|libssl\.so\.1\.|openssl-1\.[01]\./i }, // quantumscan-ignore
  // BLOCKCHAIN
  { id: "ethers-wallet",       name: "ethers.js Wallet (secp256k1)",       sev: "high", re: /new\s+ethers\.Wallet\s*\(|Wallet\.createRandom\s*\(|Wallet\.fromMnemonic\s*\(|Wallet\.fromPhrase\s*\(/i, alt: "Monitor Ethereum PQC roadmap (EIP-7786)" }, // quantumscan-ignore
  { id: "web3-accounts",       name: "web3.js / viem accounts (secp256k1)",sev: "high", re: /web3\.eth\.accounts\.|accounts\.create\s*\(|privateKeyToAccount\s*\(|createWalletClient\s*\(|generatePrivateKey\s*\(\)/i, alt: "Monitor Ethereum PQC roadmap" }, // quantumscan-ignore
  { id: "bitcoinjs-ecpair",    name: "bitcoinjs-lib ECPair (secp256k1)",   sev: "high", re: /ECPair\.fromPrivateKey\s*\(|ECPair\.makeRandom\s*\(|ECPair\.fromWIF\s*\(|bitcoin\.ECPair/i, alt: "Follow Bitcoin PQC proposals (BIP-360 draft)" }, // quantumscan-ignore
  { id: "solana-keypair",      name: "Solana Keypair (Ed25519)",           sev: "high", re: /Keypair\.generate\s*\(|Keypair\.fromSecretKey\s*\(|Keypair\.fromSeed\s*\(|web3\.Keypair\b/i, alt: "Monitor Solana PQC roadmap" }, // quantumscan-ignore
  { id: "solidity-ecrecover",  name: "Solidity ecrecover (secp256k1)",     sev: "high", re: /\becrecover\s*\(|ECDSA\.recover\s*\(|ECDSA\.tryRecover\s*\(/i, alt: "Monitor EVM PQC precompile proposals" }, // quantumscan-ignore
  { id: "bip32-hd-wallet",     name: "BIP32/BIP39 HD Wallet derivation",  sev: "high", re: /BIP32Factory\s*\(|hdkey\.fromMasterSeed\s*\(|HDKey\.fromMasterSeed\s*\(|EthereumHDKey|derivePath\s*\(\s*["']m\//i, alt: "No PQC BIP32 standard yet — monitor BIP proposals" }, // quantumscan-ignore
  { id: "eth-account-python",  name: "eth-account / web3.py (secp256k1)", sev: "high", re: /from\s+eth_account\s+import|Account\.create\s*\(|Account\.from_key\s*\(|w3\.eth\.account\./i, alt: "Monitor ethereum/py-evm PQC roadmap" }, // quantumscan-ignore
  { id: "coincurve-secp256k1", name: "coincurve / python-bitcoin",        sev: "high", re: /import\s+coincurve\b|coincurve\.(?:PublicKey|PrivateKey)|from\s+bitcoinlib\s+import.*(?:Key|sign)/i, alt: "ML-DSA (CRYSTALS-Dilithium)" }, // quantumscan-ignore
  { id: "rust-secp256k1-crate",name: "Rust secp256k1 / k256 crate",      sev: "high", re: /use\s+secp256k1::|use\s+k256::|Secp256k1::new\s*\(|SecretKey::from_slice\s*\(|SigningKey::from_bytes\s*\(/i, alt: "ML-DSA via pqcrypto-dilithium crate" }, // quantumscan-ignore
  { id: "tronweb-wallet",      name: "TronWeb wallet (secp256k1)",        sev: "high", re: /TronWeb\.createAccount\s*\(|tronWeb\.createAccount|tronWeb\.address\.fromPrivateKey/i, alt: "Monitor TRON PQC roadmap" }, // quantumscan-ignore
  { id: "bls12-381",           name: "BLS12-381 pairing curve",           sev: "high", re: /\bbls12[_-]381\b|G1Affine\b|G2Affine\b|G1Projective\b|G2Projective\b|bls\.sign\s*\(|bls\.verify\s*\(|bls\.aggregateVerify\s*\(|pairing\s*\(\s*&?G[12]|from_compressed\s*\(\)|Gt::generator\s*\(/i, alt: "No NIST PQC pairing standard yet — monitor IETF PQC pairings WG" }, // quantumscan-ignore
  { id: "ed25519-dalek-rust",  name: "ed25519-dalek Rust crate usage",    sev: "high", re: /ed25519_dalek::(?:Keypair|SigningKey|VerifyingKey|SecretKey|Signature|ExpandedSecretKey)|SigningKey::from_bytes\s*\(|ExpandedSecretKey::from\s*\(/i, alt: "ML-DSA via pqcrypto-dilithium crate" }, // quantumscan-ignore
  // HIGH — Solidity / DeFi PQC patterns (v1.5.0 — QuantumScan for DeFi)
  { id: "solidity-eip712",         name: "Solidity EIP-712 typed data sig (secp256k1)",  sev: "high", re: /\b_hashTypedDataV4\s*\(|EIP712\b|DOMAIN_SEPARATOR\b|_DOMAIN_SEPARATOR\b|_buildDomainSeparator\s*\(|eip712Domain\s*\(|hashTypedDataV4\s*\(/i,                                             alt: "Monitor EVM PQC precompile proposals — no quantum-safe EIP-712 standard yet" }, // quantumscan-ignore
  { id: "solidity-assembly-ecr",   name: "Solidity assembly ecrecover precompile (0x1)", sev: "high", re: /staticcall\s*\([^,)]*,\s*(?:0x0*1|1)\s*,|signer\s*:=\s*mload\s*\(|recovered\s*:=\s*mload\s*\(|let\s+signer\s*:=\s*(?:ecrecover|mload)/i,                                              alt: "Monitor EIP for PQC signature precompile replacement" }, // quantumscan-ignore
  { id: "solidity-oracle-chainlink",name: "Chainlink oracle (secp256k1 ECDSA DON)",     sev: "high", re: /\bAggregatorV3Interface\b|latestRoundData\s*\(|ChainlinkClient\b|buildChainlinkRequest\s*\(|sendChainlinkRequestTo\s*\(|VRFConsumerBase\b|VRFConsumerBaseV2\b|requestRandomness\s*\(/i,  alt: "Monitor Chainlink PQC roadmap — DON uses secp256k1 threshold signatures" }, // quantumscan-ignore
  { id: "solidity-permit-eip2612", name: "ERC-2612 permit() gasless approval (ECDSA)",  sev: "high", re: /\bERC20Permit\b|\bIERC20Permit\b|\bERC2612\b|function\s+permit\s*\(\s*address\s+(?:owner|spender)|\bDAI_DOMAIN_SEPARATOR\b/i,                                                              alt: "No PQC permit standard yet — signature-based approvals will break post-quantum" }, // quantumscan-ignore
  { id: "solidity-multisig-ecdsa", name: "Gnosis Safe / MultiSig ECDSA (N-of-M keys)", sev: "high", re: /\bGnosisSafe\b|\bMultiSigWallet\b|checkNSignatures\s*\(|execTransaction\s*\(|isValidSignature\s*\(|signatureToAddress\s*\(|_checkSignatures\s*\(|SafeSignature\b|ISafe\b/i,               alt: "Monitor Safe{Wallet} PQC migration — each signer key is Shor-vulnerable" }, // quantumscan-ignore
  // HIGH — Java JCA / SSH library false-negative fixes (2026-06-04)
  { id: "java-jca-rsa",        name: "Java JCA RSA getInstance",              sev: "high", re: /(?:KeyPairGenerator|KeyFactory|Cipher|KeyGenerator)\.getInstance\s*\(\s*["']RSA["']/i, alt: "ML-KEM-768 (NIST FIPS 203)" }, // quantumscan-ignore
  { id: "java-jca-sig",        name: "Java JCA RSA/ECDSA Signature",          sev: "high", re: /Signature\.getInstance\s*\(\s*["'][^"']*(?:withRSA|withECDSA|withDSA)[^"']*["']/i, alt: "ML-DSA-65 (NIST FIPS 204)" }, // quantumscan-ignore
  { id: "java-ssh-mina-jsch",  name: "Apache MINA SSHD / JSch client",        sev: "high", re: /SshClient\.setUpDefaultClient\s*\(|new\s+JSch\s*\(|\.setKeyPairProvider\s*\(|SshServer\.setUpDefaultServer\s*\(/i, alt: "Monitor OpenSSH PQC KEX: mlkem768x25519-sha256" }, // quantumscan-ignore
  { id: "csharp-ssh-net",      name: "SSH.NET SshClient / PrivateKeyFile",     sev: "high", re: /new\s+SshClient\s*\(|new\s+SftpClient\s*\(|new\s+PrivateKeyFile\s*\(|new\s+RsaKey\s*\(/i, alt: "Monitor OpenSSH PQC roadmap" }, // quantumscan-ignore
  { id: "csharp-rsa-cng",      name: "C# RSACng / ECDsaCng (CNG APIs)",        sev: "high", re: /new\s+RSACng\s*\(|new\s+ECDsaCng\s*\(|new\s+DSACng\s*\(|AsymmetricAlgorithm\.Create\s*\(/i, alt: "ML-KEM-768 or ML-DSA-65 via NIST FIPS 203/204" }, // quantumscan-ignore
  { id: "go-crypto-rsa",       name: "Go stdlib RSA/ECDSA keygen",             sev: "high", re: /rsa\.GenerateKey\s*\(|ecdsa\.GenerateKey\s*\(|rsa\.EncryptPKCS1v15\s*\(|rsa\.SignPKCS1v15\s*\(|rsa\.DecryptPKCS1v15\s*\(/i, alt: "ML-KEM-768 via golang.org/x/crypto/mlkem (FIPS 203)" }, // quantumscan-ignore
  { id: "rust-ring",           name: "Rust ring RSA/ECDSA signatures",         sev: "high", re: /ring::signature::(?:RSA_PKCS1|ECDSA_P(?:256|384))|RsaKeyPair::from_pkcs8\s*\(|EcdsaKeyPair::from_pkcs8\s*\(/i, alt: "pqcrypto-dilithium or ml-dsa crate" }, // quantumscan-ignore
  { id: "python-paramiko-key", name: "Paramiko RSA/ECDSA key operations",      sev: "high", re: /paramiko\.RSAKey\b|paramiko\.ECDSAKey\b|RSAKey\.generate\s*\(|ECDSAKey\.generate\s*\(|paramiko\.DSSKey\b/i, alt: "Monitor OpenSSH PQC roadmap" }, // quantumscan-ignore
  // HIGH — crypto implementation patterns (library internals — 2026-06-08 v1.3.0)
  { id: "openssl-evp-cipher",  name: "OpenSSL EVP cipher impl",         sev: "high", re: /EVP_(?:Encrypt|Decrypt|Cipher)Init(?:_ex2?)?\s*\(/i,                                                                                     alt: "OpenSSL 3.x oqs-provider for AES-GCM + ML-KEM" }, // quantumscan-ignore
  { id: "openssl-rsa-gen",     name: "OpenSSL RSA keygen impl",          sev: "high", re: /RSA_generate_key(?:_ex)?\s*\(|EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_RSA/i,                                                                 alt: "ML-KEM-768 (NIST FIPS 203)" }, // quantumscan-ignore
  { id: "openssl-ec-gen",      name: "OpenSSL EC keygen impl",           sev: "high", re: /EC_KEY_new_by_curve_name\s*\(|EC_GROUP_new_by_curve_name\s*\(/i,                                                                          alt: "ML-KEM or ML-DSA via oqs-provider" }, // quantumscan-ignore
  { id: "openssl-bn-prime",    name: "OpenSSL BN prime (RSA impl)",      sev: "high", re: /BN_generate_prime(?:_ex2?)?\s*\(/i,                                                                                                       alt: "ML-KEM-768 (NIST FIPS 203)" }, // quantumscan-ignore
  { id: "openssl-dsa-gen",     name: "OpenSSL DSA keygen impl",          sev: "high", re: /DSA_generate_key\s*\(|DSA_generate_parameters(?:_ex)?\s*\(/i,                                                                             alt: "ML-DSA-65 (NIST FIPS 204)" }, // quantumscan-ignore
  { id: "java-jca-ec-gen",     name: "Java JCA EC KeyPairGenerator",     sev: "high", re: /KeyPairGenerator\.getInstance\s*\(\s*["'](?:EC|ECDH|ECDSA)["']/i,                                                                        alt: "ML-KEM-768 or ML-DSA-65 via Bouncy Castle PQC" }, // quantumscan-ignore
  { id: "java-jca-spi",        name: "Java JCA provider SPI impl",       sev: "high", re: /extends\s+(?:KeyPairGeneratorSpi|SignatureSpi|CipherSpi|MessageDigestSpi|KeyAgreementSpi)\b|Security\.addProvider\s*\(/i,                 alt: "Implement PQC via Bouncy Castle bcpqc jar" }, // quantumscan-ignore
  { id: "java-jca-keyagree",   name: "Java JCA KeyAgreement ECDH/DH",   sev: "high", re: /KeyAgreement\.getInstance\s*\(\s*["'](?:ECDH|DH|ECMQV)["']/i,                                                                            alt: "ML-KEM-768 (NIST FIPS 203)" }, // quantumscan-ignore
  { id: "node-crypto-keygen",  name: "Node.js crypto.generateKeyPair",   sev: "high", re: /crypto\.generateKeyPair(?:Sync)?\s*\(\s*["'](?:rsa|ec|dsa|ed25519|x25519)["']/i,                                                         alt: "await Web Crypto + liboqs-js for ML-KEM/ML-DSA" }, // quantumscan-ignore
  { id: "node-crypto-ecdh",    name: "Node.js crypto.createECDH",        sev: "high", re: /crypto\.createECDH\s*\(/i,                                                                                                                alt: "ML-KEM-768 via liboqs-js" }, // quantumscan-ignore
  // HIGH — extended language / framework coverage (2026-06-09 v1.4.0)
  { id: "python-hazmat-rsa",  name: "Python hazmat RSA/DSA/DH keygen",  sev: "high", re: /(?:rsa|dsa|dh)\.generate_(?:private_key|parameters)\s*\(/i,                                                                                           alt: "ML-KEM-768 or ML-DSA-65 via pqcrypto package \(NIST FIPS 203/204\)" }, // quantumscan-ignore
  { id: "python-hazmat-ec",   name: "Python hazmat EC keygen",           sev: "high", re: /ec\.generate_private_key\s*\(/i,                                                                                                                          alt: "ML-DSA-65 \(NIST FIPS 204\) for signatures; ML-KEM-768 for KEM" }, // quantumscan-ignore
  { id: "swift-seckey",       name: "Swift/iOS SecKey RSA/ECDSA keygen", sev: "high", re: /SecKeyCreateRandomKey\s*\(|kSecAttrKeyTypeRSA\b|kSecAttrKeyTypeECSECPrimeRandom\b|SecKeyGeneratePair\s*\(/i,                                              alt: "Monitor Apple CryptoKit PQC roadmap" }, // quantumscan-ignore
  { id: "csharp-rsa-create",  name: "C# RSA.Create / ECDsa.Create",      sev: "high", re: /\bRSA\.Create\s*\(|\bECDsa\.Create\s*\(|\bDSA\.Create\s*\(/i,                                                                                            alt: "ML-KEM-768 or ML-DSA-65 via NIST FIPS 203/204" }, // quantumscan-ignore
  { id: "php-openssl-asym",   name: "PHP openssl asymmetric ops",        sev: "high", re: /openssl_sign\s*\(|openssl_verify\s*\(|openssl_private_encrypt\s*\(|openssl_public_decrypt\s*\(/i,                                                         alt: "Await PHP PQC ext; short-term: use HMAC-SHA256 for integrity" }, // quantumscan-ignore
  { id: "aws-s2n-tls",        name: "AWS s2n-tls classical TLS conn",    sev: "high", re: /s2n_connection_new\s*\(|s2n_config_new\s*\(|s2n_cipher_preferences|s2n_send\s*\(|s2n_recv\s*\(/i,                                                        alt: "Enable ML-KEM via AWS-LC: S2N_TLS_KEM_GROUP_X25519_KYBER_512_R3" }, // quantumscan-ignore
  { id: "openssh-sshkey-gen", name: "OpenSSH C sshkey_generate",         sev: "high", re: /sshkey_generate\s*\(|sshkey_ecdsa_new\s*\(|sshkey_dsa_generate\s*\(|KEX_CLIENT_ENCRYPT\b/i,                                                              alt: "Set KexAlgorithms mlkem768x25519-sha256 in sshd_config" }, // quantumscan-ignore
  { id: "rustls-config",      name: "rustls classical TLS ClientConfig", sev: "high", re: /rustls::(?:Client|Server)Config::builder\s*\(|ClientConnection::new\s*\(|RootCertStore::empty\s*\(\)/i,                                                   alt: "Monitor rustls PQC roadmap; use aws-lc-rs provider for ML-KEM hybrid" }, // quantumscan-ignore
    // AUTO-ADDED by scanner-evolution-agent 2026-06-12
  { id: "google-tink-ecdsa", name: "Google Tink ECDSA signature", sev: "high", re: /EcdsaSignKeyManager|EcdsaVerifyKeyManager|ECDSA_P256|ECDSA_P384|ECDSA_P521|EcdsaPrivateKey|KeysetHandle\.generateNew\s*\(\s*EcdsaSign|register(?:Ecdsa|ECDSA)|TinkProtoParametersFormat.*ecdsa/i, alt: "ML-DSA-65 or SLH-DSA (NIST FIPS 204/205) via liboqs or Tink PQC fork" },
  { id: "aws-kms-rsa-classical", name: "AWS KMS RSA/ECC key operations", sev: "high", re: /CreateKey.*KeySpec.*(?:RSA_2048|RSA_3072|RSA_4096|ECC_NIST_P256|ECC_NIST_P384|ECC_NIST_P521|ECC_SECG_P256K1)|KeyUsage.*SIGN_VERIFY.*(?:RSA|ECDSA)|GetPublicKey.*(?:RSA|ECC)|aws-kms.*KeySpec.*(?:RSA|ECC)/i, alt: "AWS KMS post-quantum TLS (when available) or client-side ML-KEM/ML-DSA" },
  { id: "ruby-openssl-rsa-ecdsa", name: "Ruby OpenSSL RSA/ECDSA key generation", sev: "high", re: /OpenSSL::PKey::RSA\.(?:new|generate)|OpenSSL::PKey::EC\.(?:new|generate)|OpenSSL::PKey::DSA\.(?:new|generate)|rsa\.generate_key|ec\.generate_key/i, alt: "Post-quantum signatures via experimental Ruby bindings to liboqs" },
  { id: "azure-keyvault-rsa-ec", name: "Azure Key Vault RSA/EC key operations", sev: "high", re: /CreateRsaKey|CreateEcKey|KeyVaultKey.*Rsa|KeyVaultKey.*Ec|JsonWebKey.*Kty.*(?:RSA|EC)|beginCreateKey.*(?:Rsa|Ec)|KeyType\.(?:RSA|EC)/i, alt: "Azure confidential computing with post-quantum readiness or hybrid solutions" },
  { id: "kotlin-java-security-rsa-ec", name: "Kotlin/Java Security RSA/EC keygen", sev: "high", re: /KeyPairGenerator\.getInstance\s*\(\s*['"](?:RSA|EC|ECDSA|ECDH)['"]|Signature\.getInstance\s*\(\s*['"](?:SHA\d+withRSA|SHA\d+withECDSA|NONEwithRSA)['"]|KeyFactory\.getInstance\s*\(\s*['"](?:RSA|EC)['"]/i, alt: "BouncyCastle PQC provider with ML-DSA or SLH-DSA" },
  // HIGH — additional language / ecosystem coverage (2026-06-18 v1.5.0)
  { id: "rust-dalek-curves",          name: "Rust ed25519-dalek / x25519-dalek",      sev: "high", re: /use\s+ed25519_dalek::|use\s+x25519_dalek::|ed25519_dalek::(?:SigningKey|Keypair|SecretKey)\b|x25519_dalek::(?:StaticSecret|EphemeralSecret)\b/i,                                                                                                                      alt: "ML-DSA via pqcrypto-dilithium crate (NIST FIPS 204)" }, // quantumscan-ignore
  { id: "rust-p256-ecdsa-crate",      name: "Rust p256 / ecdsa crate usage",           sev: "high", re: /use\s+p256::|use\s+ecdsa::|p256::(?:SecretKey|PublicKey)\b|ecdsa::(?:SigningKey|VerifyingKey)\b/i,                                                                                                                                                                  alt: "ML-DSA via pqcrypto-dilithium crate (NIST FIPS 204)" }, // quantumscan-ignore
  { id: "webcrypto-classical",        name: "WebCrypto classical key algorithm",       sev: "high", re: /crypto\.subtle\.(?:generateKey|importKey|deriveKey)\s*\(\s*\{[^}]*(?:name\s*:\s*)?["'](?:RSASSA-PKCS1-v1_5|RSA-PSS|RSA-OAEP|ECDSA|ECDH)["']/i,                                                                                                                    alt: "Await WebCrypto ML-KEM/ML-DSA; use @noble/post-quantum or liboqs-js" }, // quantumscan-ignore
  { id: "python-load-pem-key",        name: "Python load classical PEM/DER key",       sev: "high", re: /(?:load_pem_private_key|load_der_private_key|load_pem_public_key|load_der_public_key|load_ssh_private_key)\s*\(/i,                                                                                                                                                  alt: "Audit key type; migrate to ML-KEM-768 or ML-DSA-65 (NIST FIPS 203/204)" }, // quantumscan-ignore
  { id: "csharp-bc-rsa-ec",          name: "C# BouncyCastle RSA/EC keygen",           sev: "high", re: /(?:RsaKeyPairGenerator|ECKeyPairGenerator|DsaKeyPairGenerator)\b|new\s+RsaKeyGenerationParameters\s*\(|new\s+ECKeyGenerationParameters\s*\(/i,                                                                                                                      alt: "NTRUKeyPairGenerator or SphincsPlusKeyPairGenerator via Bouncy Castle PQC" }, // quantumscan-ignore
  { id: "go-tls-classical-config",   name: "Go TLS classical cipher/curve config",    sev: "high", re: /tls\.TLS_RSA_WITH|tls\.TLS_ECDHE_(?:RSA|ECDSA)\b|CurvePreferences\s*:\s*\[\]tls\.CurveID\{[^}]*(?:tls\.CurveP(?:256|384|521)|tls\.X25519)\b/i,                                                                                                                    alt: "Use tls.X25519Kyber768Draft00 in CurvePreferences (Go 1.23+ / NIST FIPS 203)" }, // quantumscan-ignore
  { id: "elixir-erlang-crypto",      name: "Elixir/Erlang :crypto classical keygen",  sev: "high", re: /:crypto\.(?:generate_key|sign|verify|public_encrypt|private_decrypt)\(\s*:(?:rsa|ecdh|ecdsa|dss)|:public_key\.generate_key\(\{:namedCurve/i,                                                                                                                        alt: "Await OTP PQC support; monitor erlang-libsodium bindings" }, // quantumscan-ignore
  { id: "android-keystore-classical", name: "Android KeyStore RSA/EC key",             sev: "high", re: /KeyProperties\.KEY_ALGORITHM_(?:RSA|EC)\b|KeyGenParameterSpec\.Builder\s*\([^)]*['"]\w+['"]\s*,\s*KeyProperties\.PURPOSE_(?:SIGN|ENCRYPT)/i,                                                                                                                        alt: "Monitor Android PQC roadmap; ML-KEM/ML-DSA via BouncyCastle PQC on Android" }, // quantumscan-ignore
  // HIGH — SSH / blockchain false-negative fixes (2026-06-20 v1.7.0)
  { id: "go-xcrypto-ssh",            name: "Go x/crypto/ssh key & conn API",         sev: "high", re: /\bssh\.ParsePrivateKey\s*\(|\bssh\.NewSignerFromKey\s*\(|\bssh\.Dial\s*\(|\bgossh\.NewServerConn\s*\(|\bssh\.NewPublicKey\s*\(|\bssh\.ParseAuthorizedKey\s*\(/i,                                                                                                                      alt: "Monitor OpenSSH PQC KEX: mlkem768x25519-sha256 in Go x/crypto (NIST FIPS 203)" }, // quantumscan-ignore
  { id: "python-asyncssh",           name: "Python asyncssh SSH transport",           sev: "high", re: /import\s+asyncssh\b|asyncssh\.connect\s*\(|asyncssh\.create_server\s*\(|asyncssh\.generate_private_key\s*\(|asyncssh\.read_private_key\s*\(/i,                                                                                                                       alt: "Monitor OpenSSH PQC roadmap; asyncssh uses RSA/ECDSA/Ed25519 — no PQC KEX yet" }, // quantumscan-ignore
  { id: "java-mina-sshd-hostkey",    name: "Apache MINA SSHD host key provider",     sev: "high", re: /SimpleGeneratorHostKeyProvider\s*\(|new\s+DefaultKeyPairProvider\s*\(|\.setHostKeyProvider\s*\(|new\s+DefaultSshClient\s*\(|new\s+SshServer\s*\(/i,                                                                                                                   alt: "Monitor Apache MINA SSHD for mlkem768x25519 KEX; no PQC host key provider yet" }, // quantumscan-ignore
  { id: "libsecp256k1-capi",         name: "libsecp256k1 ECDSA C API (Bitcoin/EVM)", sev: "high", re: /secp256k1_(?:ecdsa_sign|ecdsa_verify|keypair_create|ec_pubkey_create|context_create|schnorrsig_sign|schnorrsig_verify)\s*\(/i,                                                                                                                        alt: "Monitor Bitcoin BIP-360 PQC transition; secp256k1 is Shor-vulnerable" }, // quantumscan-ignore
  { id: "go-btcec-btcd",             name: "Go btcd/btcec secp256k1 key operations", sev: "high", re: /btcec\.GenerateKey\s*\(|btcec\.ParsePubKey\s*\(|btcec\.ParsePrivKey\s*\(|btcec\.NewPrivateKey\s*\(|"github\.com\/btcsuite\/btcd(?:\/btcec)?"|btcutil\.NewAddressPubKey\s*\(/i,                                                                                         alt: "Monitor Bitcoin BIP-360 — btcec wraps libsecp256k1 (Shor-vulnerable)" }, // quantumscan-ignore
  { id: "csharp-sshnet-ecdsa",       name: "SSH.NET EcdsaKey / ED25519Key",          sev: "high", re: /new\s+EcdsaKey\s*\(|new\s+ED25519Key\s*\(|new\s+DsaKey\s*\(|Renci\.SshNet\.|SshNet\.(?:Client|Server|Security)\./i,                                                                                                                                                  alt: "Monitor OpenSSH PQC roadmap — no quantum-safe SSH.NET key type available yet" }, // quantumscan-ignore
  { id: "rust-rsa-crate",            name: "Rust rsa crate key operations",           sev: "high", re: /use\s+rsa::|RsaPrivateKey::new\s*\(|RsaPublicKey::from\s*\(|rsa::pkcs(?:1|8)|PaddingScheme::new_pkcs1v15|RsaPublicKey::new\s*\(/i,                                                                                                                   alt: "pqcrypto-kyber (ML-KEM-768, NIST FIPS 203) for encryption; pqcrypto-dilithium (ML-DSA, FIPS 204) for signing" }, // quantumscan-ignore
  { id: "rust-solana-sdk",           name: "Rust solana-sdk Keypair (Ed25519)",       sev: "high", re: /use\s+solana_sdk::|use\s+solana_program::|Keypair::new\s*\(|Keypair::from_bytes\s*\(|Keypair::from_seed\s*\(|solana_sdk::signature::Keypair|solana_keypair!/i,                                                                                                       alt: "Monitor Solana PQC roadmap for account signature algorithm migration" }, // quantumscan-ignore
  // HIGH — OpenPGP / JSSE / X.509 cert / Rust TLS / Go ecdsa coverage (2026-06-21 v1.7.0)
  { id: "openpgp-js",          name: "OpenPGP.js classical key generation",             sev: "high", re: /openpgp\.generateKey\s*\(\s*\{|openpgp\.readKey\s*\(|openpgp\.decryptKey\s*\(|OpenPGP\.(?:generateKey|readKey|sign)\s*\(/i,                                                                        alt: "Await ML-DSA / SLH-DSA PGP standard (draft-ietf-openpgp-pqc-08)" }, // quantumscan-ignore
  { id: "rust-rcgen",          name: "Rust rcgen TLS cert generation (RSA/ECDSA)",       sev: "high", re: /use\s+rcgen::|rcgen::CertificateParams\b|rcgen::Certificate::from_params\s*\(|generate_simple_self_signed\s*\(|rcgen::KeyPair::generate\s*\(/i,                                                    alt: "Monitor rcgen PQC roadmap; use ML-DSA hybrid cert when supported" }, // quantumscan-ignore
  { id: "java-jsse-ctx",       name: "Java JSSE SSLContext / KeyManagerFactory",         sev: "high", re: /SSLContext\.getInstance\s*\(\s*["'][^"']+["']\s*\)|KeyManagerFactory\.getInstance\s*\(\s*["'](?:PKIX|SunX509)["']\s*\)|TrustManagerFactory\.getInstance\s*\(\s*["']/i,                             alt: "Monitor JDK PQC TLS roadmap; target SSLParameters with ML-KEM hybrid KEX" }, // quantumscan-ignore
  { id: "csharp-x509cert2",    name: "C# X509Certificate2 RSA/ECDSA cert operations",   sev: "high", re: /new\s+X509Certificate2\s*\(|X509Certificate2\.CreateFromPem\s*\(|CertificateRequest\s*\(\s*[^,]+,\s*(?:RSA|ECDsa)\b/i,                                                                              alt: "Await .NET 10 PQC certificate support; monitor ML-KEM/ML-DSA roadmap" }, // quantumscan-ignore
  { id: "python-gnupg",        name: "Python gnupg / pgpy classical PGP key ops",        sev: "high", re: /gpg\.gen_key\s*\(|gpg\.import_keys\s*\(|gpg\.sign\s*\(|pgpy\.PGPKey\.new\s*\(|PubKeyAlgorithm\.RSAEncryptOrSign|gnupg\.GPG\s*\(/i,                                                                alt: "Await ML-DSA / SLH-DSA PGP standard (draft-ietf-openpgp-pqc-08)" }, // quantumscan-ignore
  { id: "go-ecdsa-sign",       name: "Go stdlib ecdsa.Sign / ecdsa.Verify",              sev: "high", re: /ecdsa\.Sign\s*\(|ecdsa\.Verify\s*\(|ecdsa\.SignASN1\s*\(|ecdsa\.VerifyASN1\s*\(/i,                                                                                                                  alt: "ML-DSA-65 via golang.org/x/crypto (NIST FIPS 204)" }, // quantumscan-ignore
  { id: "java-keystore-load",  name: "Java KeyStore PKCS12/JKS RSA key loading",         sev: "high", re: /KeyStore\.getInstance\s*\(\s*["'](?:PKCS12|JKS|BKS|Windows-MY)["']\s*\)|KeyStore\.load\s*\(|ks\.getKey\s*\(|keyStore\.aliases\s*\(\)/i,                                                            alt: "Migrate to PQC keys via Bouncy Castle bcpqc; PKCS12 format supports ML-DSA" }, // quantumscan-ignore
  { id: "rust-native-tls",     name: "Rust native-tls / openssl crate TLS",              sev: "high", re: /use\s+native_tls::|use\s+openssl::(?:ssl|rsa|ec|dsa|pkey)::|TlsConnector::(?:builder|new)\s*\(\s*\)|TlsAcceptor::(?:builder|new)\s*\(\s*\)|SslMethod::tls\s*\(\s*\)/i,                             alt: "Migrate to rustls with aws-lc-rs or oqs-provider for ML-KEM hybrid TLS" }, // quantumscan-ignore
  { id: "python-paramiko",    name: "Python Paramiko SSH",                    sev: "high", re: /paramiko\.(?:RSAKey|ECDSAKey|DSSKey|Ed25519Key)\.generate|paramiko\.(?:SSHClient|Transport)\(|from paramiko import|import paramiko/i, alt: "OpenSSH mlkem768x25519-sha256 (when Paramiko adds PQC KEM)" }, // quantumscan-ignore
  { id: "ruby-openssl-pkey",  name: "Ruby OpenSSL PKey RSA/EC/DSA",           sev: "high", re: /OpenSSL::PKey::(?:RSA|EC|DSA)\.(?:new|generate)|OpenSSL::SSL::SSLContext\.new|require\s+[\'"]openssl[\'"].*PKey/i, alt: "openssl-oqs gem (ML-KEM / ML-DSA) or Ruby oqs-provider" }, // quantumscan-ignore
  { id: "terraform-tls-key",  name: "Terraform tls_private_key RSA/ECDSA",   sev: "high", re: /resource\s+["'"]tls_private_key["'"]|algorithm\s*=\s*["'"](?:RSA|ECDSA|DSA)["'"]|tls_self_signed_cert|tls_locally_signed_cert/i, alt: "Await HashiCorp tls provider PQC support; use external_provider with openssl-oqs" }, // quantumscan-ignore
  { id: "nodejs-crypto-asym", name: "Node.js crypto asymmetric ops",           sev: "high", re: /crypto\.createECDH\s*\(|generateKeyPairSync\s*\(\s*['\"](?:rsa|ec|dsa|ed25519|x25519)['\"]|crypto\.createSign\s*\(|createDiffieHellman\s*\(/i, alt: "Node.js crypto.generateKeyPairSync with ML-KEM-768 via oqs-node binding" }, // quantumscan-ignore
  { id: "java-bc-pem-io",     name: "Bouncy Castle PEM I/O",                  sev: "high", re: /PEMParser\s*\(|PEMKeyPair|JcaPEMKeyConverter|JcaPKCS8Generator|PKCS8Generator|PemWriter|JcaPEMWriter/i, alt: "Bouncy Castle bcpqc-jdk18on: ML-DSA / ML-KEM PKCS12 support" }, // quantumscan-ignore
  { id: "dart-pointycastle",  name: "Dart pointycastle RSA/EC",               sev: "high", re: /(?:package:pointycastle|RSAKeyGenerationParameters|ECKeyGeneratorParameters|RSAPrivateKey\s*\(|ECPrivateKey\s*\(|AsymmetricKeyPair<(?:RSA|EC))/i, alt: "package:cryptography with ML-KEM-768 (liboqs FFI) when Dart binding lands" }, // quantumscan-ignore
  { id: "go-rsa-ops",         name: "Go crypto/rsa operations",               sev: "high", re: /rsa\.GenerateMultiPrimeKey|rsa\.DecryptPKCS1v15|rsa\.SignPSS\s*\(|rsa\.EncryptOAEP\s*\(|rsa\.DecryptOAEP\s*\(|rsa\.EncryptPKCS1v15/i, alt: "ML-KEM-768 (FIPS 203) via golang.org/x/crypto/mlkem or cloudflare/circl" }, // quantumscan-ignore
  { id: "python-x509-builder",name: "Python cryptography x509 cert builder",  sev: "high", re: /x509\.CertificateBuilder\(\)|x509\.load_pem_x509_certificate|x509\.load_der_x509_certificate|CertificateRevocationListBuilder|x509\.NameAttribute\s*\(|\.sign\s*\(.*hashes\.SHA/i, alt: "Await pyca/cryptography ML-DSA cert support (draft-ietf-lamps-dilithium-certificates)" }, // quantumscan-ignore
    // AUTO-ADDED by scanner-evolution-agent 2026-06-23
  { id: "solidity-erc1271-signature", name: "Solidity ERC-1271 isValidSignature (ECDSA)", sev: "high", re: /function\s+isValidSignature\s*\(|IERC1271\s*\.\s*isValidSignature|ERC1271\.isValidSignature|SignatureChecker\.isValidSignatureNow|_isValidSignature\s*\([^)]*\)|0x1626ba7e/i, alt: "Post-quantum signature schemes: ML-DSA (Dilithium, NIST FIPS 204) or SLH-DSA (SPHINCS+, NIST FIPS 205)" },
  { id: "solidity-erc4337-ecdsa", name: "Solidity ERC-4337 UserOperation ECDSA validation", sev: "high", re: /validateUserOp\s*\(|IAccount\.validateUserOp|UserOperation\s*\.|_validateSignature\s*\(\s*UserOperation|ecrecover\s*\([^)]*userOp|ECDSA\.recover\s*\([^)]*userOp/i, alt: "Post-quantum signature schemes: ML-DSA (Dilithium, NIST FIPS 204) or SLH-DSA (SPHINCS+, NIST FIPS 205)" },
  { id: "uniswap-permit2-ecdsa", name: "Uniswap Permit2 / position signature (ECDSA)", sev: "high", re: /IPermit2\.permit|Permit2\.permitTransferFrom|PermitTransferFrom|SignatureTransfer|AllowanceTransfer\.permit|_verifyPermitSignature|EIP712\s*\(\s*["']Permit2|INonfungiblePositionManager\.permit/i, alt: "Post-quantum gasless approval via ML-DSA (Dilithium, NIST FIPS 204)" },
  { id: "zk-ecdsa-circuit", name: "ZK ECDSA signature verification circuit (Groth16/PLONK)", sev: "high", re: /ECDSAVerify\s*\(|circom.*ecdsa|Secp256k1\s*\(|ecdsa_verify_circuit|groth16.*ecdsa|plonk.*ecdsa|"ecdsa"\s*:\s*\{|ecdsaCircuit|verifyECDSAProof/i, alt: "Post-quantum ZK circuits using hash-based or lattice-friendly signatures (e.g., Picnic, Rainier)" },
    // AUTO-ADDED by scanner-evolution-agent 2026-06-23
  { id: "solidity-permit2-signature", name: "Uniswap Permit2 / position signature (ECDSA)", sev: "high", re: /IPermit2\s*\.\s*permit|permitTransferFrom\s*\(|permitWitnessTransferFrom\s*\(|SignatureTransfer\s*\.\s*permit|AllowanceTransfer\s*\.\s*permit|_verifyPermit2Signature|Permit2\.permitTransferFrom/i, alt: "Quantum-resistant authorization schemes or hash-based commitments with post-quantum signatures" },
  { id: "solidity-zk-ecdsa-circuit", name: "ZK ECDSA signature verification circuit (Groth16/PLONK)", sev: "high", re: /verifyECDSASignature\s*\(|ECDSAVerifier\.verify|Groth16Verifier.*ecdsa|PlonkVerifier.*ecdsa|zkECDSA|circuit.*ecrecover|snark.*ecdsa.*proof|verify.*secp256k1.*proof/i, alt: "Hash-based ZK proofs (e.g., MiMC, Poseidon) or quantum-resistant signature schemes inside circuits" },
  { id: "layerzero-crosschain-signature", name: "LayerZero / Wormhole cross-chain ECDSA signature relay", sev: "high", re: /ILayerZeroEndpoint\s*\.\s*send|lzReceive\s*\(.*signatures|adapterParams.*signatures|relayer.*verifySignatures|Wormhole.*parseAndVerifyVM|verifyVAA\s*\(|GuardianSet.*signatures|parseVM\s*\(.*signatures/i, alt: "Quantum-resistant cross-chain messaging with ML-DSA or hash-based oracle commitments" },
  { id: "signal-protocol-x3dh-ecdh", name: "Signal Protocol X3DH / Double Ratchet ECDH", sev: "high", re: /X3DH|Extended\s+Triple\s+Diffie-Hellman|DoubleRatchet|Signal\s+Protocol.*ECDH|libsignal.*KeyPair|Curve25519.*agreementWith|generateIdentityKeyPair|generatePreKey|calculateAgreement\s*\(.*Curve25519/i, alt: "Quantum-resistant key agreement: ML-KEM-768 (Kyber) or NTRU for session key establishment" },
    // AUTO-ADDED by scanner-evolution-agent 2026-06-24
  { id: "python-pycryptodome-rsa-dsa", name: "PyCryptodome RSA/DSA key operations", sev: "high", re: /from\s+Crypto\.PublicKey\s+import\s+(RSA|DSA)|RSA\.generate\s*\(|DSA\.generate\s*\(|RSA\.import_key\s*\(|DSA\.import_key\s*\(/i, alt: "ML-KEM-768 or ML-DSA-65 (NIST FIPS 203/204) via liboqs-python" },
  { id: "java-bouncy-rsa-ec-keygen", name: "Bouncy Castle RSA/EC KeyPairGenerator", sev: "high", re: /KeyPairGenerator\.getInstance\s*\(\s*['"]RSA['"].*BouncyCastle|KeyPairGenerator\.getInstance\s*\(\s*['"]EC['"].*BouncyCastle|KeyPairGenerator\.getInstance\s*\(\s*['"]ECDSA['"].*BouncyCastle|new\s+RSAKeyPairGenerator\s*\(|new\s+ECKeyPairGenerator\s*\(/i, alt: "CRYSTALS-Kyber or CRYSTALS-Dilithium via BouncyCastle PQC provider" },
  { id: "dotnet-rsa-ecdsa-sign-verify", name: ".NET RSA/ECDSA SignData/VerifyData", sev: "high", re: /\.SignData\s*\(.*RSA|\.VerifyData\s*\(.*RSA|\.SignData\s*\(.*ECDSA|\.VerifyData\s*\(.*ECDSA|RSACryptoServiceProvider\s*\(|ECDsaCng\s*\(|RSACng\.SignData|ECDsa\.SignData/i, alt: "ML-DSA-65 (NIST FIPS 204) via future .NET PQC libraries" },
  { id: "php-openssl-ec-keygen", name: "PHP openssl EC key generation", sev: "high", re: /openssl_pkey_new\s*\(.*['"](ec|EC)_KEY|openssl_pkey_new\s*\(.*prime256v1|openssl_pkey_new\s*\(.*secp256k1|openssl_pkey_new\s*\(.*secp384r1|phpseclib.*ECDSA.*createKey|phpseclib.*EC.*createKey/i, alt: "Post-quantum signatures via sodium_crypto_sign (Ed25519 interim) or future ML-DSA bindings" },
  { id: "swift-cryptokit-p256-sign", name: "Swift CryptoKit P256 signing", sev: "high", re: /P256\.Signing\.PrivateKey\s*\(|P256\.KeyAgreement\.PrivateKey\s*\(|P384\.Signing\.PrivateKey\s*\(|P521\.Signing\.PrivateKey\s*\(|Curve25519\.Signing\.PrivateKey\s*\(/i, alt: "Post-quantum signatures (ML-DSA) via future Swift PQC libraries or CryptoKit updates" },
    // AUTO-ADDED by scanner-evolution-agent 2026-06-24
  { id: "go-crypto-dsa", name: "Go stdlib DSA key operations", sev: "high", re: /dsa\.GenerateParameters\s*\(|dsa\.GenerateKey\s*\(|dsa\.Sign\s*\(|dsa\.Verify\s*\(|\*dsa\.PrivateKey|\*dsa\.PublicKey/i, alt: "ML-DSA-65 (NIST FIPS 204) via liboqs-go or circl" },
  { id: "scala-bouncycastle-rsa-ec", name: "Scala Bouncy Castle RSA/EC key operations", sev: "high", re: /RSAKeyPairGenerator|ECKeyPairGenerator|new\s+KeyPairGenerator\.getInstance\s*\(\s*["']RSA["']|new\s+KeyPairGenerator\.getInstance\s*\(\s*["']EC["']|org\.bouncycastle\.crypto\.generators\.(RSA|EC)KeyPairGenerator/i, alt: "ML-KEM-768 or ML-DSA-65 (NIST FIPS 203/204)" },
  { id: "rust-snow-noise-protocol", name: "Rust snow Noise Protocol (DH-based)", sev: "high", re: /snow::(Builder|HandshakeState|TransportState)|NoiseBuilder::new|\bNoise(IK|XX|KK|NK|XK|N|K|X)\b|params\s*:\s*NoiseParams|25519.*ChaChaPoly|snow::params::NoiseParams/i, alt: "PQ Noise with Kyber/ML-KEM via pqnoise or hybrid extensions" },
  { id: "libsodium-box-scalarmult", name: "libsodium Curve25519 box/scalarmult", sev: "high", re: /crypto_box_keypair\s*\(|crypto_box_seal\s*\(|crypto_scalarmult_base\s*\(|crypto_scalarmult\s*\(|crypto_kx_keypair\s*\(|crypto_kx_client_session_keys\s*\(|crypto_kx_server_session_keys\s*\(/i, alt: "ML-KEM-768 (NIST FIPS 203) via liboqs" },
  // LOW — informational
  { id: "hardcoded-key",name: "Hardcoded key",            sev: "low",      re: /(?:private_key|secret_key|encryption_key|aes_key|rsa_key)\s*=\s*["'][^"']{16,}["']|-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/i }, // quantumscan-ignore
  { id: "crc32",        name: "CRC32 for integrity",      sev: "low",      re: /crc32.*(?:integrity|verify|validate)|(?:integrity|verify|validate).*crc32|CRC32C?\.(?:compute|calculate|verify)/i, alt: "SHA-256 or BLAKE3" }, // quantumscan-ignore
  { id: "sha256-kdf",   name: "SHA-256 as password KDF",  sev: "low",      re: /sha256.*(?:password|passphrase)\b|(?:password|passphrase).*sha256/i, alt: "Argon2id or bcrypt" }, // quantumscan-ignore
  { id: "dh-1024",      name: "DH 1024-bit params",       sev: "low",      re: /DHParameterSpec\s*\(\s*1024|generate_parameters.*1024|dhparam\s+1024/i, alt: "ML-KEM" }, // quantumscan-ignore
  // HIGH — new patterns added 2026-06-24 v1.9.0 — coverage for Rust SSH, libssh, pyOpenSSL, .NET ECDiffieHellman, Go elliptic, Java EdDSA
  { id: "rust-russh-ssh",       name: "Rust russh/thrussh SSH",             sev: "high",   re: /\buse\s+russh::|use\s+thrussh::|russh::client::|russh::server::|ClientConfig::with_crypto_config|russh_keys::|thrussh_keys::|russh::ChannelMsg/g,                                   desc: "Rust russh/thrussh SSH library (Curve25519/RSA key exchange)",            pqcAlt: "Migrate SSH key exchange to PQC-hybrid ML-KEM-768 + X25519 (RFC 9370)" },
  { id: "rust-ssh2-libssh2",    name: "Rust ssh2 (libssh2 bindings)",        sev: "high",   re: /\bssh2::Session\b|ssh2::Channel\b|\.handshake\(\)|\.userauth_password\b|\.userauth_pubkey_file\b|ssh2::PublicKey\b|\buse\s+ssh2::/g,                              desc: "Rust ssh2 crate (libssh2 bindings) uses RSA/ECDSA/Ed25519",              pqcAlt: "Replace with PQC-hybrid SSH key exchange; use ML-KEM-768 + X25519" },
  { id: "c-libssh-api",         name: "libssh C API (SSH session/key)",       sev: "high",   re: /\bssh_new\s*\(\)|ssh_connect\s*\(|ssh_generate_keypair\s*\(|ssh_pki_generate\s*\(|ssh_key_type\s*\(|ssh_options_set\s*\(|SSH_KEYTYPE_RSA\b|SSH_KEYTYPE_ECDSA\b|ssh_userauth_publickey/g, desc: "libssh C API — SSH session and key operations (RSA/ECDSA/Ed25519)",    pqcAlt: "Migrate to PQC-hybrid SSH; use ML-KEM-768 for key encapsulation (RFC 9370)" },
  { id: "java-eddsa-net-i2p",   name: "Java EdDSA / Ed25519 (net.i2p)",      sev: "high",   re: /net\.i2p\.crypto\.eddsa|\bEdDSAEngine\b|EdDSAPrivateKeySpec\b|EdDSAPublicKeySpec\b|EdDSASecurityProvider\b|\bnew\s+EdDSAPrivateKey|EdDSASigner\b/g,             desc: "Java net.i2p.crypto.eddsa (Ed25519) — used by Apache MINA SSHD",       pqcAlt: "Replace Ed25519 with ML-DSA (NIST FIPS 204) for post-quantum signatures" },
  { id: "python-pyopenssl",     name: "Python pyOpenSSL classical key ops",   sev: "high",   re: /from\s+OpenSSL(?:\.crypto)?\s+import|OpenSSL\.crypto\.PKey\(\)|crypto\.TYPE_RSA\b|crypto\.TYPE_DSA\b|crypto\.TYPE_EC\b|crypto\.PKey\(\)|X509Req\s*\(\)|\bload_certificate\b|\bcrypto\.dump_privatekey|\bcrypto\.dump_publickey/g, desc: "Python pyOpenSSL — classical RSA/ECDSA/DSA key generation and handling",  pqcAlt: "Migrate to pyca/cryptography with ML-KEM-768 (FIPS 203) / ML-DSA (FIPS 204)" },
  { id: "csharp-ecdh-create",   name: ".NET ECDiffieHellman key agreement",   sev: "high",   re: /ECDiffieHellman\.Create\s*\(|ECDiffieHellmanCng\b|\bnew\s+ECDiffieHellmanCng\s*\(|DeriveKeyMaterial\b|DeriveKeyFromHash\b|DeriveKeyFromHmac\b|DeriveKeyTls\s*\(/g,    desc: ".NET ECDiffieHellman (ECDH) key agreement — vulnerable to Shor's algorithm", pqcAlt: "Replace ECDH key agreement with ML-KEM-768 (NIST FIPS 203)" },
  { id: "go-crypto-elliptic",   name: "Go crypto/elliptic curve operations",  sev: "high",   re: /elliptic\.P256\s*\(\)|elliptic\.P384\s*\(\)|elliptic\.P521\s*\(\)|elliptic\.Marshal\s*\(|elliptic\.Unmarshal\s*\(|elliptic\.GenerateKey\s*\(|\becdh\.P256\(\)|ecdh\.P384\(\)|ecdh\.P521\(\)/g,       desc: "Go crypto/elliptic and crypto/ecdh NIST curve operations",              pqcAlt: "Replace NIST curves with ML-KEM-768 (FIPS 203) for KEM or ML-DSA (FIPS 204) for signatures" },
  { id: "java-pkcs11-classical", name: "Java PKCS#11 classical key provider",  sev: "high",   re: /sun\.security\.pkcs11|SunPKCS11\b|PKCS11\.getInstance\b|new\s+sun\.security\.pkcs11\.SunPKCS11|pkcs11\.jar|iaik\.pkcs\.pkcs11|iaik\.security\.provider\.IAIK|\bPKCS11KeyStore\b/g, desc: "Java PKCS#11 provider — hardware/software token storing RSA/EC keys",      pqcAlt: "Upgrade HSM/token firmware for PQC; use ML-KEM / ML-DSA where supported" },

];

// ── Vulnerable dependencies ───────────────────────────────────────────────────
const VULNERABLE_DEPS = [
  // npm / package.json
  { pkg: "node-forge",       eco: "npm",    sev: "high",     reason: "RSA/ECDSA/DH crypto library",               alt: "Web Crypto API + liboqs-js" }, // quantumscan-ignore
  { pkg: "jsrsasign",        eco: "npm",    sev: "high",     reason: "RSA/ECDSA/DSA signatures",                  alt: "ml-dsa" }, // quantumscan-ignore
  { pkg: "elliptic",         eco: "npm",    sev: "high",     reason: "Elliptic curve crypto (secp256k1, P-256)",   alt: "ml-kem / ml-dsa" }, // quantumscan-ignore
  { pkg: "secp256k1",        eco: "npm",    sev: "high",     reason: "secp256k1 curve (Shor-vulnerable)",         alt: "ml-dsa for signatures" }, // quantumscan-ignore
  { pkg: "bitcoinjs-lib",    eco: "npm",    sev: "high",     reason: "secp256k1 Bitcoin transactions",            alt: "Monitor BIP-360 draft" }, // quantumscan-ignore
  { pkg: "@noble/secp256k1", eco: "npm",    sev: "high",     reason: "secp256k1 (Shor-vulnerable)",               alt: "ml-dsa" }, // quantumscan-ignore
  { pkg: "noble-secp256k1",  eco: "npm",    sev: "high",     reason: "secp256k1",                                 alt: "ml-dsa" }, // quantumscan-ignore
  { pkg: "@noble/curves",    eco: "npm",    sev: "high",     reason: "ECC curves including secp256k1 and P-256",  alt: "ml-kem / ml-dsa" }, // quantumscan-ignore
  { pkg: "@noble/bls12-381",eco: "npm",    sev: "high",     reason: "BLS12-381 pairing curve (quantum-vulnerable)", alt: "No NIST PQC pairing standard yet — monitor IETF PQC pairings WG" }, // quantumscan-ignore
  { pkg: "bls-eth-wasm",    eco: "npm",    sev: "high",     reason: "Ethereum BLS12-381 validator signatures",   alt: "Monitor Ethereum PQC roadmap (EIP-7786)" }, // quantumscan-ignore
  // Solidity / DeFi ecosystem
  { pkg: "@openzeppelin/contracts",            eco: "npm", sev: "high",   reason: "ECDSA.sol / EIP712.sol / SignatureChecker.sol — secp256k1 signature verification", alt: "Monitor OpenZeppelin PQC contracts — no drop-in replacement yet" }, // quantumscan-ignore
  { pkg: "@openzeppelin/contracts-upgradeable",eco: "npm", sev: "high",   reason: "Upgradeable ECDSA/EIP712 contracts — same quantum exposure",                       alt: "Monitor OpenZeppelin PQC contracts" }, // quantumscan-ignore
  { pkg: "@chainlink/contracts",               eco: "npm", sev: "high",   reason: "Chainlink oracle interfaces — DON aggregation uses secp256k1 ECDSA",               alt: "Monitor Chainlink PQC roadmap" }, // quantumscan-ignore
  { pkg: "@safe-global/safe-contracts",        eco: "npm", sev: "high",   reason: "Gnosis Safe — N-of-M secp256k1 ECDSA multi-sig verification",                     alt: "Monitor Safe{Wallet} PQC migration" }, // quantumscan-ignore
  { pkg: "jose",             eco: "npm",    sev: "medium",   reason: "Supports RS256/ES256 JWT algorithms",       alt: "Use HS256 only until PQC JOSE RFC" }, // quantumscan-ignore
  { pkg: "jsonwebtoken",     eco: "npm",    sev: "medium",   reason: "RS256/ES256 JWT by default",                alt: "Use HS256 algorithms only" }, // quantumscan-ignore
  { pkg: "ssh2",             eco: "npm",    sev: "high",     reason: "RSA/ECDSA SSH host keys",                   alt: "Monitor OpenSSH PQC roadmap" }, // quantumscan-ignore
  { pkg: "forge",            eco: "npm",    sev: "high",     reason: "Alias for node-forge — RSA/ECDSA",          alt: "Web Crypto API + liboqs-js" }, // quantumscan-ignore
  // Python / requirements.txt
  { pkg: "ecdsa",            eco: "python", sev: "critical", reason: "Pure ECDSA — named after the broken algo",  alt: "pqcrypto (dilithium)" }, // quantumscan-ignore
  { pkg: "python-ecdsa",     eco: "python", sev: "critical", reason: "Pure ECDSA implementation",                alt: "pqcrypto (dilithium)" }, // quantumscan-ignore
  { pkg: "pyOpenSSL",        eco: "python", sev: "high",     reason: "RSA/ECDSA TLS operations",                 alt: "Monitor OpenSSL PQC roadmap" }, // quantumscan-ignore
  { pkg: "pyjwt",            eco: "python", sev: "medium",   reason: "RS256/ES256/PS256 JWT support",            alt: "Use HS256 algorithms only" }, // quantumscan-ignore
  { pkg: "python-jose",      eco: "python", sev: "medium",   reason: "RSA/ECDSA JWT",                            alt: "Use HS256 only" }, // quantumscan-ignore
  { pkg: "paramiko",         eco: "python", sev: "high",     reason: "RSA/ECDSA SSH transport",                  alt: "Monitor OpenSSH PQC roadmap" }, // quantumscan-ignore
  { pkg: "eth-account",      eco: "python", sev: "high",     reason: "secp256k1 Ethereum accounts",              alt: "Monitor ethereum PQC roadmap" }, // quantumscan-ignore
  { pkg: "coincurve",        eco: "python", sev: "high",     reason: "secp256k1 Python bindings",                alt: "pqcrypto (dilithium)" }, // quantumscan-ignore
  // Java / pom.xml (groupId prefix match)
  { pkg: "org.bouncycastle", eco: "maven",  sev: "high",     reason: "RSA/ECDSA/DSA — use bcpqc for PQC",        alt: "Upgrade to bcpqc jar (Bouncy Castle PQC)" }, // quantumscan-ignore
  { pkg: "org.apache.sshd", eco: "maven",  sev: "high",     reason: "Apache MINA SSHD — RSA/ECDSA host keys & auth", alt: "Monitor Apache MINA PQC roadmap; prefer mlkem768x25519 KEX" }, // quantumscan-ignore
  { pkg: "com.jcraft",      eco: "maven",  sev: "high",     reason: "JSch — RSA/ECDSA SSH transport",               alt: "Monitor OpenSSH PQC roadmap" }, // quantumscan-ignore
  { pkg: "net.schmizz",     eco: "maven",  sev: "high",     reason: "sshj — RSA/ECDSA SSH transport",               alt: "Monitor PQC KEX support in sshj" }, // quantumscan-ignore
  { pkg: "io.jsonwebtoken",  eco: "maven",  sev: "medium",   reason: "RS256/ES256 JWT",                          alt: "Use HS256 algorithms only" }, // quantumscan-ignore
  { pkg: "com.auth0:java-jwt",eco: "maven", sev: "medium",   reason: "RSA/ECDSA JWT support",                    alt: "Use HMAC algorithms only" }, // quantumscan-ignore
  // Go / go.mod
  { pkg: "golang.org/x/crypto", eco: "go", sev: "medium",   reason: "Contains Ed25519, x/crypto/ssh, ECDH",     alt: "stdlib crypto/ecdh; await Go stdlib ML-KEM" }, // quantumscan-ignore
  // Rust / Cargo.toml
  { pkg: "rsa",              eco: "rust",   sev: "high",     reason: "RSA crate (Shor-vulnerable)",              alt: "pqcrypto-kyber or oqs-rs" }, // quantumscan-ignore
  { pkg: "ecdsa",            eco: "rust",   sev: "high",     reason: "ECDSA crate",                              alt: "pqcrypto-dilithium" }, // quantumscan-ignore
  { pkg: "secp256k1",        eco: "rust",   sev: "high",     reason: "secp256k1 crate",                          alt: "pqcrypto-dilithium" }, // quantumscan-ignore
  { pkg: "k256",             eco: "rust",   sev: "high",     reason: "k256 (secp256k1) crate",                   alt: "pqcrypto-dilithium" }, // quantumscan-ignore
  { pkg: "p256",             eco: "rust",   sev: "high",     reason: "p256 (NIST P-256) crate",                  alt: "pqcrypto-dilithium" }, // quantumscan-ignore
  { pkg: "ed25519-dalek",    eco: "rust",   sev: "high",     reason: "Ed25519 (Shor-vulnerable)",                alt: "ML-DSA via pqcrypto-dilithium" }, // quantumscan-ignore
  { pkg: "x25519-dalek",     eco: "rust",   sev: "high",     reason: "X25519 key exchange (Shor-vulnerable)",    alt: "ML-KEM via pqcrypto-kyber" }, // quantumscan-ignore
  { pkg: "ring",             eco: "rust",   sev: "high",     reason: "ring crate — RSA/ECDSA/ECDH operations",   alt: "pqcrypto-kyber for KEM; pqcrypto-dilithium for signatures" }, // quantumscan-ignore
  { pkg: "bls12-381",       eco: "rust",   sev: "high",     reason: "BLS12-381 pairing curve (quantum-vulnerable)", alt: "No NIST PQC pairing standard yet — monitor IETF PQC pairings WG" }, // quantumscan-ignore
  { pkg: "bls_signatures",  eco: "rust",   sev: "high",     reason: "BLS signatures over BLS12-381",             alt: "ML-DSA (NIST FIPS 204) for non-aggregation use cases" }, // quantumscan-ignore
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

// ── Crypto library detector ───────────────────────────────────────────────────
const CRYPTO_LIB_HINTS = /\b(crypto|cipher|ssl|tls|ssh|rsa|ecdsa|ecdh|dsa|dh|pgp|gpg|tink|botan|openssl|libsodium|nacl|bcrypt|argon|signal|noise|kyber|dilithium|falcon|sphincs|pqcrypto|liboqs|mina.?sshd|jsch|paramiko)\b/i; // quantumscan-ignore

function mayBeCryptoLib(targetDir, allFiles) {
  if (CRYPTO_LIB_HINTS.test(basename(targetDir))) return true;
  const cHeaders = allFiles.filter(f => /\.(c|h|cpp|hpp)$/.test(f)).length;
  return cHeaders >= 5;
}

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

function printResults(findings, totalFiles, scannableCount, targetDir, score, depCount, isCryptoLib) {
  console.log(`\n${C.bold}QuantumScan v${VERSION}${C.reset}  Post-Quantum Cryptography Scanner`);
  console.log(`${C.cyan}${APP_URL}${C.reset}`);
  console.log(hr());
  console.log(`Path     ${C.bold}${targetDir}${C.reset}`);
  console.log(`Files    ${C.gray}${totalFiles} total · ${scannableCount} scannable${C.reset}`);
  if (depCount > 0) console.log(`Deps     ${C.gray}${depCount} vulnerable package(s) found${C.reset}`);
  if (isCryptoLib || score <= 20) {
    console.log(`${C.yellow}Coverage ${C.reset}${C.dim}score ≤ 20 or this looks like a crypto library — patterns cover API usage,`);
    console.log(`         not JCA/OpenSSL/C implementation internals. Score may undercount.`);
    console.log(`         Run full cloud analysis at ${APP_URL} for deeper coverage.${C.reset}`);
  }
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
    console.log(`\n${C.dim}Migrate to: ML-KEM (key encap, FIPS 203) · ML-DSA (signatures, FIPS 204)${C.reset}`); // quantumscan-ignore
    console.log(`${C.dim}Required by NIST, DORA, NIS2, CNSA 2.0 — deadline 2030.${C.reset}`);
    console.log(`\n${C.cyan}Full AI analysis + migration guides → ${APP_URL}${C.reset}`);
    console.log(`${C.dim}Add ${C.reset}${C.bold}// quantumscan-ignore${C.reset}${C.dim} to suppress a false positive.${C.reset}`);
  }
  console.log(`\n${C.dim}If this was useful → ⭐ ${C.reset}${C.bold}github.com/quantumscan-io/scanner-core${C.reset}`);
  console.log("");
}

// ── JSON output ───────────────────────────────────────────────────────────────
function printJson(findings, totalFiles, scannableCount, targetDir, score, isCryptoLib) {
  const summary = { riskScore: score };
  for (const sev of SEV_ORDER) summary[sev] = findings.filter(f => f.sev === sev).length;
  summary.dependencies = findings.filter(f => f.type === "dependency").length;
  console.log(JSON.stringify({
    version: VERSION,
    path: targetDir,
    stats: { totalFiles, scannableFiles: scannableCount },
    coverage: (isCryptoLib || score <= 20)
      ? "partial — crypto library or low score: implementation-level patterns may not be fully covered"
      : "standard",
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
    fullDescription: { text: "A dependency uses quantum-vulnerable cryptography (RSA, ECDSA, or similar)." }, // quantumscan-ignore
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

function printBadge(slug, dir) {
  const badgeUrl = `https://quantumscan.io/api/badge/${slug}.svg`;
  const scanUrl  = `https://quantumscan.io/en/scan`;
  const hasRst   = existsSync(join(dir, "README.rst")) || existsSync(join(dir, "readme.rst")) || existsSync(join(dir, "README.RST"));
  if (hasRst) {
    console.log(`\n${C.cyan}README badge (RST syntax for README.rst):${C.reset}`);
    console.log(`${C.bold}.. image:: ${badgeUrl}${C.reset}`);
    console.log(`${C.bold}   :target: ${scanUrl}${C.reset}`);
    console.log(`${C.bold}   :alt: QuantumScan${C.reset}`);
  } else {
    console.log(`\n${C.cyan}README badge (add to your README.md):${C.reset}`);
    console.log(`${C.bold}[![QuantumScan](${badgeUrl})](${scanUrl})${C.reset}`);
  }
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
  --no-code          Skip source code scanning (only scan dependencies)
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
  const noCode    = args.includes("--no-code");
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
  const codeFindings    = noCode ? [] : scannableFiles.flatMap(f => scanFile(f, targetDir));
  const depFindings     = noDeps ? [] : scanDependencies(targetDir);
  const allFindings     = [...codeFindings, ...depFindings];
  const score           = calcScore(allFindings);
  const isCryptoLib     = mayBeCryptoLib(targetDir, allFiles);

  if (sarifMode) {
    printSarif(allFindings, targetDir);
  } else if (jsonMode) {
    printJson(allFindings, allFiles.length, scannableFiles.length, targetDir, score, isCryptoLib);
  } else {
    printResults(allFindings, allFiles.length, scannableFiles.length, targetDir, score, depFindings.length, isCryptoLib);
    if (badgeMode) {
      const slug = detectRepoSlug(targetDir);
      if (slug) printBadge(slug, targetDir);
      else console.log(`\n${C.dim}--badge: could not detect GitHub remote.${C.reset}\n`);
    }
  }

  exit(noFail || allFindings.length === 0 ? 0 : 1);
}

main();


