/**
 * context.js — cryptographic context model
 *
 * A regex hit is a *detection*, not a vulnerability. This module turns a raw
 * pattern match into a structured record so that severity is assigned only
 * after execution context and authority are established.
 *
 * Three separate outputs are produced from the same detections:
 *   1. INVENTORY  — what primitive/construction exists.
 *   2. EXPOSURE   — what must eventually be replaced (migration surface).
 *   3. SECURITY   — what an attacker could actually authorize/forge/decrypt.
 *
 * Every derived field carries an evidence class. Static analysis cannot
 * confirm reachability or authority; it can only derive them. Fields we
 * cannot establish are reported as "unknown", never silently defaulted to
 * the worst case.
 */

// ── Enumerations ──────────────────────────────────────────────────────────────

/** What the primitive is actually used for. Determines the threat model. */
export const FUNCTION = {
  KEY_ESTABLISHMENT: "key-establishment",   // ML-KEM replaces this
  SIGNATURE: "signature",                    // ML-DSA / SLH-DSA replace this
  ASYM_ENCRYPTION: "asym-encryption",        // confidentiality via public key
  SYMMETRIC: "symmetric",                    // AES/ChaCha — Grover only
  HASH: "hash",                              // digest / commitment
  KDF: "kdf",
  RNG: "rng",
  CONSENSUS_PROOF: "consensus-proof",        // BLS aggregation, pairing, VRF
  TRANSPORT: "transport",                    // TLS/SSH suite configuration
  ENCODING: "encoding",                      // EIP-712 & friends — NOT an algorithm
  AMBIGUOUS: "ambiguous",                    // e.g. bare "RSA": sign or encrypt?
  UNKNOWN: "unknown",
};

/** How quantum computing actually affects this finding. */
export const THREAT = {
  HNDL: "harvest-now-decrypt-later",     // recorded ciphertext decrypted later
  FORGERY: "future-signature-forgery",   // authority compromised / signature forged
  GROVER: "search-speed-reduction",      // symmetric/hash — halved effective bits
  MIGRATION_DEBT: "migration-debt",      // must change, but no direct quantum break
  CLASSICAL_BREAK: "classical-break",    // already broken today, quantum irrelevant
  UNRESOLVED: "unresolved",
};

/** Where in the stack the primitive runs. Different planes migrate separately. */
export const PLANE = {
  WALLET: "wallet",
  ACCOUNT_VALIDATOR: "account-validator",
  CONTRACT: "contract",
  BRIDGE: "bridge",
  ORACLE: "oracle",
  SEQUENCER: "sequencer",
  GOVERNANCE: "governance",
  PARENT_CHAIN: "parent-chain-settlement",
  TRANSPORT: "transport",
  APPLICATION: "application",
  UNKNOWN: "unknown",
};

/** Can this code actually run in production? */
export const REACHABILITY = {
  ACTIVE: "active",
  CONDITIONAL: "conditional",
  TEST_ONLY: "test-only",
  INTERFACE_ONLY: "interface-only",
  LIBRARY_DEFINITION: "library-definition",
  UNREFERENCED: "unreferenced",
  UNKNOWN: "unknown",
};

/** What state transition the key behind this finding can authorize. */
export const AUTHORITY = {
  UPGRADE: "upgrade-authority",
  GOVERNANCE: "governance-execution",
  BRIDGE: "bridge-authorization",
  ASSET: "asset-movement",
  ACCESS_CONTROL: "access-control",
  PAUSE: "emergency-pause",
  ORACLE_REPORT: "oracle-report",
  USER_SCOPED: "user-scoped",
  NONE_IDENTIFIED: "none-identified",
  UNKNOWN: "unknown",
};

/** Is the public key visible to an attacker before the quantum era ends? */
export const PK_EXPOSURE = {
  EXPOSED: "exposed",                 // published on-chain / in every handshake
  REPEATEDLY_EXPOSED: "repeatedly-exposed",
  HIDDEN: "hidden",                   // hash-protected until first spend
  NOT_APPLICABLE: "not-applicable",
  UNKNOWN: "unknown",
};

export const LIFETIME = {
  EPHEMERAL: "ephemeral",     // bound by nonce/deadline
  ROTATING: "rotating",
  LONG_LIVED: "long-lived",
  PERMANENT: "permanent",     // immutable, no rotation path
  UNKNOWN: "unknown",
};

export const UPGRADEABILITY = {
  IMMUTABLE: "immutable",
  PROXY_UPGRADEABLE: "proxy-upgradeable",
  MODULE_REPLACEABLE: "module-replaceable",
  GOVERNANCE_CONTROLLED: "governance-controlled",
  UNKNOWN: "unknown",
};

export const MIGRATION_STATUS = {
  INVENTORY_ONLY: "inventory-only",
  PQ_CAPABLE: "pq-capable",
  HYBRID: "hybrid",
  CLASSICAL_DISABLED: "classical-disabled",
  END_TO_END_BLOCKED: "end-to-end-blocked",
  UNKNOWN: "unknown",
};

/** How strong is our claim about this record? */
export const EVIDENCE = {
  DETECTED: "detected",       // regex matched — a fact about the source text
  DERIVED: "derived",         // inferred from path/context heuristics
  CONFIRMED: "confirmed",     // human or dynamic analysis verified — never auto-set
  UNRESOLVED: "unresolved",   // we looked and could not establish it
};

/** Which of the three reports this record belongs to. */
export const LAYER = {
  INVENTORY: "inventory",
  EXPOSURE: "migration-exposure",
  SECURITY: "security-critical",
};

// ── Pattern → cryptographic function map ─────────────────────────────────────
// Keyed by pattern id from index.js. Anything unmapped falls back to
// FUNCTION.UNKNOWN and is reported as unresolved rather than assumed critical.

export const FUNCTION_MAP = {
  // Already broken classically — quantum is not the reason these are bad.
  "ssl-v2-v3":   { fn: FUNCTION.TRANSPORT, threat: THREAT.CLASSICAL_BREAK },
  "tls-old":     { fn: FUNCTION.TRANSPORT, threat: THREAT.CLASSICAL_BREAK },
  "md5":         { fn: FUNCTION.HASH,      threat: THREAT.CLASSICAL_BREAK },
  "sha1":        { fn: FUNCTION.HASH,      threat: THREAT.CLASSICAL_BREAK },
  "des":         { fn: FUNCTION.SYMMETRIC, threat: THREAT.CLASSICAL_BREAK },
  "3des":        { fn: FUNCTION.SYMMETRIC, threat: THREAT.CLASSICAL_BREAK },
  "rc4":         { fn: FUNCTION.SYMMETRIC, threat: THREAT.CLASSICAL_BREAK },
  "rc2":         { fn: FUNCTION.SYMMETRIC, threat: THREAT.CLASSICAL_BREAK },
  "ecb":         { fn: FUNCTION.SYMMETRIC, threat: THREAT.CLASSICAL_BREAK },
  "nullcipher":  { fn: FUNCTION.SYMMETRIC, threat: THREAT.CLASSICAL_BREAK },
  "cbc":         { fn: FUNCTION.SYMMETRIC, threat: THREAT.CLASSICAL_BREAK },
  "blowfish":    { fn: FUNCTION.SYMMETRIC, threat: THREAT.CLASSICAL_BREAK },
  "hmacsha1":    { fn: FUNCTION.HASH,      threat: THREAT.CLASSICAL_BREAK },
  "openssl-old": { fn: FUNCTION.TRANSPORT, threat: THREAT.CLASSICAL_BREAK },
  "rsa-small":   { fn: FUNCTION.AMBIGUOUS, threat: THREAT.CLASSICAL_BREAK },
  "solidity-ecrecover-raw-pack": { fn: FUNCTION.SIGNATURE, threat: THREAT.CLASSICAL_BREAK },

  // Grover only — halves effective key length, does not break the primitive.
  "aes128":      { fn: FUNCTION.SYMMETRIC, threat: THREAT.GROVER },
  "pbkdf2-low":  { fn: FUNCTION.KDF,       threat: THREAT.GROVER },
  "math-random": { fn: FUNCTION.RNG,       threat: THREAT.CLASSICAL_BREAK },

  // Key establishment / confidentiality → ML-KEM. This is where HNDL applies.
  "ecdh":              { fn: FUNCTION.KEY_ESTABLISHMENT, threat: THREAT.HNDL },
  "dh":                { fn: FUNCTION.KEY_ESTABLISHMENT, threat: THREAT.HNDL },
  "x25519":            { fn: FUNCTION.KEY_ESTABLISHMENT, threat: THREAT.HNDL },
  "node-crypto-ecdh":  { fn: FUNCTION.KEY_ESTABLISHMENT, threat: THREAT.HNDL },
  "java-jca-keyagree": { fn: FUNCTION.KEY_ESTABLISHMENT, threat: THREAT.HNDL },

  // Signatures / authorization → ML-DSA or SLH-DSA. HNDL does NOT apply here.
  "ecdsa":                    { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY },
  "dsa":                      { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY },
  "ed25519":                  { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY },
  "secp256k1":                { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY },
  "jwt-alg":                  { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY },
  "x509-gen":                 { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY },
  "java-jca-sig":             { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY },
  "openssl-dsa-gen":          { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY },
  "google-tink-ecdsa":        { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY },
  "rust-p256-ecdsa-crate":    { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY },
  "ed25519-dalek-rust":       { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY },
  "rust-ring":                { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY },
  "ethers-wallet":            { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.WALLET },
  "web3-accounts":            { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.WALLET },
  "bitcoinjs-ecpair":         { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.WALLET },
  "solana-keypair":           { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.WALLET },
  "rust-solana-sdk":          { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.WALLET },
  "eth-account-python":       { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.WALLET },
  "coincurve-secp256k1":      { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.WALLET },
  "rust-secp256k1-crate":     { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.WALLET },
  "tronweb-wallet":           { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.WALLET },
  "bip32-hd-wallet":          { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.WALLET },
  "libsecp256k1-capi":        { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.WALLET },
  "go-btcec-btcd":            { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.WALLET },
  "rust-dalek-curves":        { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY },
  "solidity-ecrecover":       { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.CONTRACT },
  "solidity-assembly-ecr":    { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.CONTRACT },
  "solidity-permit-eip2612":  { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.CONTRACT },
  "solidity-multisig-ecdsa":  { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.ACCOUNT_VALIDATOR },
  "solidity-oracle-chainlink":{ fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY, plane: PLANE.ORACLE },

  // Consensus / proof primitives — no NIST PQC replacement exists yet.
  "bls12-381": { fn: FUNCTION.CONSENSUS_PROOF, threat: THREAT.FORGERY },

  // Encoding & domain separation — NOT a signature algorithm.
  // The quantum exposure belongs to whichever validator consumes the digest.
  "solidity-eip712": { fn: FUNCTION.ENCODING, threat: THREAT.MIGRATION_DEBT, plane: PLANE.CONTRACT },

  // Account abstraction: a migration surface, not an intrinsic ECDSA dependency.
  // The account implementation decides what the signature field means.
  "erc4337-account":    { fn: FUNCTION.UNKNOWN,   threat: THREAT.MIGRATION_DEBT, plane: PLANE.ACCOUNT_VALIDATOR },
  // EIP-7702 authorization tuples are recovered with ecrecover — the original
  // classical root authority survives delegation.
  "eip7702-delegation": { fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY,        plane: PLANE.WALLET },

  // Ambiguous: the same API serves signing and encryption. Refuse to guess.
  "rsa":                    { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "pkcs1":                  { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "ecc":                    { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "p256":                   { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "p384":                   { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "p521":                   { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "java-jca-rsa":           { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "java-jca-ec-gen":        { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "java-jca-spi":           { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "openssl-rsa-gen":        { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "openssl-ec-gen":         { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "openssl-bn-prime":       { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "openssl-evp-cipher":     { fn: FUNCTION.SYMMETRIC, threat: THREAT.GROVER },
  "node-crypto-keygen":     { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "webcrypto-classical":    { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "python-hazmat-rsa":      { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "python-hazmat-ec":       { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "python-load-pem-key":    { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "csharp-rsa-create":      { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "csharp-rsa-cng":         { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "csharp-bc-rsa-ec":       { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "ruby-openssl-rsa-ecdsa": { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "kotlin-java-security-rsa-ec": { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "swift-seckey":           { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "android-keystore-classical": { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "aws-kms-rsa-classical":  { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "azure-keyvault-rsa-ec":  { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "php-openssl-asym":       { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "rust-rsa-crate":         { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "elixir-erlang-crypto":   { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
  "go-crypto-rsa":          { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },

  // Transport suites — both confidentiality (HNDL) and peer auth (forgery).
  "aws-s2n-tls":              { fn: FUNCTION.TRANSPORT, threat: THREAT.HNDL, plane: PLANE.TRANSPORT },
  "rustls-config":            { fn: FUNCTION.TRANSPORT, threat: THREAT.HNDL, plane: PLANE.TRANSPORT },
  "go-tls-classical-config":  { fn: FUNCTION.TRANSPORT, threat: THREAT.HNDL, plane: PLANE.TRANSPORT },
  "openssh-sshkey-gen":       { fn: FUNCTION.TRANSPORT, threat: THREAT.HNDL, plane: PLANE.TRANSPORT },
  "java-ssh-mina-jsch":       { fn: FUNCTION.TRANSPORT, threat: THREAT.HNDL, plane: PLANE.TRANSPORT },
  "java-mina-sshd-hostkey":   { fn: FUNCTION.TRANSPORT, threat: THREAT.HNDL, plane: PLANE.TRANSPORT },
  "csharp-ssh-net":           { fn: FUNCTION.TRANSPORT, threat: THREAT.HNDL, plane: PLANE.TRANSPORT },
  "csharp-sshnet-ecdsa":      { fn: FUNCTION.TRANSPORT, threat: THREAT.HNDL, plane: PLANE.TRANSPORT },
  "python-paramiko-key":      { fn: FUNCTION.TRANSPORT, threat: THREAT.HNDL, plane: PLANE.TRANSPORT },
  "python-asyncssh":          { fn: FUNCTION.TRANSPORT, threat: THREAT.HNDL, plane: PLANE.TRANSPORT },
  "go-xcrypto-ssh":           { fn: FUNCTION.TRANSPORT, threat: THREAT.HNDL, plane: PLANE.TRANSPORT },
  "openpgp-js":               { fn: FUNCTION.AMBIGUOUS, threat: THREAT.UNRESOLVED },
};

// ── Post-quantum capability signals ───────────────────────────────────────────
// Detecting these is how the scanner recognises migration *progress*. They are
// never findings; they raise migration status and enable bypass analysis.

// No word boundaries: these names are routinely embedded in camelCase
// identifiers (`verifyMLDSA`, `mlKemDecap`), and requiring \b would only detect
// the algorithm when it appears in prose such as a comment.
export const PQ_SIGNALS = [
  { id: "pq-ml-dsa",   name: "ML-DSA (FIPS 204)",   fn: FUNCTION.SIGNATURE,
    re: /ML[-_]?DSA|dilithium/i },
  { id: "pq-ml-kem",   name: "ML-KEM (FIPS 203)",   fn: FUNCTION.KEY_ESTABLISHMENT,
    re: /ML[-_]?KEM|kyber/i },
  { id: "pq-slh-dsa",  name: "SLH-DSA (FIPS 205)",  fn: FUNCTION.SIGNATURE,
    re: /SLH[-_]?DSA|sphincs(?:\+|plus)?/i },
  { id: "pq-falcon",   name: "FN-DSA / Falcon",     fn: FUNCTION.SIGNATURE,
    re: /FN[-_]?DSA|falcon(?:512|1024)/i },
  { id: "pq-liboqs",   name: "liboqs / oqs-provider", fn: FUNCTION.UNKNOWN,
    re: /\bliboqs\b|\boqs[-_]provider\b|\boqs::\b|pqcrypto[-_](?:dilithium|kyber|falcon|sphincsplus)/i },
  { id: "pq-stylus",   name: "Arbitrum Stylus contract", fn: FUNCTION.UNKNOWN,
    re: /stylus_sdk::|#\[entrypoint\]|stylus[-_]sdk|ArbWasm\b/i },
];

// ── Residual classical authority signals ──────────────────────────────────────
// A PQ verifier is worthless if a classical key can replace or bypass it.
// These are the paths that keep a classical root of authority alive.

export const BYPASS_SIGNALS = [
  { id: "owner",        label: "ECDSA owner / Ownable",        re: /\bonlyOwner\b|\bOwnable\b|\btransferOwnership\s*\(|\b_owner\b/ },
  { id: "proxy-admin",  label: "proxy admin / upgrade path",   re: /_authorizeUpgrade\s*\(|\bupgradeTo(?:AndCall)?\s*\(|ProxyAdmin\b|\bdiamondCut\s*\(|UUPSUpgradeable\b|TransparentUpgradeableProxy\b/ },
  { id: "module-mgr",   label: "module manager (Safe/4337)",   re: /\benableModule\s*\(|\bsetFallbackHandler\s*\(|\bsetValidator\s*\(|\baddValidator\s*\(|ModuleManager\b/ },
  { id: "guardian",     label: "guardian / social recovery",   re: /\bguardian\b|\brecoveryKey\b|\binitiateRecovery\s*\(|\bsocialRecovery\b/i },
  { id: "role-admin",   label: "role admin (AccessControl)",   re: /\bDEFAULT_ADMIN_ROLE\b|\bgrantRole\s*\(|\b_setupRole\s*\(|AccessControl\b/ },
  { id: "pause",        label: "emergency pause authority",    re: /\bwhenNotPaused\b|\b_pause\s*\(|\bPausable\b/ },
  { id: "eip7702",      label: "EIP-7702 residual EOA key",    re: /\bSetCode\b|\bauthorization[Ll]ist\b|\b0x04\b.*setcode|EIP[-_]?7702/i },
  { id: "ecrecover",    label: "ecrecover authority path",     re: /\becrecover\s*\(|ECDSA\.(?:recover|tryRecover)\s*\(/ },
];

// ── Migration-component signals ───────────────────────────────────────────────
// Where a PQ validator can be installed. Presence is good news, not a finding.

export const MIGRATION_COMPONENTS = [
  { id: "erc4337",  label: "ERC-4337 smart account",   re: /\bvalidateUserOp\s*\(|\bUserOperation\b|\bPackedUserOperation\b|\bIEntryPoint\b|\bEntryPoint\b/ },
  { id: "eip1271",  label: "EIP-1271 contract signature", re: /\bisValidSignature\s*\(|\bIERC1271\b|\bEIP1271\b|0x1626ba7e/i },
  { id: "safe",     label: "Safe module / validator",   re: /\bGnosisSafe\b|\bISafe\b|\bcheckNSignatures\s*\(|SafeSignature\b/ },
  { id: "eip7702",  label: "EIP-7702 delegation",       re: /EIP[-_]?7702|\bauthorization[Ll]ist\b|\bdelegateCode\b/i },
  { id: "stylus",   label: "Arbitrum Stylus verifier",  re: /stylus_sdk::|#\[entrypoint\]|ArbWasm\b/ },
  { id: "precompile", label: "signature precompile call", re: /staticcall\s*\([^,)]*,\s*0x0*[0-9a-f]{1,2}\s*,/ },
];

// ── Regulatory references ─────────────────────────────────────────────────────
// Each instrument states what it actually says. DORA Article 50 is titled
// "Administrative penalties and remedial measures" — it defines supervisory and
// sanctioning powers. It does not create a quantum-risk assessment duty and it
// does not set a 2030 PQC deadline. The 2030 date comes from the EU coordinated
// PQC transition roadmap, a separate policy instrument.

export const REGULATORY = [
  {
    id: "nist-fips",
    instrument: "NIST FIPS 203 / 204 / 205",
    says: "Finalised ML-KEM, ML-DSA and SLH-DSA as US federal standards (August 2024).",
    imposes: "Standardisation. No deadline for private-sector migration.",
  },
  {
    id: "eu-pqc-roadmap",
    instrument: "EU Coordinated Implementation Roadmap for the PQC Transition",
    says: "Member States should begin transitioning by end of 2026; critical infrastructures should transition as soon as possible and no later than end of 2030.",
    imposes: "Policy targets addressed to Member States and critical infrastructure.",
  },
  {
    id: "dora",
    instrument: "Regulation (EU) 2022/2554 (DORA)",
    says: "ICT risk-management framework for financial entities. Article 50 is titled 'Administrative penalties and remedial measures' and defines supervisory, investigatory and sanctioning powers.",
    imposes: "General ICT risk management. NOT a PQC-specific requirement, and Article 50 sets no 2030 quantum deadline.",
    correction: "Do not cite DORA Article 50 as the source of a 2030 PQC assessment deadline.",
  },
  {
    id: "cnsa-2",
    instrument: "NSA CNSA 2.0",
    says: "Timelines for US national security systems to adopt PQC algorithms.",
    imposes: "Applies to national security systems, not to DeFi protocols generally.",
  },
];

// ── Heuristics ────────────────────────────────────────────────────────────────

const TEST_PATH_RE = /(?:^|\/)(?:tests?|spec|specs|__tests__|__mocks__|mocks?|fixtures?|examples?|samples?|demos?|benchmarks?|testdata|e2e)(?:\/|$)/i;
const TEST_FILE_RE = /(?:\.(?:test|spec)\.[a-z]+$|\.t\.sol$|(?:^|\/)[A-Za-z0-9_]*(?:Test|Mock|Harness)\.sol$|_test\.go$|^test_.*\.py$|Test\.java$)/i;
const LIB_PATH_RE  = /(?:^|\/)(?:lib|libs|libraries|vendor|third[-_]?party|external|deps|node_modules)(?:\/|$)/i;

const SOL_SCOPE_RE = /^\s*(?:abstract\s+)?(contract|interface|library)\s+([A-Za-z_$][\w$]*)/;
const FN_DECL_RE   = /(?:^|\s)(?:function|def|fn|func|sub)\s+([A-Za-z_$][\w$]*)\s*[(<]/;

const PLANE_HINTS = [
  [PLANE.BRIDGE,        /bridge|gateway|inbox|outbox|cross[-_]?chain|messenger|l1l2|l2l1|teleport|portal/i],
  [PLANE.GOVERNANCE,    /governor|governance|timelock|\bdao\b|voting|council|proposal/i],
  [PLANE.ORACLE,        /oracle|aggregator|chainlink|price[-_]?feed|\bvrf\b|reporter/i],
  [PLANE.SEQUENCER,     /sequencer|batcher|batch[-_]?poster|inbox[-_]?reader|\bfeed\b/i],
  [PLANE.PARENT_CHAIN,  /rollup|assertion|challenge|settlement|state[-_]?commitment|outbox[-_]?proof/i],
  [PLANE.ACCOUNT_VALIDATOR, /account|validator|entry[-_]?point|4337|1271|paymaster|\bsafe\b|module/i],
  [PLANE.WALLET,        /wallet|keystore|signer|mnemonic|keypair|keyring/i],
  [PLANE.TRANSPORT,     /\btls\b|\bssl\b|\bssh\b|transport|handshake|socket/i],
];

// Matched against a function body. Names are matched as prefixes because the
// authority is usually reached through a wrapper (`_transferWithAuthorization`
// rather than a bare `_transfer`).
const AUTHORITY_HINTS = [
  [AUTHORITY.UPGRADE,       /_authorizeUpgrade|upgradeTo|setImplementation|diamondCut|\bupgrade[A-Za-z]*\s*\(/i],
  [AUTHORITY.GOVERNANCE,    /onlyGovernance|onlyTimelock|execute\s*\(.*proposal|queue\s*\(|governor/i],
  [AUTHORITY.BRIDGE,        /outboundTransfer|finalizeInbound|relayMessage|executeTransaction.*bridge|depositTo|withdrawTo/i],
  [AUTHORITY.ASSET,         /\b_?(?:safeTransfer|transfer|send|sendValue|mint|burn|withdraw|redeem|claim|deposit|stake|unstake)[A-Za-z]*\s*\(|\.call\s*\{\s*value\s*:/i],
  [AUTHORITY.ORACLE_REPORT, /submitReport|transmit\s*\(|fulfill(?:Random)?\w*\s*\(|latestRoundData/i],
  [AUTHORITY.ACCESS_CONTROL,/onlyOwner|onlyAdmin|onlyRole|grantRole|requiresAuth|hasRole/i],
  [AUTHORITY.PAUSE,         /_pause\s*\(|_unpause\s*\(|whenNotPaused/],
  [AUTHORITY.USER_SCOPED,   /msg\.sender\s*==|require\s*\(\s*msg\.sender|owner(?:Of)?\s*\(\s*tokenId/i],
];

const UPGRADEABILITY_HINTS = [
  [UPGRADEABILITY.PROXY_UPGRADEABLE,    /UUPSUpgradeable|TransparentUpgradeableProxy|BeaconProxy|ERC1967|_authorizeUpgrade|diamondCut|Initializable/],
  [UPGRADEABILITY.MODULE_REPLACEABLE,   /enableModule|setFallbackHandler|setValidator|addValidator|ModuleManager/],
  [UPGRADEABILITY.GOVERNANCE_CONTROLLED,/onlyGovernance|onlyTimelock|TimelockController/],
];

const EPHEMERAL_RE = /\bdeadline\b|\bexpiry\b|\bvalidUntil\b|\bvalidAfter\b|\bnonces?\b|\btimestamp\b/i;
const PERMANENT_RE = /\bimmutable\b|\bconstant\b/;

/** Look upward from a match for the nearest enclosing scope declaration. */
function enclosingScope(lines, idx) {
  for (let i = idx; i >= 0 && i > idx - 400; i--) {
    const sol = lines[i].match(SOL_SCOPE_RE);
    if (sol) return { kind: sol[1], name: sol[2] };
  }
  return null;
}

/**
 * Look upward for the nearest enclosing function. Returns the name plus the
 * declaration header, since visibility in Solidity trails the parameter list
 * (`function f(uint x) external returns (bool) {`).
 */
function enclosingFunction(lines, idx) {
  for (let i = idx; i >= 0 && i > idx - 120; i--) {
    const m = lines[i].match(FN_DECL_RE);
    if (!m) continue;
    let header = "";
    for (let j = i; j < Math.min(lines.length, i + 10); j++) {
      header += lines[j];
      if (lines[j].includes("{") || lines[j].includes(":")) break;
    }
    return { name: m[1], header };
  }
  return null;
}

/**
 * A reference count only proves unreachability for symbols that cannot be
 * called from outside the repository. Public and external entry points are
 * invoked by transactions and by downstream consumers, so a count of one means
 * "defined once", not "never called". Treating them as unreachable would hide
 * exactly the signature checks that matter most.
 */
const PRIVATE_DECL_RE  = /\b(?:internal|private|static)\b/;
const EXPORTED_DECL_RE = /\b(?:external|public|export|pub)\b/;

function isInternalOnly(name, header) {
  if (EXPORTED_DECL_RE.test(header)) return false;
  if (PRIVATE_DECL_RE.test(header)) return true;
  // Convention-based fallbacks: Solidity/Python underscore prefix.
  return name.startsWith("_");
}

/** Text window around the match — used when no enclosing function is found. */
function window(lines, idx, before = 40, after = 20) {
  return lines.slice(Math.max(0, idx - before), Math.min(lines.length, idx + after)).join("\n");
}

/**
 * The enclosing function body, bounded by the neighbouring function
 * declarations. Authority must be attributed to the function that contains the
 * match — a fixed line window bleeds in the privileges of adjacent functions
 * and reports, say, upgrade authority for a plain transfer.
 */
function functionBody(lines, idx) {
  let start = -1;
  for (let i = idx; i >= 0 && i > idx - 120; i--) {
    if (FN_DECL_RE.test(lines[i])) { start = i; break; }
  }
  // No enclosing function: the match sits at file or contract scope — an
  // import, a constant, a state variable. Those declare nothing and authorize
  // nothing, so no forward window may be used to attribute authority to them.
  if (start === -1) return null;

  let end = Math.min(lines.length, idx + 80);
  for (let i = idx + 1; i < end; i++) {
    if (FN_DECL_RE.test(lines[i])) { end = i; break; }
  }
  return lines.slice(start, end).join("\n");
}

export function classifyReachability(relPath, lines, idx, symbolCounts) {
  if (TEST_PATH_RE.test(relPath) || TEST_FILE_RE.test(relPath)) return REACHABILITY.TEST_ONLY;

  const scope = enclosingScope(lines, idx);
  if (scope?.kind === "interface") return REACHABILITY.INTERFACE_ONLY;

  if (LIB_PATH_RE.test(relPath)) return REACHABILITY.LIBRARY_DEFINITION;
  if (scope?.kind === "library" && symbolCounts && (symbolCounts.get(scope.name) ?? 0) <= 1) {
    return REACHABILITY.LIBRARY_DEFINITION;
  }

  const fn = enclosingFunction(lines, idx);
  if (fn && symbolCounts && (symbolCounts.get(fn.name) ?? 0) <= 1 &&
      isInternalOnly(fn.name, fn.header)) {
    return REACHABILITY.UNREFERENCED;
  }

  // A match guarded by an `if` on a feature flag is conditional, not active.
  const w = window(lines, idx, 6, 2);
  if (/\bif\s*\(\s*(?:!?\s*)?(?:legacy|deprecated|fallback|compat|enable|use)[A-Za-z_]*\s*[)&|=]/i.test(w)) {
    return REACHABILITY.CONDITIONAL;
  }

  return fn || scope ? REACHABILITY.ACTIVE : REACHABILITY.UNKNOWN;
}

export function classifyPlane(relPath, lines, idx, mappedPlane) {
  if (mappedPlane) return mappedPlane;
  const scope = enclosingScope(lines, idx);
  const haystack = `${relPath} ${scope?.name ?? ""}`;
  for (const [plane, re] of PLANE_HINTS) if (re.test(haystack)) return plane;
  const w = window(lines, idx, 30, 10);
  for (const [plane, re] of PLANE_HINTS) if (re.test(w)) return plane;
  return relPath.endsWith(".sol") ? PLANE.CONTRACT : PLANE.UNKNOWN;
}

/**
 * Index every function in a file by name so authority can be resolved one call
 * deep. The prevailing Solidity shape is a public entry point that verifies a
 * signature and then delegates the privileged effect to an internal function —
 * judging only the entry point's own body would report "no authority" for
 * exactly the signatures that move money.
 */
export function buildFunctionIndex(lines) {
  const index = new Map();
  const starts = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(FN_DECL_RE);
    if (m) starts.push({ name: m[1], line: i });
  }
  for (let k = 0; k < starts.length; k++) {
    const end = k + 1 < starts.length ? starts[k + 1].line : lines.length;
    index.set(starts[k].name, lines.slice(starts[k].line, end).join("\n"));
  }
  return index;
}

const CALLEE_RE = /([A-Za-z_$][\w$]*)\s*\(/g;

export function classifyAuthority(lines, idx, fnIndex = null) {
  const body = functionBody(lines, idx);
  if (body === null) return AUTHORITY.NONE_IDENTIFIED;
  for (const [authority, re] of AUTHORITY_HINTS) if (re.test(body)) return authority;

  // One hop: inspect the bodies of functions this one calls.
  if (fnIndex) {
    const seen = new Set();
    let m;
    CALLEE_RE.lastIndex = 0;
    while ((m = CALLEE_RE.exec(body)) !== null) {
      const callee = m[1];
      if (seen.has(callee) || !fnIndex.has(callee)) continue;
      seen.add(callee);
      const calleeBody = fnIndex.get(callee);
      for (const [authority, re] of AUTHORITY_HINTS) {
        if (re.test(calleeBody)) return authority;
      }
    }
  }

  return AUTHORITY.NONE_IDENTIFIED;
}

export function classifyUpgradeability(fileContent) {
  for (const [status, re] of UPGRADEABILITY_HINTS) if (re.test(fileContent)) return status;
  return PERMANENT_RE.test(fileContent) ? UPGRADEABILITY.IMMUTABLE : UPGRADEABILITY.UNKNOWN;
}

export function classifyLifetime(lines, idx, authority) {
  const w = window(lines, idx, 30, 15);
  if (EPHEMERAL_RE.test(w)) return LIFETIME.EPHEMERAL;
  if (authority === AUTHORITY.UPGRADE || authority === AUTHORITY.GOVERNANCE) return LIFETIME.LONG_LIVED;
  if (PERMANENT_RE.test(w)) return LIFETIME.PERMANENT;
  return LIFETIME.UNKNOWN;
}

export function classifyPkExposure(fn, plane) {
  if (fn === FUNCTION.SYMMETRIC || fn === FUNCTION.HASH || fn === FUNCTION.KDF ||
      fn === FUNCTION.RNG || fn === FUNCTION.ENCODING) {
    return PK_EXPOSURE.NOT_APPLICABLE;
  }
  // On-chain verification republishes the key material with every use.
  if (plane === PLANE.CONTRACT || plane === PLANE.BRIDGE || plane === PLANE.ORACLE ||
      plane === PLANE.ACCOUNT_VALIDATOR || plane === PLANE.GOVERNANCE) {
    return PK_EXPOSURE.REPEATEDLY_EXPOSED;
  }
  if (plane === PLANE.TRANSPORT) return PK_EXPOSURE.EXPOSED;
  return PK_EXPOSURE.UNKNOWN;
}

// ── Layer assignment and severity ─────────────────────────────────────────────

const SEV_SCALE = ["info", "low", "medium", "high", "critical"];
const bump = (sev, n) => SEV_SCALE[Math.max(0, Math.min(SEV_SCALE.length - 1, SEV_SCALE.indexOf(sev) + n))];

const PRIVILEGED = new Set([
  AUTHORITY.UPGRADE, AUTHORITY.GOVERNANCE, AUTHORITY.BRIDGE,
  AUTHORITY.ASSET, AUTHORITY.ORACLE_REPORT, AUTHORITY.ACCESS_CONTROL,
]);

const NON_EXECUTING = new Set([
  REACHABILITY.TEST_ONLY, REACHABILITY.INTERFACE_ONLY,
  REACHABILITY.LIBRARY_DEFINITION, REACHABILITY.UNREFERENCED,
]);

/**
 * Assign the reporting layer. This is the core correction: a detection only
 * reaches the security layer when execution context AND authority establish a
 * consequence. Everything else is inventory or migration surface.
 */
export function assignLayer({ fn, threat, reachability, authority }) {
  if (NON_EXECUTING.has(reachability)) return LAYER.INVENTORY;

  // Encoding standards are never a security finding on their own.
  if (fn === FUNCTION.ENCODING) return LAYER.EXPOSURE;

  // Already-broken primitives are a security problem today, quantum aside.
  if (threat === THREAT.CLASSICAL_BREAK) return LAYER.SECURITY;

  // Grover halves margins; it does not break AES-256 or SHA-256.
  if (threat === THREAT.GROVER) return LAYER.EXPOSURE;

  if (threat === THREAT.UNRESOLVED) return LAYER.EXPOSURE;

  if ((threat === THREAT.FORGERY || threat === THREAT.HNDL) && PRIVILEGED.has(authority)) {
    return LAYER.SECURITY;
  }

  return LAYER.EXPOSURE;
}

/**
 * Severity is computed last, from context — never taken straight from the
 * pattern table. `baseSev` is only a prior.
 */
export function assessSeverity(baseSev, ctx) {
  const { layer, reachability, authority, threat, residualBypass, hybridOr } = ctx;

  if (layer === LAYER.INVENTORY) {
    return reachability === REACHABILITY.TEST_ONLY ? "info" : "low";
  }

  if (layer === LAYER.EXPOSURE) {
    let s = threat === THREAT.MIGRATION_DEBT || threat === THREAT.GROVER ? "low" : "medium";
    if (PRIVILEGED.has(authority)) s = bump(s, 1);
    if (reachability === REACHABILITY.CONDITIONAL) s = bump(s, -1);
    return s;
  }

  // SECURITY layer
  let s = threat === THREAT.CLASSICAL_BREAK ? baseSev : "high";
  if (authority === AUTHORITY.UPGRADE || authority === AUTHORITY.GOVERNANCE) s = bump(s, 1);
  if (residualBypass) s = bump(s, 1);
  if (hybridOr) s = bump(s, 1);
  if (reachability === REACHABILITY.CONDITIONAL) s = bump(s, -1);
  if (reachability === REACHABILITY.UNKNOWN) s = bump(s, -1);
  return s;
}

/** Evidence class for the record as a whole. */
export function assessEvidence({ fn, reachability, authority }) {
  if (fn === FUNCTION.AMBIGUOUS || fn === FUNCTION.UNKNOWN) return EVIDENCE.UNRESOLVED;
  if (reachability === REACHABILITY.UNKNOWN || authority === AUTHORITY.UNKNOWN) return EVIDENCE.UNRESOLVED;
  if (NON_EXECUTING.has(reachability)) return EVIDENCE.DERIVED;
  if (authority === AUTHORITY.NONE_IDENTIFIED) return EVIDENCE.DERIVED;
  return EVIDENCE.DERIVED; // static analysis never yields CONFIRMED on its own
}

// ── Repository-level analysis ─────────────────────────────────────────────────

/**
 * Detect PQ capability, residual classical authority and hybrid composition
 * semantics. `files` is an array of { relPath, content }.
 */
export function analyzeRepo(files) {
  const pqCapabilities = new Map();
  const bypasses = new Map();
  const components = new Map();
  const hybrids = [];
  let settlementDependency = false;

  for (const { relPath, content } of files) {
    if (TEST_PATH_RE.test(relPath) || TEST_FILE_RE.test(relPath)) continue;

    for (const sig of PQ_SIGNALS) {
      if (sig.re.test(content)) {
        if (!pqCapabilities.has(sig.id)) pqCapabilities.set(sig.id, { ...sig, files: [] });
        pqCapabilities.get(sig.id).files.push(relPath);
      }
    }
    for (const sig of BYPASS_SIGNALS) {
      if (sig.re.test(content)) {
        if (!bypasses.has(sig.id)) bypasses.set(sig.id, { ...sig, files: [] });
        bypasses.get(sig.id).files.push(relPath);
      }
    }
    for (const sig of MIGRATION_COMPONENTS) {
      if (sig.re.test(content)) {
        if (!components.has(sig.id)) components.set(sig.id, { ...sig, files: [] });
        components.get(sig.id).files.push(relPath);
      }
    }
    if (/\barbitrum\b|\brollup\b|\bassertion\b|\bsettlement\b|ArbSys\b/i.test(content)) {
      settlementDependency = true;
    }

    hybrids.push(...detectHybridComposition(relPath, content));
  }

  const pqPresent = pqCapabilities.size > 0;
  const bypassList = [...bypasses.values()];

  let migrationStatus = MIGRATION_STATUS.INVENTORY_ONLY;
  if (pqPresent && hybrids.length > 0) migrationStatus = MIGRATION_STATUS.HYBRID;
  else if (pqPresent) migrationStatus = MIGRATION_STATUS.PQ_CAPABLE;
  if (pqPresent && bypassList.length === 0) migrationStatus = MIGRATION_STATUS.CLASSICAL_DISABLED;
  if (settlementDependency && pqPresent) migrationStatus = MIGRATION_STATUS.END_TO_END_BLOCKED;

  return {
    pqCapabilities: [...pqCapabilities.values()],
    residualBypasses: bypassList,
    migrationComponents: [...components.values()],
    hybridCompositions: hybrids,
    settlementDependency,
    migrationStatus,
    // The headline claim the reviewer asked for: PQ verification present, but a
    // classical key can still authorize the same transitions.
    residualBypassRisk: pqPresent && bypassList.length > 0,
  };
}

const CLASSICAL_VERIFY_RE = /\becrecover\s*\(|ECDSA\.(?:recover|tryRecover)\s*\(|isValidSignature\s*\(|checkNSignatures\s*\(/;
const PQ_VERIFY_RE = /(?:ML[-_]?DSA|ML[-_]?KEM|SLH[-_]?DSA|dilithium|sphincs|falcon)\w*\s*\(|\w*(?:ML[-_]?DSA|SLH[-_]?DSA|dilithium)\w*\s*\(|\bpqVerify\s*\(/i;

/**
 * Hybrid signature security depends on the composition rule.
 *   AND — secure while either scheme holds, at the cost of size and lifecycle.
 *   OR  — remains fully breakable through the classical branch.
 * An OR composition is a downgrade path, not a migration.
 */
export function detectHybridComposition(relPath, content) {
  const out = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    // Join a small window so a multi-line require(...) is seen as one expression.
    const expr = lines.slice(i, Math.min(lines.length, i + 6)).join(" ");
    if (!CLASSICAL_VERIFY_RE.test(expr) || !PQ_VERIFY_RE.test(expr)) continue;
    const composition = /\|\|/.test(expr) ? "OR" : /&&/.test(expr) ? "AND" : "UNKNOWN";
    out.push({ file: relPath, line: i + 1, composition, snippet: expr.trim().slice(0, 160) });
    i += 5;
  }
  return out;
}

/**
 * Both branches of a hybrid must be bound to the same message, chain id,
 * account, nonce, action, expiry and domain separator. Missing bindings allow
 * downgrade, replay or cross-domain split-message failures.
 */
export const HYBRID_BINDING_FIELDS = [
  { id: "chainid",  label: "chain id",         re: /block\.chainid|chainId/i },
  { id: "verifying",label: "verifying contract",re: /address\s*\(\s*this\s*\)|verifyingContract/i },
  { id: "nonce",    label: "nonce",            re: /\bnonces?\b/i },
  { id: "expiry",   label: "expiry / deadline",re: /\bdeadline\b|\bexpiry\b|\bvalidUntil\b/i },
  { id: "domain",   label: "domain separator", re: /DOMAIN_SEPARATOR|_hashTypedDataV4|domainSeparator/i },
];

export function checkHybridBindings(snippetOrFile) {
  return HYBRID_BINDING_FIELDS.map(f => ({
    ...f, present: f.re.test(snippetOrFile),
  }));
}

/**
 * Build an identifier frequency table across the corpus. Used to tell a
 * definition apart from a call site, which is what separates a library match
 * from a reachable one.
 */
export function buildSymbolCounts(files) {
  const counts = new Map();
  const ident = /[A-Za-z_$][\w$]{2,}/g;
  for (const { content } of files) {
    let m;
    while ((m = ident.exec(content)) !== null) {
      counts.set(m[0], (counts.get(m[0]) ?? 0) + 1);
    }
  }
  return counts;
}
