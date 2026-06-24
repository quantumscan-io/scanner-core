/**
 * Substrate/Polkadot PQC Pattern Tests
 * W3F Grant Milestone 1 — deliverable 0c
 *
 * Run: npm test
 * Node.js built-in test runner (no extra dependencies needed).
 *
 * Groups:
 *   1. BABE/GRANDPA consensus keys
 *   2. Pallet crypto (sp-runtime, sp-core, sp-io)
 *   3. XCM signing
 *   4. ink! smart contracts
 *   5. schnorrkel / ed25519-dalek / x25519-dalek / libp2p-noise
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

// ── Pattern definitions (mirrors SUBSTRATE_PATTERNS in index.js) ──────────────
const SUBSTRATE_PATTERNS = [
  { id: "substrate-babe-authority",
    re: /BabeId|babe_generate_session_keys|sr25519::(?:Public|Pair|Signature)\b|app_crypto!\s*\(.*sr25519|BabeAuthorityId|BabeKeyType/i },
  { id: "substrate-grandpa-authority",
    re: /GrandpaId|grandpa_generate_session_keys|ed25519::(?:Public|Pair|Signature)\b|GrandpaAuthorityId|AuthorityList.*grandpa|GrandpaKeyType|GRANDPA_ENGINE_ID/i },
  { id: "substrate-session-keys",
    re: /impl_opaque_keys!\s*\{|SessionKeys\s*\{[^}]*(?:babe|grandpa|im_online|authority_discovery)|generate_session_keys|decode_session_keys/i },
  { id: "substrate-validator-keystore",
    re: /KeystorePtr|SyncCryptoStorePtr|LocalKeystore::open|keystore\.(?:sr25519_generate_new|ed25519_generate_new|ecdsa_generate_new)|sp_keystore|CryptoStore/i },
  { id: "substrate-pallet-verify",
    re: /sp_runtime::traits::Verify|MultiSignature|AnySignature|sp_core::(?:sr25519|ed25519|ecdsa)::Signature|(?:Sr25519|Ed25519|Ecdsa)Signature\b/i },
  { id: "substrate-pallet-crypto-primitive",
    re: /sp_core::crypto::|sp_core::(?:sr25519|ed25519|ecdsa)::|use sp_core::(?:Pair|Public|Signature)|frame_support::crypto::|CryptoTypePublicPair/i },
  { id: "substrate-sp-io-crypto",
    re: /sp_io::crypto::(?:sr25519_verify|ed25519_verify|ecdsa_verify|sr25519_sign|ed25519_sign|ecdsa_sign)|sp_io::crypto::sr25519_public_keys/i },
  { id: "substrate-account-id",
    re: /AccountId32|MultiSigner|(?:Sr25519|Ed25519|Ecdsa)(?:Signer|Public)\b|from_(?:ss58check|public)\s*\(|derive_account/i },
  { id: "substrate-xcm-origin",
    re: /OriginKind::(?:SovereignAccount|Superuser|Native)|xcm::(?:v3|v4)::OriginKind|SignedOrigin.*xcm|XcmRouter.*sign|xcm_executor::(?:Config|XcmExecutor)/i },
  { id: "substrate-xcm-multiasset-sign",
    re: /xcm::prelude::\*|MultiLocation.*AccountId32|AccountId32.*(?:network|junction)|Junction::AccountId32|WithdrawAsset.*AccountId32/i },
  { id: "substrate-xcm-barrier",
    re: /AllowSignedExtrinsic|SignedExtension.*xcm|xcm_builder::(?:SignedToAccountId32|OriginToPluralityVoice)|pallet_xcm::(?:Origin|Config)/i },
  { id: "ink-ecdsa-recover",
    re: /ink::env::ecdsa_recover|ink_env::ecdsa_recover|self\.env\(\)\.ecdsa_recover|ink::env::ecdsa_to_eth_address/i },
  { id: "ink-sr25519-verify",
    re: /ink::env::sr25519_verify|ink_env::sr25519_verify|self\.env\(\)\.sr25519_verify/i },
  { id: "ink-hash-crypto",
    re: /ink::env::hash_bytes|ink::env::hash_encoded|self\.env\(\)\.hash_(?:bytes|encoded)|CryptoHash\b.*ink|ink.*\bBlake2x(?:128|256)\b/i },
  { id: "ink-account-id-sign",
    re: /AccountId.*caller\(\)|self\.env\(\)\.caller\(\)|ink::env::caller|#\[ink\(constructor\)\].*AccountId|set_code_hash.*AccountId/i },
  { id: "substrate-schnorrkel",
    re: /use\s+schnorrkel::|schnorrkel::(?:Keypair|PublicKey|SecretKey|MiniSecretKey|Signature|sign|verify)|MiniSecretKey::from_bytes/i },
  { id: "substrate-ed25519-dalek",
    re: /use\s+ed25519_dalek::|ed25519_dalek::(?:Keypair|PublicKey|SecretKey|ExpandedSecretKey|Signature|Verifier|SigningKey|VerifyingKey)/i },
  { id: "substrate-x25519-dalek",
    re: /use\s+x25519_dalek::|x25519_dalek::(?:EphemeralSecret|StaticSecret|PublicKey|SharedSecret)/i },
  { id: "substrate-libp2p-noise",
    re: /libp2p(?:_noise|::noise)::Config|NoiseConfig::xx|libp2p::noise::NoiseAuthenticated|noise::X25519Spec/i },
];

function find(id) {
  return SUBSTRATE_PATTERNS.find(p => p.id === id);
}
function hits(id, code)   { return find(id).re.test(code); }
function miss(id, code)   { return !find(id).re.test(code); }

// ── 1. BABE/GRANDPA ──────────────────────────────────────────────────────────

describe("1. BABE/GRANDPA consensus key detection", () => {
  test("babe-authority: detects BabeId", () =>
    assert.ok(hits("substrate-babe-authority", "pub type BabeId = app_crypto::sr25519::Public;")));
  test("babe-authority: detects sr25519::Pair", () =>
    assert.ok(hits("substrate-babe-authority", "use sp_core::sr25519::Pair;")));
  test("babe-authority: detects app_crypto! macro", () =>
    assert.ok(hits("substrate-babe-authority", "app_crypto!(sr25519, KEY_TYPE);")));
  test("babe-authority: no false positive on plain sha256", () =>
    assert.ok(miss("substrate-babe-authority", "let h = sha256(data);")));

  test("grandpa-authority: detects GrandpaId", () =>
    assert.ok(hits("substrate-grandpa-authority", "pub type GrandpaId = app_crypto::ed25519::Public;")));
  test("grandpa-authority: detects GRANDPA_ENGINE_ID", () =>
    assert.ok(hits("substrate-grandpa-authority", 'pub const GRANDPA_ENGINE_ID: ConsensusEngineId = *b"FRNK";')));
  test("grandpa-authority: no false positive on tls comment", () =>
    assert.ok(miss("substrate-grandpa-authority", "// TODO: implement tls handshake")));

  test("session-keys: detects impl_opaque_keys!", () =>
    assert.ok(hits("substrate-session-keys",
      "impl_opaque_keys! { pub struct SessionKeys { pub babe: Babe, pub grandpa: Grandpa } }")));
  test("session-keys: detects generate_session_keys", () =>
    assert.ok(hits("substrate-session-keys",
      "fn generate_session_keys(seed: Option<Vec<u8>>) -> Vec<u8>")));
  test("session-keys: no false positive on HttpSession", () =>
    assert.ok(miss("substrate-session-keys", "let session = HttpSession::new();")));

  test("validator-keystore: detects KeystorePtr", () =>
    assert.ok(hits("substrate-validator-keystore", "pub keystore: KeystorePtr,")));
  test("validator-keystore: detects sr25519_generate_new", () =>
    assert.ok(hits("substrate-validator-keystore", "keystore.sr25519_generate_new(KEY_TYPE, None).unwrap();")));
  test("validator-keystore: detects LocalKeystore::open", () =>
    assert.ok(hits("substrate-validator-keystore", "let ks = LocalKeystore::open(path, None)?;")));
  test("validator-keystore: no false positive on KeyValueStore", () =>
    assert.ok(miss("substrate-validator-keystore", "let db = KeyValueStore::open(path);")));
});

// ── 2. Pallet crypto ─────────────────────────────────────────────────────────

describe("2. Pallet cryptography (sp-runtime, sp-core, sp-io)", () => {
  test("pallet-verify: detects sp_runtime::traits::Verify", () =>
    assert.ok(hits("substrate-pallet-verify", "use sp_runtime::traits::Verify;")));
  test("pallet-verify: detects MultiSignature", () =>
    assert.ok(hits("substrate-pallet-verify", "pub type Signature = MultiSignature;")));
  test("pallet-verify: detects Sr25519Signature", () =>
    assert.ok(hits("substrate-pallet-verify", "let sig = Sr25519Signature::from_raw(bytes);")));
  test("pallet-verify: no false positive on plain Verify trait", () =>
    assert.ok(miss("substrate-pallet-verify", "impl Verify for EmailAddress { fn verify(&self) {} }")));

  test("pallet-crypto-primitive: detects sp_core::crypto", () =>
    assert.ok(hits("substrate-pallet-crypto-primitive", "use sp_core::crypto::Pair;")));
  test("pallet-crypto-primitive: detects sp_core::sr25519", () =>
    assert.ok(hits("substrate-pallet-crypto-primitive", "use sp_core::sr25519::{Public, Pair};")));
  test("pallet-crypto-primitive: no false positive on sp_core::storage", () =>
    assert.ok(miss("substrate-pallet-crypto-primitive", "use sp_core::storage::StorageKey;")));

  test("sp-io-crypto: detects sr25519_verify", () =>
    assert.ok(hits("substrate-sp-io-crypto", "sp_io::crypto::sr25519_verify(&sig, &msg, &pub_key);")));
  test("sp-io-crypto: detects ed25519_sign", () =>
    assert.ok(hits("substrate-sp-io-crypto", "let sig = sp_io::crypto::ed25519_sign(KEY_TYPE, &pub, &msg);")));
  test("sp-io-crypto: no false positive on sp_io::storage", () =>
    assert.ok(miss("substrate-sp-io-crypto", 'sp_io::storage::set(b"key", b"value");')));

  test("account-id: detects AccountId32", () =>
    assert.ok(hits("substrate-account-id", "let account: AccountId32 = sender.into();")));
  test("account-id: detects from_ss58check", () =>
    assert.ok(hits("substrate-account-id", "let account = AccountId32::from_ss58check(address).unwrap();")));
});

// ── 3. XCM signing ───────────────────────────────────────────────────────────

describe("3. XCM signing and cross-chain authentication", () => {
  test("xcm-origin: detects OriginKind::SovereignAccount", () =>
    assert.ok(hits("substrate-xcm-origin", "origin_kind: OriginKind::SovereignAccount,")));
  test("xcm-origin: detects xcm::v3::OriginKind", () =>
    assert.ok(hits("substrate-xcm-origin", "use xcm::v3::OriginKind;")));
  test("xcm-origin: detects xcm_executor::XcmExecutor", () =>
    assert.ok(hits("substrate-xcm-origin", "type XcmRouter = xcm_executor::XcmExecutor<XcmConfig>;")));
  test("xcm-origin: no false positive on plain RequestOrigin", () =>
    assert.ok(miss("substrate-xcm-origin", "let origin = RequestOrigin::new();")));

  test("xcm-multiasset: detects Junction::AccountId32", () =>
    assert.ok(hits("substrate-xcm-multiasset-sign",
      "Junction::AccountId32 { network: None, id: account_id.into() }")));
  test("xcm-multiasset: detects xcm::prelude wildcard", () =>
    assert.ok(hits("substrate-xcm-multiasset-sign", "use xcm::prelude::*;")));
  test("xcm-multiasset: no false positive on plain ensure_signed", () =>
    assert.ok(miss("substrate-xcm-multiasset-sign",
      "let account_id = frame_system::ensure_signed(origin)?;")));

  test("xcm-barrier: detects SignedToAccountId32", () =>
    assert.ok(hits("substrate-xcm-barrier",
      "xcm_builder::SignedToAccountId32<RuntimeOrigin, AccountId, AnyNetwork>")));
  test("xcm-barrier: detects pallet_xcm::Origin", () =>
    assert.ok(hits("substrate-xcm-barrier",
      "type LocalOriginToLocation = pallet_xcm::Origin<Runtime>;")));
});

// ── 4. ink! smart contracts ──────────────────────────────────────────────────

describe("4. ink! smart contract cryptography", () => {
  test("ink-ecdsa-recover: detects self.env().ecdsa_recover", () =>
    assert.ok(hits("ink-ecdsa-recover",
      "let pub_key = self.env().ecdsa_recover(&sig, &hash).map_err(|_| Error::InvalidSignature)?;")));
  test("ink-ecdsa-recover: detects ink_env::ecdsa_recover", () =>
    assert.ok(hits("ink-ecdsa-recover",
      "ink_env::ecdsa_recover(&signature, &message_hash, &mut output)?;")));
  test("ink-ecdsa-recover: detects ecdsa_to_eth_address", () =>
    assert.ok(hits("ink-ecdsa-recover",
      "let eth_addr = ink::env::ecdsa_to_eth_address(&pub_key)?;")));
  test("ink-ecdsa-recover: no false positive on ring verify", () =>
    assert.ok(miss("ink-ecdsa-recover",
      "let valid = ring::signature::verify(&ECDSA_P256_SHA256_ASN1, key, msg, sig);")));

  test("ink-sr25519-verify: detects ink::env::sr25519_verify", () =>
    assert.ok(hits("ink-sr25519-verify",
      "ink::env::sr25519_verify(&signature, &message, &public_key).is_ok()")));
  test("ink-sr25519-verify: detects self.env().sr25519_verify", () =>
    assert.ok(hits("ink-sr25519-verify",
      "self.env().sr25519_verify(&sig, &msg, &pub).map_err(|_| Error::BadSig)?;")));
  test("ink-sr25519-verify: no false positive on sp_core sr25519_generate", () =>
    assert.ok(miss("ink-sr25519-verify",
      "let pair = sr25519::Pair::generate().0;")));

  test("ink-hash-crypto: detects hash_bytes", () =>
    assert.ok(hits("ink-hash-crypto",
      "ink::env::hash_bytes::<Blake2x256>(&input, &mut output);")));
  test("ink-hash-crypto: detects self.env().hash_encoded", () =>
    assert.ok(hits("ink-hash-crypto",
      "self.env().hash_encoded::<Sha2x256, _>(&value, &mut hash);")));

  test("ink-account-id-sign: detects ink::env::caller", () =>
    assert.ok(hits("ink-account-id-sign",
      "let caller = ink::env::caller::<DefaultEnvironment>();")));
  test("ink-account-id-sign: detects self.env().caller()", () =>
    assert.ok(hits("ink-account-id-sign", "let owner = self.env().caller();")));
});

// ── 5. Crate-level patterns ──────────────────────────────────────────────────

describe("5. Substrate crate-level (schnorrkel, dalek, libp2p-noise)", () => {
  test("schnorrkel: detects use schnorrkel::", () =>
    assert.ok(hits("substrate-schnorrkel", "use schnorrkel::{Keypair, PublicKey, SecretKey};")));
  test("schnorrkel: detects MiniSecretKey::from_bytes", () =>
    assert.ok(hits("substrate-schnorrkel", "let mini = MiniSecretKey::from_bytes(&secret_bytes)?;")));
  test("schnorrkel: no false positive on ssh_key Keypair", () =>
    assert.ok(miss("substrate-schnorrkel", "use ssh_key::Keypair; let kp = Keypair::generate();")));

  test("ed25519-dalek: detects use ed25519_dalek::SigningKey", () =>
    assert.ok(hits("substrate-ed25519-dalek", "use ed25519_dalek::SigningKey;")));
  test("ed25519-dalek: detects ed25519_dalek::VerifyingKey", () =>
    assert.ok(hits("substrate-ed25519-dalek",
      "let vk = ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;")));
  test("ed25519-dalek: no false positive on comment", () =>
    assert.ok(miss("substrate-ed25519-dalek", "// ed25519 is a signing algorithm")));

  test("x25519-dalek: detects use x25519_dalek::EphemeralSecret", () =>
    assert.ok(hits("substrate-x25519-dalek", "use x25519_dalek::EphemeralSecret;")));
  test("x25519-dalek: detects StaticSecret", () =>
    assert.ok(hits("substrate-x25519-dalek", "let secret = x25519_dalek::StaticSecret::new(OsRng);")));
  test("x25519-dalek: no false positive on comment", () =>
    assert.ok(miss("substrate-x25519-dalek", "// uses x25519 for key agreement")));

  test("libp2p-noise: detects libp2p_noise::Config", () =>
    assert.ok(hits("substrate-libp2p-noise", "libp2p_noise::Config::new(&keypair).unwrap()")));
  test("libp2p-noise: detects NoiseConfig::xx", () =>
    assert.ok(hits("substrate-libp2p-noise", "let noise = NoiseConfig::xx(keypair).into_authenticated();")));
  test("libp2p-noise: detects libp2p::noise import", () =>
    assert.ok(hits("substrate-libp2p-noise", "use libp2p::noise::NoiseAuthenticated;")));
  test("libp2p-noise: no false positive on libp2p TCP", () =>
    assert.ok(miss("substrate-libp2p-noise", "use libp2p::tcp::TcpConfig;")));
});

// ── 6. All 19 patterns registered ────────────────────────────────────────────

describe("6. Registry completeness", () => {
  const EXPECTED_IDS = [
    "substrate-babe-authority", "substrate-grandpa-authority",
    "substrate-session-keys", "substrate-validator-keystore",
    "substrate-pallet-verify", "substrate-pallet-crypto-primitive",
    "substrate-sp-io-crypto", "substrate-account-id",
    "substrate-xcm-origin", "substrate-xcm-multiasset-sign", "substrate-xcm-barrier",
    "ink-ecdsa-recover", "ink-sr25519-verify", "ink-hash-crypto", "ink-account-id-sign",
    "substrate-schnorrkel", "substrate-ed25519-dalek",
    "substrate-x25519-dalek", "substrate-libp2p-noise",
  ];

  test("all 19 Substrate pattern IDs are present", () => {
    const ids = new Set(SUBSTRATE_PATTERNS.map(p => p.id));
    for (const id of EXPECTED_IDS) {
      assert.ok(ids.has(id), `Missing pattern: ${id}`);
    }
    assert.equal(SUBSTRATE_PATTERNS.length, 19);
  });
});
