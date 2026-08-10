/**
 * Context model tests
 *
 * These lock in the distinctions between a detection, a migration surface and
 * a security-critical finding. Run: npm test
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  FUNCTION, THREAT, PLANE, REACHABILITY, AUTHORITY, LAYER, EVIDENCE,
  FUNCTION_MAP, REGULATORY,
  classifyReachability, classifyAuthority, classifyPkExposure,
  assignLayer, assessSeverity, assessEvidence,
  analyzeRepo, buildSymbolCounts, buildFunctionIndex,
  detectHybridComposition, checkHybridBindings,
} from "../context.js";

const L = s => s.split("\n");

describe("1. cryptographic function is separated from severity", () => {
  test("EIP-712 is an encoding standard, not a signature algorithm", () => {
    assert.equal(FUNCTION_MAP["solidity-eip712"].fn, FUNCTION.ENCODING);
    assert.notEqual(FUNCTION_MAP["solidity-eip712"].fn, FUNCTION.SIGNATURE);
  });

  test("an encoding finding can never reach the security layer", () => {
    const layer = assignLayer({
      fn: FUNCTION.ENCODING,
      threat: THREAT.MIGRATION_DEBT,
      reachability: REACHABILITY.ACTIVE,
      authority: AUTHORITY.UPGRADE,   // even with the most privileged authority
    });
    assert.equal(layer, LAYER.EXPOSURE);
  });

  test("ERC-4337 is a migration surface, not an intrinsic ECDSA dependency", () => {
    assert.notEqual(FUNCTION_MAP["erc4337-account"].fn, FUNCTION.SIGNATURE);
    assert.equal(FUNCTION_MAP["erc4337-account"].threat, THREAT.MIGRATION_DEBT);
  });

  test("EIP-7702 keeps a classical signature root", () => {
    assert.equal(FUNCTION_MAP["eip7702-delegation"].fn, FUNCTION.SIGNATURE);
    assert.equal(FUNCTION_MAP["eip7702-delegation"].threat, THREAT.FORGERY);
  });
});

describe("2. HNDL is not the same as signature forgery", () => {
  test("key establishment carries the harvest-now-decrypt-later threat", () => {
    for (const id of ["ecdh", "dh", "x25519"]) {
      assert.equal(FUNCTION_MAP[id].fn, FUNCTION.KEY_ESTABLISHMENT);
      assert.equal(FUNCTION_MAP[id].threat, THREAT.HNDL);
    }
  });

  test("signatures carry the future-forgery threat, never HNDL", () => {
    for (const id of ["ecdsa", "secp256k1", "ed25519", "solidity-permit-eip2612"]) {
      assert.equal(FUNCTION_MAP[id].fn, FUNCTION.SIGNATURE);
      assert.equal(FUNCTION_MAP[id].threat, THREAT.FORGERY);
      assert.notEqual(FUNCTION_MAP[id].threat, THREAT.HNDL);
    }
  });

  test("a recorded permit signature is not encrypted payload", () => {
    // ERC-2612 permits are signature artifacts; their risk is authorization
    // forgery bounded by nonce and deadline, not future decryption.
    assert.equal(FUNCTION_MAP["solidity-permit-eip2612"].threat, THREAT.FORGERY);
  });

  test("symmetric and hash primitives get Grover, not Shor", () => {
    assert.equal(FUNCTION_MAP["aes128"].threat, THREAT.GROVER);
    assert.equal(
      assignLayer({ fn: FUNCTION.SYMMETRIC, threat: THREAT.GROVER,
        reachability: REACHABILITY.ACTIVE, authority: AUTHORITY.ASSET }),
      LAYER.EXPOSURE,
    );
  });

  test("already-broken primitives are flagged as classical, not quantum", () => {
    for (const id of ["md5", "sha1", "rc4", "des"]) {
      assert.equal(FUNCTION_MAP[id].threat, THREAT.CLASSICAL_BREAK);
    }
  });
});

describe("3. reachability separates inventory from live code", () => {
  const counts = new Map();

  test("test files are inventory, never security", () => {
    const r = classifyReachability("test/Foo.t.sol", L("contract T {\n  ecrecover(h,v,r,s);\n}"), 1, counts);
    assert.equal(r, REACHABILITY.TEST_ONLY);
    assert.equal(
      assignLayer({ fn: FUNCTION.SIGNATURE, threat: THREAT.FORGERY,
        reachability: r, authority: AUTHORITY.ASSET }),
      LAYER.INVENTORY,
    );
  });

  test("interface declarations are inventory", () => {
    const lines = L("interface IFoo {\n  function verify(bytes calldata s) external;\n}");
    assert.equal(classifyReachability("src/IFoo.sol", lines, 1, counts), REACHABILITY.INTERFACE_ONLY);
  });

  test("an external entry point is never marked unreferenced", () => {
    // Called by transactions, so a corpus reference count of one proves nothing.
    const lines = L("contract A {\n  function claimIt(bytes calldata s) external {\n    ecrecover(h,v,r,s);\n  }\n}");
    const c = new Map([["claimIt", 1]]);
    assert.equal(classifyReachability("src/A.sol", lines, 2, c), REACHABILITY.ACTIVE);
  });

  test("an unreferenced internal helper is reported as unreferenced", () => {
    const lines = L("contract A {\n  function _dead(bytes calldata s) internal {\n    ecrecover(h,v,r,s);\n  }\n}");
    const c = new Map([["_dead", 1]]);
    assert.equal(classifyReachability("src/A.sol", lines, 2, c), REACHABILITY.UNREFERENCED);
  });
});

describe("4. authority is attributed to the containing function", () => {
  test("adjacent privileged functions do not leak their authority", () => {
    const lines = L([
      "contract A {",
      "  function upgradeTo(address impl) external onlyOwner {",
      "    _setImplementation(impl);",
      "  }",
      "  function readOnly(bytes32 h, uint8 v, bytes32 r, bytes32 s) external view returns (address) {",
      "    return ecrecover(h, v, r, s);",
      "  }",
      "}",
    ].join("\n"));
    const authority = classifyAuthority(lines, 5, buildFunctionIndex(lines));
    assert.notEqual(authority, AUTHORITY.UPGRADE);
  });

  test("authority is resolved one call deep", () => {
    // The public entry point verifies; an internal function moves the value.
    const lines = L([
      "contract A {",
      "  function receiveWithAuthorization(bytes32 h, uint8 v, bytes32 r, bytes32 s) public {",
      "    require(from == ECDSA.recover(h, v, r, s));",
      "    _transferWithAuthorization(from, to, value);",
      "  }",
      "  function _transferWithAuthorization(address f, address t, uint256 v) internal {",
      "    _transfer(f, t, v);",
      "  }",
      "}",
    ].join("\n"));
    assert.equal(classifyAuthority(lines, 2, buildFunctionIndex(lines)), AUTHORITY.ASSET);
  });

  test("file-scope matches (imports, constants) carry no authority", () => {
    const lines = L([
      "import {ECDSA} from './ECDSA.sol';",
      "contract A {",
      "  function withdraw() external { _transfer(a, b, c); }",
      "}",
    ].join("\n"));
    assert.equal(classifyAuthority(lines, 0, buildFunctionIndex(lines)), AUTHORITY.NONE_IDENTIFIED);
  });
});

describe("5. severity is computed from context, not read from the pattern", () => {
  const ctx = over => ({
    layer: LAYER.SECURITY, reachability: REACHABILITY.ACTIVE,
    authority: AUTHORITY.ASSET, threat: THREAT.FORGERY,
    residualBypass: false, hybridOr: false, ...over,
  });

  test("a high-prior pattern in a test file drops to info", () => {
    assert.equal(
      assessSeverity("high", ctx({ layer: LAYER.INVENTORY, reachability: REACHABILITY.TEST_ONLY })),
      "info",
    );
  });

  test("upgrade authority escalates above asset movement", () => {
    const asset   = assessSeverity("high", ctx({ authority: AUTHORITY.ASSET }));
    const upgrade = assessSeverity("high", ctx({ authority: AUTHORITY.UPGRADE }));
    assert.equal(asset, "high");
    assert.equal(upgrade, "critical");
  });

  test("a residual classical bypass escalates severity", () => {
    assert.equal(assessSeverity("high", ctx({ residualBypass: true })), "critical");
  });

  test("an OR hybrid escalates severity", () => {
    assert.equal(assessSeverity("high", ctx({ hybridOr: true })), "critical");
  });

  test("migration-surface findings never start at high", () => {
    const s = assessSeverity("high", ctx({ layer: LAYER.EXPOSURE, authority: AUTHORITY.NONE_IDENTIFIED }));
    assert.ok(["low", "medium"].includes(s), `expected low|medium, got ${s}`);
  });
});

describe("6. evidence class never overstates static analysis", () => {
  test("an ambiguous primitive is unresolved, not assumed", () => {
    assert.equal(FUNCTION_MAP["rsa"].fn, FUNCTION.AMBIGUOUS);
    assert.equal(
      assessEvidence({ fn: FUNCTION.AMBIGUOUS, reachability: REACHABILITY.ACTIVE, authority: AUTHORITY.ASSET }),
      EVIDENCE.UNRESOLVED,
    );
  });

  test("static analysis never yields CONFIRMED", () => {
    const e = assessEvidence({ fn: FUNCTION.SIGNATURE, reachability: REACHABILITY.ACTIVE, authority: AUTHORITY.ASSET });
    assert.notEqual(e, EVIDENCE.CONFIRMED);
  });
});

describe("7. hybrid composition semantics", () => {
  const orSrc = `
    function exec(bytes calldata a, bytes calldata b) external {
      require(ecrecover(h, v, r, s) == owner || verifyMLDSA(h, b), "bad");
    }`;
  const andSrc = `
    function exec(bytes calldata a, bytes calldata b) external {
      require(ECDSA.recover(h, v, r, s) == owner && verifyMLDSA(h, b), "bad");
    }`;

  test("OR composition is detected as a classical downgrade path", () => {
    const [h] = detectHybridComposition("src/A.sol", orSrc);
    assert.equal(h.composition, "OR");
  });

  test("AND composition is detected", () => {
    const [h] = detectHybridComposition("src/A.sol", andSrc);
    assert.equal(h.composition, "AND");
  });

  test("missing cross-scheme bindings are reported", () => {
    const missing = checkHybridBindings(orSrc).filter(b => !b.present).map(b => b.id);
    assert.ok(missing.includes("chainid"));
    assert.ok(missing.includes("nonce"));
    assert.ok(missing.includes("expiry"));
  });

  test("a fully bound hybrid reports no missing fields", () => {
    const bound = `keccak256(abi.encode(block.chainid, address(this), nonces[o], deadline, DOMAIN_SEPARATOR))`;
    assert.equal(checkHybridBindings(bound).filter(b => !b.present).length, 0);
  });
});

describe("8. residual classical bypass", () => {
  const pqWithOwner = [{
    relPath: "src/Account.sol",
    content: `
      contract Account {
        address public owner;
        modifier onlyOwner() { require(msg.sender == owner); _; }
        function setValidator(address v) external onlyOwner { validator = v; }
        function check(bytes32 h, bytes calldata s) public view returns (bool) {
          return verifyMLDSA(h, s);
        }
      }`,
  }];

  test("PQ verification plus a classical owner is flagged as not migrated", () => {
    const repo = analyzeRepo(pqWithOwner);
    assert.equal(repo.pqCapabilities.length > 0, true);
    assert.equal(repo.residualBypassRisk, true);
    assert.ok(repo.residualBypasses.some(b => b.id === "owner"));
  });

  test("no PQ capability means no bypass claim is made", () => {
    // Absence of a PQ verifier is not a bypass — it is simply pre-migration.
    const repo = analyzeRepo([{ relPath: "src/A.sol", content: "contract A { address owner; }" }]);
    assert.equal(repo.residualBypassRisk, false);
  });

  test("test files do not contribute PQ capability or bypass signals", () => {
    const repo = analyzeRepo([{ relPath: "test/A.t.sol", content: "verifyMLDSA(h, s); onlyOwner" }]);
    assert.equal(repo.pqCapabilities.length, 0);
  });
});

describe("9. public key exposure follows function and plane", () => {
  test("on-chain verification republishes key material", () => {
    assert.equal(classifyPkExposure(FUNCTION.SIGNATURE, PLANE.CONTRACT), "repeatedly-exposed");
  });

  test("exposure does not apply to hashes or encodings", () => {
    assert.equal(classifyPkExposure(FUNCTION.HASH, PLANE.CONTRACT), "not-applicable");
    assert.equal(classifyPkExposure(FUNCTION.ENCODING, PLANE.CONTRACT), "not-applicable");
  });
});

describe("10. regulatory mapping states what each instrument says", () => {
  test("DORA carries an explicit correction and no 2030 PQC deadline", () => {
    const dora = REGULATORY.find(r => r.id === "dora");
    assert.ok(dora.correction, "DORA entry must carry a correction");
    assert.match(dora.says, /Administrative penalties and remedial measures/);
    // The entry may mention 2030 only to deny that Article 50 imposes it.
    assert.match(dora.imposes, /NOT a PQC-specific requirement/);
    assert.match(dora.imposes, /sets no 2030 quantum deadline/);
    assert.match(dora.correction, /Do not cite DORA Article 50/);
  });

  test("the 2030 date belongs to the EU PQC roadmap", () => {
    const roadmap = REGULATORY.find(r => r.id === "eu-pqc-roadmap");
    assert.match(roadmap.says, /2030/);
    assert.match(roadmap.says, /2026/);
  });

  test("CNSA 2.0 is scoped to national security systems", () => {
    assert.match(REGULATORY.find(r => r.id === "cnsa-2").imposes, /national security systems/);
  });
});

describe("11. symbol counting", () => {
  test("identifiers are counted across the corpus", () => {
    const counts = buildSymbolCounts([
      { relPath: "a.sol", content: "function helper() {} helper();" },
      { relPath: "b.sol", content: "helper();" },
    ]);
    assert.equal(counts.get("helper"), 3);
  });
});
