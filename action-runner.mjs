#!/usr/bin/env node
// GitHub Action entrypoint — called by action.yml
import { execSync } from "child_process";
import { appendFileSync, writeFileSync } from "fs";

const [, , targetPath = ".", failOn = "high", sarifOutput = "", substrate = "false", noDeps = "false"] = process.argv;

const flags = ["--no-fail"];
if (substrate === "true") flags.push("--substrate");
if (noDeps === "true")    flags.push("--no-deps");

const cmd = (extra = []) =>
  ["npx", "--yes", `quantumscan@latest`, `"${targetPath}"`, ...flags, ...extra].join(" ");

// 1. JSON scan — parse metrics
let summary = { riskScore: 0, exposureScore: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
let migration = null;
try {
  const jsonStr = execSync(cmd(["--json"]), { encoding: "utf8", maxBuffer: 20 * 1024 * 1024 });
  const data = JSON.parse(jsonStr);
  summary = { ...summary, ...data.summary };
  migration = data.migration ?? null;
} catch (e) {
  try {
    const data = JSON.parse(e.stdout);
    summary = { ...summary, ...data.summary };
    migration = data.migration ?? null;
  } catch {}
}
const layers = summary.byLayer ?? { securityCritical: 0, migrationExposure: 0, inventory: 0 };

// 2. Write GitHub Action outputs
const ghOut = process.env.GITHUB_OUTPUT;
if (ghOut) {
  appendFileSync(ghOut, `risk-score=${summary.riskScore}\n`);
  appendFileSync(ghOut, `exposure-score=${summary.exposureScore}\n`);
  appendFileSync(ghOut, `critical=${summary.critical}\n`);
  appendFileSync(ghOut, `high=${summary.high}\n`);
  appendFileSync(ghOut, `medium=${summary.medium}\n`);
  // The three reports, kept distinct: a migration surface is not an incident.
  appendFileSync(ghOut, `security-critical=${layers.securityCritical}\n`);
  appendFileSync(ghOut, `migration-exposure=${layers.migrationExposure}\n`);
  appendFileSync(ghOut, `inventory=${layers.inventory}\n`);
  appendFileSync(ghOut, `residual-classical-bypass=${migration?.residualBypassRisk ?? false}\n`);
  appendFileSync(ghOut, `migration-status=${migration?.status ?? "unknown"}\n`);
}

// A post-quantum verifier that a classical key can replace or bypass has not
// completed migration. Surface it regardless of the fail threshold.
if (migration?.residualBypassRisk) {
  const paths = migration.residualBypasses.map(b => b.label).join(", ");
  console.log(`::warning::QuantumScan: post-quantum verification detected, but classical authority remains (${paths}). The classical root of authority still authorizes the same transitions.`);
}
for (const h of migration?.hybridCompositions ?? []) {
  if (h.composition === "OR") {
    console.log(`::warning file=${h.file},line=${h.line}::Hybrid OR composition — the classical branch alone still authorizes this action. This is a downgrade path, not a migration.`);
  }
}

// 3. Optional SARIF output
if (sarifOutput) {
  try {
    const sarif = execSync(cmd(["--sarif"]), { encoding: "utf8", maxBuffer: 20 * 1024 * 1024 });
    writeFileSync(sarifOutput, sarif);
    console.log(`::notice::QuantumScan SARIF written to ${sarifOutput}`);
  } catch { /* non-fatal */ }
}

// 4. Human-readable output (always shown in CI log)
try {
  execSync(cmd([]), { stdio: "inherit" });
} catch { /* no-fail flag prevents exit 1, this is just for display */ }

// 5. Fail logic
//
// `fail-on` accepts a layer (security | exposure | never) or, for backwards
// compatibility, a severity name. Failing a build on an inventory entry turns a
// pattern count into a false emergency, so layer mode is preferred.
if (failOn === "security" || failOn === "exposure") {
  const count = failOn === "security"
    ? layers.securityCritical
    : layers.securityCritical + layers.migrationExposure;
  if (count > 0) {
    console.error(`\n::error::QuantumScan: ${layers.securityCritical} security-critical finding(s)` +
      (failOn === "exposure" ? ` and ${layers.migrationExposure} migration-exposure finding(s)` : "") +
      `. Signatures/authorization → ML-DSA (FIPS 204); key establishment → ML-KEM (FIPS 203).`);
    process.exit(1);
  }
} else if (failOn !== "never") {
  const SEV_ORDER = ["critical", "high", "medium", "low"];
  const failIdx = SEV_ORDER.indexOf(failOn);
  if (failIdx >= 0) {
    for (const sev of SEV_ORDER.slice(0, failIdx + 1)) {
      const count = summary[sev] ?? 0;
      if (count > 0) {
        console.error(`\n::error::QuantumScan: ${count} ${sev} finding(s) detected. ` +
          `Severity is computed from reachability and authority — see the security-critical report for what is actually exploitable.`);
        process.exit(1);
      }
    }
  }
}
