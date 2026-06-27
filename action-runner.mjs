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
let summary = { riskScore: 0, critical: 0, high: 0, medium: 0, low: 0 };
try {
  const jsonStr = execSync(cmd(["--json"]), { encoding: "utf8", maxBuffer: 20 * 1024 * 1024 });
  const data = JSON.parse(jsonStr);
  summary = { ...summary, ...data.summary };
} catch (e) {
  try { summary = { ...summary, ...JSON.parse(e.stdout).summary }; } catch {}
}

// 2. Write GitHub Action outputs
const ghOut = process.env.GITHUB_OUTPUT;
if (ghOut) {
  appendFileSync(ghOut, `risk-score=${summary.riskScore}\n`);
  appendFileSync(ghOut, `critical=${summary.critical}\n`);
  appendFileSync(ghOut, `high=${summary.high}\n`);
  appendFileSync(ghOut, `medium=${summary.medium}\n`);
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
const SEV_ORDER = ["critical", "high", "medium", "low"];
const failIdx = failOn === "never" ? -1 : SEV_ORDER.indexOf(failOn);
if (failIdx >= 0) {
  for (const sev of SEV_ORDER.slice(0, failIdx + 1)) {
    const count = summary[sev] ?? 0;
    if (count > 0) {
      console.error(`\n::error::QuantumScan: ${count} ${sev} finding(s) detected. Migrate to ML-KEM (FIPS 203) / ML-DSA (FIPS 204) before Q-Day.`);
      process.exit(1);
    }
  }
}
