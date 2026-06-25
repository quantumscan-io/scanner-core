import { readdirSync, readFileSync, statSync, existsSync } from "fs";
import { execSync } from "child_process";
import { join, extname, relative, resolve, basename } from "path";
import { argv, exit } from "process";

const VERSION = "1.9.1";
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