#!/usr/bin/env node
/**
 * java4shell - is this Java install actually exposed to Java4Shell
 * (CVE-2026-114938)? Condition-based: JDK patch level + CPU AVX-512
 * VBMI + Base64 intrinsics, checked together on the live host.
 * Zero runtime dependencies. No network calls in scan/check.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readCpuinfoPath, readHostCpu, type CpuInfo } from "./cpu.js";
import { CHECKED_AT, CVE_ID, VERSION } from "./cli-version.js";
import { scanCodeDir } from "./decode.js";
import {
  discoverJdks,
  fileExists,
  isJdkHome,
  probeJdk,
  type JdkInstall,
} from "./discover.js";
import { EXPLAIN_TOPICS, PLAYBOOK_STEPS } from "./playbook.js";
import {
  renderCheckTable,
  renderScanTable,
  scanJson,
  verdictExitCode,
  type InstallReport,
} from "./report.js";
import {
  collectEnvJvmFlags,
  decideVerdict,
  intrinsicsFromFlags,
  type Verdict,
} from "./verdict.js";
import { parseJavaVersion } from "./versions.js";

const SCOPE_LINE =
  "java4shell checks exposure conditions for CVE-2026-114938 only. It does not prove exploitability and never runs exploit input.";

function printHelp(): void {
  console.log(`java4shell ${VERSION} - is this Java install exposed to Java4Shell (${CVE_ID})?
${SCOPE_LINE}

Usage:
  java4shell scan [--dirs <dir>...] [--cpuinfo <file>] [--jvm-flags <file>] [--scan-code <dir>] [--json]
  java4shell check <jdk-dir> [--cpuinfo <file>] [--jvm-flags <file>] [--json]
  java4shell decode-scan <dir> [--json]
  java4shell playbook [--json]
  java4shell explain <topic>
  java4shell init
  java4shell --help | --version

Commands:
  scan         Discover JDK installs (PATH, JAVA_HOME, well-known dirs, --dirs)
               and verdict each one: EXPOSED / AT-RISK / SAFE / UNKNOWN.
  check        Verdict a single JDK directory.
  decode-scan  Find Base64 decode sites in source or jars (REVIEW only:
               a decode site is a candidate, never proof of exploitability).
  playbook     First-hour stopgap: patch order, mitigation flag, verification.
  explain      Background on a topic: ${CVE_ID}, EXPOSED, AT-RISK, SAFE,
               UNKNOWN, intrinsics, cpu, versions.
  init         Write java4shell.config.json for this directory.

Exit codes (scan/check):
  0  no EXPOSED install (scan) / SAFE (check)
  1  >=1 EXPOSED install (scan) / EXPOSED or AT-RISK (check)
  2  usage error, no JDK found, or UNKNOWN verdict (check)

Flags:
  --cpuinfo <file>    Read CPU flags from a file instead of /proc/cpuinfo
                      (macOS sysctl dump, or a fleet host cpuinfo).
  --jvm-flags <file>  Extra JVM flags file to inspect for -XX:-UseBASE64Intrinsics.
  --scan-code <dir>   Also scan a code tree for Base64 decode sites.
  --json              Machine-readable output.

Facts checked ${CHECKED_AT}: fixed Oracle builds 17.0.21.1, 21.0.13.1,
25.0.5.1, 27.0.1.1, 8u513-perf. No exploitation in the wild reported as
of ${CHECKED_AT}; Calif published a safe trigger-only reproducer, no weaponised public exploit.`);
}

interface GlobalOpts {
  cpuinfo: string | null;
  jvmFlagsFile: string | null;
  scanCode: string | null;
  json: boolean;
  rest: string[];
}

function parseGlobalArgs(args: string[]): GlobalOpts {
  const opts: GlobalOpts = {
    cpuinfo: null,
    jvmFlagsFile: null,
    scanCode: null,
    json: false,
    rest: [],
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") opts.json = true;
    else if (a === "--cpuinfo" && i + 1 < args.length) opts.cpuinfo = args[++i];
    else if (a === "--jvm-flags" && i + 1 < args.length)
      opts.jvmFlagsFile = args[++i];
    else if (a === "--scan-code" && i + 1 < args.length)
      opts.scanCode = args[++i];
    else if (a === "--dirs") {
      // Handled by the scan command itself; keep the marker and values.
      opts.rest.push(a);
      while (i + 1 < args.length && !args[i + 1].startsWith("--")) {
        opts.rest.push(args[++i]);
      }
    } else if (a.startsWith("--")) {
      console.error(`unknown flag: ${a}`);
      process.exit(2);
    } else {
      opts.rest.push(a);
    }
  }
  return opts;
}

function loadCpu(opts: GlobalOpts): CpuInfo {
  if (opts.cpuinfo) {
    if (!fileExists(opts.cpuinfo)) {
      console.error(`cpuinfo file not found: ${opts.cpuinfo}`);
      process.exit(2);
    }
    return readCpuinfoPath(opts.cpuinfo);
  }
  return readHostCpu();
}

function loadJvmFlags(opts: GlobalOpts): { text: string; label: string } {
  const env = collectEnvJvmFlags();
  const parts = [env.text];
  const labels = [env.label];
  if (opts.jvmFlagsFile) {
    if (!fileExists(opts.jvmFlagsFile)) {
      console.error(`jvm-flags file not found: ${opts.jvmFlagsFile}`);
      process.exit(2);
    }
    parts.push(readFileSync(opts.jvmFlagsFile, "utf8"));
    labels.push(opts.jvmFlagsFile);
  }
  return { text: parts.join(" "), label: labels.filter(Boolean).join(", ") };
}

async function buildReport(
  install: JdkInstall,
  cpu: CpuInfo,
  jvmFlags: { text: string; label: string },
): Promise<InstallReport> {
  const probed = await probeJdk(install);
  const version = probed.rawVersion
    ? parseJavaVersion(probed.rawVersion)
    : null;
  const intrinsics = intrinsicsFromFlags(jvmFlags.text, jvmFlags.label);
  const archForVerdict: CpuInfo =
    cpu.known || process.arch === "x64" ? cpu : { ...cpu, arch: process.arch };
  const result = decideVerdict({
    version,
    cpu: archForVerdict,
    intrinsics,
    rawVersion: probed.rawVersion,
  });
  // A probe failure with no version text is UNKNOWN regardless of the
  // version branch above.
  const verdict: Verdict =
    probed.probeError && !probed.rawVersion ? "UNKNOWN" : result.verdict;
  const reasons =
    probed.probeError && !probed.rawVersion
      ? [probed.probeError]
      : result.reasons;
  return {
    home: install.home,
    source: install.source,
    javaBin: install.javaBin,
    rawVersion: probed.rawVersion,
    version,
    patch: "",
    cpu: archForVerdict,
    intrinsicsOn: intrinsics.on,
    intrinsicsSource: intrinsics.source,
    intrinsicsOffFlag: intrinsics.offFlag,
    verdict,
    deciding:
      verdict === "UNKNOWN" && probed.probeError
        ? "probe failed"
        : result.deciding,
    reasons,
    probeError: probed.probeError,
  };
}

async function cmdScan(opts: GlobalOpts): Promise<number> {
  const extraDirs: string[] = [];
  const rest = opts.rest;
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === "--dirs") {
      i++;
      while (i < rest.length && !rest[i].startsWith("--"))
        extraDirs.push(rest[i++]);
      i--;
    }
  }
  const cpu = loadCpu(opts);
  const jvmFlags = loadJvmFlags(opts);
  const installs = discoverJdks({ extraDirs, includePath: true });
  if (installs.length === 0) {
    console.error(
      "no JDK install found (checked PATH, JAVA_HOME, well-known dirs, --dirs)",
    );
    console.error("pass a JDK home with: java4shell check <jdk-dir>");
    return 2;
  }
  const reports: InstallReport[] = [];
  for (const install of installs) {
    reports.push(await buildReport(install, cpu, jvmFlags));
  }
  if (opts.json) {
    console.log(JSON.stringify(scanJson(reports), null, 2));
  } else {
    console.log(renderScanTable(reports));
  }
  if (opts.scanCode) {
    if (!existsSync(opts.scanCode)) {
      console.error(`scan-code dir not found: ${opts.scanCode}`);
      return 2;
    }
    const sites = scanCodeDir(opts.scanCode);
    console.log("");
    console.log(
      `decode-scan: ${sites.length} Base64 decode site(s) in ${opts.scanCode} (REVIEW only)`,
    );
    for (const site of sites) {
      console.log(
        `  ${site.severity} ${site.file}${site.line ? `:${site.line}` : ""} - ${site.snippet}`,
      );
    }
    if (sites.length > 0) {
      console.log(
        "A decode site is a candidate for untrusted-input reachability, never proof of exploitability.",
      );
    }
  }
  const exposed = reports.some((r) => r.verdict === "EXPOSED");
  return exposed ? 1 : 0;
}

async function cmdCheck(opts: GlobalOpts): Promise<number> {
  const dir = opts.rest[0];
  if (!dir) {
    console.error("usage: java4shell check <jdk-dir>");
    return 2;
  }
  if (!isJdkHome(dir)) {
    console.error(`not a JDK home (no bin/java under ${dir})`);
    return 2;
  }
  const cpu = loadCpu(opts);
  const jvmFlags = loadJvmFlags(opts);
  const report = await buildReport(
    {
      home: dir,
      source: "check <jdk-dir>",
      javaBin: join(dir, "bin", "java"),
      rawVersion: "",
      probeError: null,
    },
    cpu,
    jvmFlags,
  );
  if (opts.json) {
    console.log(JSON.stringify(scanJson([report]), null, 2));
  } else {
    console.log(renderCheckTable(report));
  }
  return verdictExitCode(report.verdict);
}

function cmdDecodeScan(opts: GlobalOpts): number {
  const dir = opts.rest[0];
  if (!dir) {
    console.error("usage: java4shell decode-scan <dir>");
    return 2;
  }
  if (!existsSync(dir)) {
    console.error(`dir not found: ${dir}`);
    return 2;
  }
  const sites = scanCodeDir(dir);
  if (opts.json) {
    console.log(
      JSON.stringify(
        { tool: "java4shell", version: VERSION, cve: CVE_ID, dir, sites },
        null,
        2,
      ),
    );
  } else {
    console.log(`decode-scan: ${sites.length} Base64 decode site(s) in ${dir}`);
    for (const site of sites) {
      console.log(
        `  ${site.severity} ${site.file}${site.line ? `:${site.line}` : ""} - ${site.snippet}`,
      );
    }
    console.log(
      "REVIEW only: a decode site reachable from untrusted input is a candidate, never proof of exploitability.",
    );
  }
  return sites.length > 0 ? 1 : 0;
}

function cmdPlaybook(opts: GlobalOpts): number {
  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          tool: "java4shell",
          version: VERSION,
          cve: CVE_ID,
          checkedAt: CHECKED_AT,
          steps: PLAYBOOK_STEPS,
        },
        null,
        2,
      ),
    );
    return 0;
  }
  console.log(
    `First-hour playbook for ${CVE_ID} (Java4Shell), checked ${CHECKED_AT}:`,
  );
  console.log("");
  for (const step of PLAYBOOK_STEPS) {
    console.log(step.step);
    console.log(`  ${step.detail}`);
    console.log("");
  }
  return 0;
}

function cmdExplain(opts: GlobalOpts): number {
  const topic = opts.rest[0];
  if (!topic) {
    console.error("usage: java4shell explain <topic>");
    console.error(
      `topics: ${CVE_ID}, EXPOSED, AT-RISK, SAFE, UNKNOWN, intrinsics, cpu, versions`,
    );
    return 2;
  }
  const lines = EXPLAIN_TOPICS[topic] ?? EXPLAIN_TOPICS[topic.toUpperCase()];
  if (!lines) {
    console.error(`unknown topic: ${topic}`);
    console.error(
      `topics: ${CVE_ID}, EXPOSED, AT-RISK, SAFE, UNKNOWN, intrinsics, cpu, versions`,
    );
    return 2;
  }
  for (const line of lines) console.log(line);
  return 0;
}

function cmdInit(): number {
  const config = {
    tool: "java4shell",
    version: VERSION,
    cve: CVE_ID,
    scanDirs: ["/usr/lib/jvm"],
    cpuinfo: null,
    jvmFlagsFile: null,
    notes:
      "Pass --cpuinfo with the host cpuinfo when scanning from a container. Add the mitigation flag -XX:-UseBASE64Intrinsics to a service launcher only after reading its own docs.",
  };
  writeFileSync(
    "java4shell.config.json",
    JSON.stringify(config, null, 2) + "\n",
  );
  console.log("wrote java4shell.config.json");
  console.log("run on each host: java4shell scan");
  console.log("single install:   java4shell check /path/to/jdk-home");
  return 0;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    printHelp();
    process.exit(0);
  }
  if (args[0] === "--version" || args[0] === "-V") {
    console.log(`java4shell ${VERSION}`);
    process.exit(0);
  }
  const command = args[0];
  const opts = parseGlobalArgs(args.slice(1));
  let code: number;
  if (command === "scan") code = await cmdScan(opts);
  else if (command === "check") code = await cmdCheck(opts);
  else if (command === "decode-scan") code = cmdDecodeScan(opts);
  else if (command === "playbook") code = cmdPlaybook(opts);
  else if (command === "explain") code = cmdExplain(opts);
  else if (command === "init") code = cmdInit();
  else {
    console.error(`unknown command: ${command}`);
    printHelp();
    code = 2;
  }
  process.exit(code);
}

main();
