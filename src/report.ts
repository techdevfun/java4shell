/**
 * Human and JSON reporting.
 * Every human output ends with the scope footer: this tool checks
 * exposure conditions for one CVE only, never proves exploitability.
 */
import { CHECKED_AT, CVE_ID, VERSION } from "./cli-version.js";
import type { CpuInfo } from "./cpu.js";
import type { Verdict, VerdictResult } from "./verdict.js";
import { patchSummary, type ParsedVersion } from "./versions.js";

export const SCOPE_FOOTER =
  "Scope: java4shell checks exposure conditions for CVE-2026-114938 only (JDK patch level + CPU AVX-512 VBMI + Base64 intrinsics). " +
  "It does not prove exploitability and never runs exploit input. A SAFE verdict means these three conditions do not line up - not that the host is safe from every Java flaw.";

export interface InstallReport {
  home: string;
  source: string;
  javaBin: string;
  rawVersion: string;
  version: ParsedVersion | null;
  patch: string;
  cpu: CpuInfo;
  intrinsicsOn: boolean;
  intrinsicsSource: string;
  intrinsicsOffFlag: string | null;
  verdict: Verdict;
  deciding: string;
  reasons: string[];
  probeError: string | null;
}

export function verdictCounts(
  reports: InstallReport[],
): Record<Verdict, number> {
  const counts: Record<Verdict, number> = {
    EXPOSED: 0,
    "AT-RISK": 0,
    SAFE: 0,
    UNKNOWN: 0,
  };
  for (const r of reports) counts[r.verdict]++;
  return counts;
}

function pad(s: string, width: number): string {
  if (s.length >= width) return s.slice(0, width);
  return s + " ".repeat(width - s.length);
}

export function renderScanTable(reports: InstallReport[]): string {
  const lines: string[] = [];
  lines.push(
    `${pad("jdk home", 44)} ${pad("version", 12)} ${pad("cpu vbmi", 9)} ${pad("intrinsics", 10)} verdict`,
  );
  lines.push("-".repeat(100));
  for (const r of reports) {
    const version = r.version ? r.version.raw : "?";
    const cpu = !r.cpu.known ? "unknown" : r.cpu.hasAll ? "all 4" : "no vbmi";
    const intr = r.intrinsicsOn ? "on" : `off (${r.intrinsicsOffFlag})`;
    lines.push(
      `${pad(r.home, 44)} ${pad(version, 12)} ${pad(cpu, 9)} ${pad(intr, 10)} ${r.verdict}`,
    );
    if (r.probeError) {
      lines.push(`  probe error: ${r.probeError}`);
    } else if (r.version) {
      lines.push(`  patch: ${patchSummary(r.version)}`);
    }
    lines.push(`  deciding: ${r.deciding}`);
    for (const reason of r.reasons) lines.push(`  - ${reason}`);
  }
  lines.push("");
  const counts = verdictCounts(reports);
  lines.push(
    `summary: EXPOSED ${counts.EXPOSED} | AT-RISK ${counts["AT-RISK"]} | SAFE ${counts.SAFE} | UNKNOWN ${counts.UNKNOWN} | installs ${reports.length}`,
  );
  lines.push(SCOPE_FOOTER);
  return lines.join("\n");
}

export function renderCheckTable(report: InstallReport): string {
  const lines: string[] = [];
  lines.push(`verdict: ${report.verdict}`);
  lines.push(`jdk: ${report.home} (${report.source})`);
  if (report.version) {
    lines.push(
      `version: ${report.version.raw}${report.version.vendor ? ` (${report.version.vendor})` : ""}`,
    );
    lines.push(`patch: ${patchSummary(report.version)}`);
  } else if (report.rawVersion) {
    lines.push(`raw version output: ${report.rawVersion.split("\n")[0]}`);
  }
  if (report.probeError) lines.push(`probe error: ${report.probeError}`);
  lines.push(
    `cpu: arch ${report.cpu.arch}, flags from ${report.cpu.source}: ` +
      (!report.cpu.known
        ? "unknown"
        : report.cpu.hasAll
          ? "all four present (avx512f, avx512bw, avx512vbmi, bmi2)"
          : `missing ${report.cpu.missing.join(", ")}`),
  );
  lines.push(
    `intrinsics: ${report.intrinsicsOn ? "on" : `off (${report.intrinsicsOffFlag})`} (${report.intrinsicsSource})`,
  );
  lines.push(`deciding: ${report.deciding}`);
  for (const reason of report.reasons) lines.push(`- ${reason}`);
  lines.push(SCOPE_FOOTER);
  return lines.join("\n");
}

export function scanJson(reports: InstallReport[]): object {
  return {
    tool: "java4shell",
    version: VERSION,
    cve: CVE_ID,
    checkedAt: CHECKED_AT,
    counts: verdictCounts(reports),
    installs: reports.map((r) => ({
      home: r.home,
      source: r.source,
      rawVersion: r.rawVersion,
      version: r.version ? r.version.raw : null,
      vendor: r.version ? r.version.vendor : null,
      patch: r.version ? patchSummary(r.version) : null,
      cpu: {
        arch: r.cpu.arch,
        source: r.cpu.source,
        known: r.cpu.known,
        present: r.cpu.present,
        missing: r.cpu.missing,
      },
      intrinsics: {
        on: r.intrinsicsOn,
        source: r.intrinsicsSource,
        offFlag: r.intrinsicsOffFlag,
      },
      verdict: r.verdict,
      deciding: r.deciding,
      reasons: r.reasons,
      probeError: r.probeError,
    })),
  };
}

export function verdictExitCode(verdict: Verdict): number {
  if (verdict === "EXPOSED" || verdict === "AT-RISK") return 1;
  if (verdict === "UNKNOWN") return 2;
  return 0;
}

export type { VerdictResult };
