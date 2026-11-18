/**
 * CPU detection for the Java4Shell condition check.
 *
 * The vulnerable code runs only on x86-64 CPUs that expose all four
 * flags: avx512f, avx512bw, avx512vbmi, bmi2 (Calif / OpenJDK advisory,
 * checked 2026-11-18). ARM64 has none of them. The flags are read from
 * the host the JVM runs on: /proc/cpuinfo on Linux, or a file passed
 * with --cpuinfo (a sysctl dump on macOS, a saved cpuinfo for a fleet
 * host). The source path is always reported so a container-vs-host
 * mix-up is visible in the output.
 */

export const REQUIRED_FLAGS = ["avx512f", "avx512bw", "avx512vbmi", "bmi2"];

export interface CpuInfo {
  arch: string;
  flags: string[];
  present: string[];
  missing: string[];
  /** All four required flags present. */
  hasAll: boolean;
  /** Where the flags were read from ("host", a file path, or "unknown"). */
  source: string;
  /** False when no flag data could be read at all. */
  known: boolean;
}

import { readFileSync } from "node:fs";

/** Parse a flags list (space-separated, as in /proc/cpuinfo or sysctl). */
export function parseFlags(text: string): string[] {
  const flagsLine = text
    .split("\n")
    .find((line) => /^(flags|Features|machdep\.cpu\.features)\s*:/i.test(line));
  const raw = flagsLine ? flagsLine.split(":").slice(1).join(":") : text;
  const seen = new Set<string>();
  for (const token of raw.split(/[\s,]+/)) {
    const flag = token.trim().toLowerCase();
    if (flag) seen.add(flag);
  }
  return [...seen].sort();
}

export function cpuFromFlags(
  flags: string[],
  arch: string,
  source: string,
): CpuInfo {
  const present = REQUIRED_FLAGS.filter((f) => flags.includes(f));
  const missing = REQUIRED_FLAGS.filter((f) => !flags.includes(f));
  return {
    arch,
    flags,
    present,
    missing,
    hasAll: missing.length === 0,
    source,
    known: flags.length > 0,
  };
}

/** Read the host CPU flags. On Linux this is /proc/cpuinfo; on other
 *  platforms it returns known=false and the caller must use --cpuinfo. */
export function readHostCpu(): CpuInfo {
  const arch = process.arch;
  try {
    // Dynamic import avoided: use the sync fs API via a lazy require
    // through the node:fs import below (static import is fine here).
    const text = readCpuinfoFile("/proc/cpuinfo");
    if (text !== null) {
      return cpuFromFlags(parseFlags(text), arch, "/proc/cpuinfo");
    }
  } catch {
    // Fall through to unknown.
  }
  return {
    arch,
    flags: [],
    present: [],
    missing: [...REQUIRED_FLAGS],
    hasAll: false,
    source: "unknown (no /proc/cpuinfo on this host)",
    known: false,
  };
}

function readCpuinfoFile(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

/** Parse a --cpuinfo file (cpuinfo text or macOS sysctl output). */
export function readCpuinfoPath(path: string): CpuInfo {
  const text = readFileSync(path, "utf8");
  const arch = /aarch64|arm64/i.test(text) ? "arm64" : process.arch;
  return cpuFromFlags(parseFlags(text), arch, path);
}
