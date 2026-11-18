/**
 * JDK version parsing and the Java4Shell fixed-version table.
 *
 * Fixed builds are the Oracle numbers published 17/11/2026 (Oracle
 * November 2026 Critical Patch Update + OpenJDK vulnerability
 * advisory). Other vendors use their own build numbers: Corretto
 * 17.0.21.1.2 carries the fix, Temurin 17.0.21+9 does NOT (Hadrian lab,
 * 17/11/2026). The comparator therefore treats the Oracle numbers as
 * the reference and anything it cannot place as UNKNOWN, never SAFE.
 *
 * Affected range (Calif / OpenJDK advisory, checked 2026-11-18):
 * OpenJDK 17.0.6 and later, including lines 21, 25 and 27. Standard
 * Java 8 and 11 are NOT affected. Oracle Java SE 8 Enterprise
 * Performance Pack build 8u511b33-perf IS affected (fixed 8u513-perf).
 */

export interface ParsedVersion {
  /** Raw version string as printed by `java -version`, e.g. "17.0.21". */
  raw: string;
  /** Numeric parts, e.g. [17, 0, 21]. Build metadata (+9) is kept apart. */
  parts: number[];
  /** Build number after `+`, when present (Temurin 17.0.21+9 -> 9). */
  build: number | null;
  /** Major line: 8, 11, 17, 21, 25, 27... */
  major: number;
  /** Vendor string from the -version output, e.g. "Temurin-17.0.21+9". */
  vendor: string;
  /** True when the -version text marks an Oracle 8 Enterprise
   *  Performance Pack build (the only affected Java 8 build). */
  isPerfPack8: boolean;
  /** True when the -version text names a VM that does not carry the
   *  HotSpot AVX-512 intrinsic (OpenJ9). Detection only, not a
   *  guarantee - see README Honest limits. */
  isOpenJ9: boolean;
}

export interface FixedEntry {
  line: number;
  fixed: string;
  fixedParts: number[];
  affectedFrom: string;
}

export const FIXED_TABLE: FixedEntry[] = [
  {
    line: 17,
    fixed: "17.0.21.1",
    fixedParts: [17, 0, 21, 1],
    affectedFrom: "17.0.6",
  },
  {
    line: 21,
    fixed: "21.0.13.1",
    fixedParts: [21, 0, 13, 1],
    affectedFrom: "21.0.0",
  },
  {
    line: 25,
    fixed: "25.0.5.1",
    fixedParts: [25, 0, 5, 1],
    affectedFrom: "25.0.0",
  },
  {
    line: 27,
    fixed: "27.0.1.1",
    fixedParts: [27, 0, 1, 1],
    affectedFrom: "27.0.0",
  },
];

/** Compare two numeric version part lists. -1 / 0 / 1. Missing parts are 0. */
export function compareParts(a: number[], b: number[]): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

/**
 * Parse the first quoted version from `java -version` output.
 * Handles Oracle ("17.0.21"), Temurin ("17.0.21"), Corretto, Zulu,
 * Microsoft ("21.0.13"), and the 8u511 style ("1.8.0_511").
 * Returns null when no version can be found.
 */
export function parseJavaVersion(output: string): ParsedVersion | null {
  const m = output.match(/version\s+"([^"]+)"/);
  if (!m) return null;
  const raw = m[1];
  const vendorMatch = output.match(
    /(Temurin|Corretto|Zulu|Microsoft|OpenJ9|GraalVM|SapMachine|Liberica|Red Hat)[-\s]?[0-9][^\s)]*/,
  );
  const vendor = vendorMatch ? vendorMatch[0].trim() : "";
  const isOpenJ9 = /OpenJ9/i.test(output) || /Eclipse OpenJ9/i.test(output);
  // Oracle 8 style: "1.8.0_511" plus a "perf" marker in the text.
  const isPerfPack8 = /perf/i.test(output) && raw.startsWith("1.8.0");
  let parts: number[];
  let build: number | null = null;
  let major: number;
  if (/^1\.8\.0_/.test(raw)) {
    const update = Number(raw.split("_")[1]);
    parts = [8, 0, update];
    major = 8;
  } else {
    const plusSplit = raw.split("+");
    const base = plusSplit[0];
    if (plusSplit.length > 1 && /^\d+$/.test(plusSplit[1])) {
      build = Number(plusSplit[1]);
    }
    if (build === null) {
      // Temurin prints the build in the Runtime Environment line:
      // "Temurin-17.0.21+9 (build 17.0.21+9)". Take the first +N
      // after a dotted version in the output.
      const buildMatch = output.match(/\d+\.\d+\.\d+\+(\d+)/);
      if (buildMatch) build = Number(buildMatch[1]);
    }
    parts = base.split(".").map((p) => {
      const n = Number(p.replace(/[^0-9].*$/, ""));
      return Number.isNaN(n) ? 0 : n;
    });
    major = parts[0] ?? 0;
  }
  return { raw, parts, build, major, vendor, isPerfPack8, isOpenJ9 };
}

/** Fixed build for a major line, or null when the line has no entry. */
export function fixedForLine(major: number): FixedEntry | null {
  return FIXED_TABLE.find((e) => e.line === major) ?? null;
}

export type PatchVerdict = "fixed" | "affected" | "not-affected" | "unknown";

/**
 * Patch-level verdict for one parsed version, before CPU/intrinsics.
 * - "fixed": at or above the fixed build for its line (or the 8 perf fix).
 * - "affected": inside the affected range for its line.
 * - "not-affected": below 17.0.6, standard Java 8/11, or any line with
 *   no fixed entry and a major below 17.
 * - "unknown": major 17+ line with no fixed entry (a future line whose
 *   fix status this table does not know).
 */
export function patchVerdict(v: ParsedVersion): PatchVerdict {
  if (v.isPerfPack8) {
    // Only the 8u513-perf build is fixed; 8u511b33-perf is affected.
    // The -version raw is "1.8.0_511" for the affected build.
    return v.parts[2] >= 513 ? "fixed" : "affected";
  }
  if (v.major < 17) return "not-affected";
  const entry = fixedForLine(v.major);
  if (!entry) return "unknown";
  if (compareParts(v.parts, entry.fixedParts) >= 0) return "fixed";
  if (v.major === 17 && compareParts(v.parts, [17, 0, 6]) < 0) {
    return "not-affected";
  }
  return "affected";
}

/** Human-readable one-liner for a patch verdict, used in tables. */
export function patchSummary(v: ParsedVersion): string {
  const verdict = patchVerdict(v);
  const entry = fixedForLine(v.major);
  if (verdict === "fixed") {
    return `fixed build (${v.raw} >= ${entry ? entry.fixed : "?"})`;
  }
  if (verdict === "affected") {
    return `affected range (${v.raw} < ${entry ? entry.fixed : "8u513-perf"})`;
  }
  if (verdict === "not-affected") {
    if (v.major < 17 && !v.isPerfPack8) {
      return `not affected (Java ${v.major} has no AVX-512 Base64 intrinsic)`;
    }
    return `not affected (${v.raw} below 17.0.6)`;
  }
  return `unknown fix status for Java ${v.major} (table checked 2026-11-18)`;
}
