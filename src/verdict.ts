/**
 * Condition-based verdicts for CVE-2026-114938 (Java4Shell).
 *
 * Exposure needs ALL of these together: an affected patch level, an
 * x86-64 CPU with AVX-512 VBMI, and the Base64 fast path switched on.
 * A verdict is never taken from a CVE database lookup alone.
 *
 * - EXPOSED: affected version + all four CPU flags + intrinsics on.
 * - SAFE: fixed version, or below 17.0.6 / standard Java 8/11, or CPU
 *   lacks a flag, or arch is not x86-64, or intrinsics off, or a
 *   non-HotSpot VM detected (OpenJ9 - detection only).
 * - AT-RISK: affected version but CPU flags or intrinsics state
 *   unknown - the honest middle verdict, never silently SAFE.
 * - UNKNOWN: version unparseable or the JDK could not be probed.
 */

import type { CpuInfo } from "./cpu.js";
import { patchVerdict, type ParsedVersion } from "./versions.js";

export type Verdict = "EXPOSED" | "AT-RISK" | "SAFE" | "UNKNOWN";

export interface IntrinsicsState {
  /** True when the fast path is switched on (the default). */
  on: boolean;
  /** False when no JVM flag source could be read at all. */
  known: boolean;
  /** Where the state was read from (env vars, flags file, default). */
  source: string;
  /** The flag that switched it off, when one was found. */
  offFlag: string | null;
}

const OFF_FLAGS = ["-XX:-UseBASE64Intrinsics", "-XX:UseAVX=2"];

/**
 * Detect the intrinsics state from JVM flag sources.
 * `flagSources` is the concatenated text of JAVA_TOOL_OPTIONS,
 * JDK_JAVA_OPTIONS, _JAVA_OPTIONS and any --jvm-flags file content.
 * An empty string means "no flag source found": the JVM default is
 * ON, but the state is reported as known=false so the verdict can
 * say AT-RISK instead of guessing.
 */
export function intrinsicsFromFlags(
  flagSources: string,
  sourceLabel: string,
): IntrinsicsState {
  for (const flag of OFF_FLAGS) {
    if (flagSources.includes(flag)) {
      return { on: false, known: true, source: sourceLabel, offFlag: flag };
    }
  }
  // No disabling flag found in the sources inspected (environment
  // variables and any --jvm-flags file). The JVM default is ON, and
  // inspecting the sources and finding nothing IS the evidence: the
  // state is known, with the source recorded so a reviewer can see
  // the service launcher was not inspected (it may set the flag in a
  // systemd unit or start script - see the playbook).
  return {
    on: true,
    known: true,
    source:
      sourceLabel.trim().length > 0
        ? sourceLabel
        : "JVM default, no disabling flag in environment",
    offFlag: null,
  };
}

/** Collect the JVM flag sources visible in this process environment. */
export function collectEnvJvmFlags(): { text: string; label: string } {
  const parts: string[] = [];
  const labels: string[] = [];
  for (const name of [
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "_JAVA_OPTIONS",
  ]) {
    const value = process.env[name];
    if (value) {
      parts.push(value);
      labels.push(name);
    }
  }
  return { text: parts.join(" "), label: labels.join(", ") };
}

export interface VerdictInput {
  version: ParsedVersion | null;
  cpu: CpuInfo;
  intrinsics: IntrinsicsState;
  /** Raw `java -version` output, for evidence. */
  rawVersion: string;
}

export interface VerdictResult {
  verdict: Verdict;
  reasons: string[];
  /** The single condition that decides the verdict, for tables. */
  deciding: string;
}

export function decideVerdict(input: VerdictInput): VerdictResult {
  const { version, cpu, intrinsics } = input;
  if (!version) {
    return {
      verdict: "UNKNOWN",
      reasons: ["java -version output could not be parsed"],
      deciding: "version unparseable",
    };
  }
  const patch = patchVerdict(version);
  if (patch === "fixed") {
    return {
      verdict: "SAFE",
      reasons: [
        `${version.raw} is at or above the fixed build for Java ${version.major}`,
      ],
      deciding: "fixed build",
    };
  }
  if (patch === "not-affected") {
    return {
      verdict: "SAFE",
      reasons: [
        version.major < 17 && !version.isPerfPack8
          ? `Java ${version.major} has no AVX-512 Base64 intrinsic`
          : `${version.raw} is below 17.0.6, before the intrinsic shipped`,
      ],
      deciding: "version not affected",
    };
  }
  if (patch === "unknown") {
    return {
      verdict: "UNKNOWN",
      reasons: [
        `no fixed build known for Java ${version.major} in the table checked 2026-11-18`,
      ],
      deciding: "fix status unknown",
    };
  }
  // From here the version is in the affected range.
  if (version.isOpenJ9) {
    return {
      verdict: "SAFE",
      reasons: [
        "OpenJ9 VM detected from -version output; it does not carry the HotSpot intrinsic (detection only, not a guarantee)",
      ],
      deciding: "non-HotSpot VM detected",
    };
  }
  if (cpu.arch !== "x64" && cpu.arch !== "x86_64") {
    return {
      verdict: "SAFE",
      reasons: [
        `CPU arch ${cpu.arch} is not x86-64; the AVX-512 intrinsic does not run here`,
      ],
      deciding: "not x86-64",
    };
  }
  if (cpu.known && !cpu.hasAll) {
    return {
      verdict: "SAFE",
      reasons: [`CPU lacks AVX-512 VBMI flag(s): ${cpu.missing.join(", ")}`],
      deciding: `CPU missing ${cpu.missing.join(", ")}`,
    };
  }
  if (!intrinsics.on) {
    return {
      verdict: "SAFE",
      reasons: [
        `Base64 intrinsics switched off by ${intrinsics.offFlag} (${intrinsics.source})`,
      ],
      deciding: `mitigation flag ${intrinsics.offFlag}`,
    };
  }
  if (!cpu.known) {
    return {
      verdict: "AT-RISK",
      reasons: [
        `${version.raw} is in the affected range but CPU flags could not be read (${cpu.source})`,
        "run on the host itself, or pass --cpuinfo with the host cpuinfo, to decide",
      ],
      deciding: "CPU flags unknown",
    };
  }
  if (!intrinsics.known) {
    return {
      verdict: "AT-RISK",
      reasons: [
        `${version.raw} is in the affected range on an AVX-512 VBMI CPU, but no JVM flag source was found`,
        "confirm no -XX:-UseBASE64Intrinsics flag is set in the service launcher before calling this SAFE",
      ],
      deciding: "intrinsics state unknown",
    };
  }
  return {
    verdict: "EXPOSED",
    reasons: [
      `${version.raw} is in the affected range (fixed build is ${fixedBuildFor(version.major)})`,
      `CPU has all four flags: ${cpu.present.join(", ")}`,
      "Base64 intrinsics are on (default)",
    ],
    deciding: "version + CPU + intrinsics all line up",
  };
}

function fixedBuildFor(major: number): string {
  const table: Record<number, string> = {
    17: "17.0.21.1",
    21: "21.0.13.1",
    25: "25.0.5.1",
    27: "27.0.1.1",
  };
  return table[major] ?? "see the vendor advisory";
}

/** Exit code for a verdict set: 0 = no EXPOSED, 1 = >=1 EXPOSED. */
export function exitForVerdicts(verdicts: Verdict[]): number {
  return verdicts.includes("EXPOSED") ? 1 : 0;
}
