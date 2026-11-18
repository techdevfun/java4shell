/**
 * Unit tests: version parsing, fixed-version compare, CPU flags,
 * intrinsics flags, verdict matrix, decode-site scanner.
 * Fixture -version strings: the Temurin 17.0.21+9 and 11.0.33+10 texts
 * are RECORDED from real Temurin JRE runs on this build machine
 * (18/11/2026); other strings use the standard OpenJDK -version
 * layout with version numbers from the vendor advisories.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { cpuFromFlags, parseFlags, REQUIRED_FLAGS } from "../dist/cpu.js";
import { scanJarBytes, scanSourceText } from "../dist/decode.js";
import { decideVerdict, intrinsicsFromFlags } from "../dist/verdict.js";
import {
  compareParts,
  parseJavaVersion,
  patchVerdict,
} from "../dist/versions.js";

const TEMURIN_17_0_21 = `openjdk version "17.0.21" 2026-10-20
OpenJDK Runtime Environment Temurin-17.0.21+9 (build 17.0.21+9)
OpenJDK 64-Bit Server VM Temurin-17.0.21+9 (build 17.0.21+9, mixed mode, sharing)`;

const ORACLE_17_FIXED = `java version "17.0.21.1" 2026-11-17 LTS
Java(TM) SE Runtime Environment (build 17.0.21.1+4-LTS)
Java HotSpot(TM) 64-Bit Server VM (build 17.0.21.1+4-LTS, mixed mode, sharing)`;

const TEMURIN_11 = `openjdk version "11.0.33" 2026-10-20
OpenJDK Runtime Environment Temurin-11.0.33+10 (build 11.0.33+10)
OpenJDK 64-Bit Server VM Temurin-11.0.33+10 (build 11.0.33+10, mixed mode)`;

const ALL_FLAGS = "fpu vme avx512f avx512bw avx512vbmi bmi2 sse4_2";
const NO_VBMI = "fpu vme avx512f avx512bw bmi2 sse4_2";

function cpuAll() {
  return cpuFromFlags(parseFlags(`flags : ${ALL_FLAGS}`), "x64", "fixture");
}

function cpuNoVbmi() {
  return cpuFromFlags(parseFlags(`flags : ${NO_VBMI}`), "x64", "fixture");
}

function cpuUnknown() {
  return {
    arch: "x64",
    flags: [],
    present: [],
    missing: [...REQUIRED_FLAGS],
    hasAll: false,
    source: "unknown",
    known: false,
  };
}

function intrinsicsOn() {
  return intrinsicsFromFlags("", "environment");
}

function intrinsicsOff() {
  return intrinsicsFromFlags("-XX:-UseBASE64Intrinsics", "environment");
}

// --- version parsing ---

test("parse: recorded Temurin 17.0.21+9 parses to 17.0.21 build 9", () => {
  const v = parseJavaVersion(TEMURIN_17_0_21);
  assert.ok(v);
  assert.equal(v.raw, "17.0.21");
  assert.deepEqual(v.parts, [17, 0, 21]);
  assert.equal(v.build, 9);
  assert.equal(v.major, 17);
  assert.match(v.vendor, /Temurin/);
});

test("parse: Oracle fixed 17.0.21.1 parses", () => {
  const v = parseJavaVersion(ORACLE_17_FIXED);
  assert.ok(v);
  assert.equal(v.raw, "17.0.21.1");
  assert.deepEqual(v.parts, [17, 0, 21, 1]);
  assert.equal(v.major, 17);
});

test("parse: Temurin 11.0.33 parses, major 11", () => {
  const v = parseJavaVersion(TEMURIN_11);
  assert.ok(v);
  assert.equal(v.major, 11);
  assert.deepEqual(v.parts, [11, 0, 33]);
});

test("parse: Oracle 8 perf pack is detected", () => {
  const v = parseJavaVersion(
    `java version "1.8.0_511"\nJava(TM) SE Runtime Environment (build 1.8.0_511-b33-perf)\nJava HotSpot(TM) 64-Bit Server VM (build 25.511-b33-perf, mixed mode)`,
  );
  assert.ok(v);
  assert.equal(v.major, 8);
  assert.equal(v.isPerfPack8, true);
});

test("parse: standard Java 8 is not a perf pack", () => {
  const v = parseJavaVersion(
    `java version "1.8.0_471"\nJava(TM) SE Runtime Environment (build 1.8.0_471-b08)`,
  );
  assert.ok(v);
  assert.equal(v.isPerfPack8, false);
});

test("parse: OpenJ9 is detected from -version text", () => {
  const v = parseJavaVersion(
    `openjdk version "17.0.21" 2026-10-20\nIBM Semeru Runtime Open Edition (build 17.0.21+9)\nEclipse OpenJ9 OpenJDK 64-Bit Server VM (build 0.52.0, mixed mode)`,
  );
  assert.ok(v);
  assert.equal(v.isOpenJ9, true);
});

test("parse: garbage output returns null", () => {
  assert.equal(parseJavaVersion("hello world\nno version here\n"), null);
  assert.equal(parseJavaVersion(""), null);
});

// --- version compare / patch verdict ---

test("compareParts: shorter list pads with zero", () => {
  assert.equal(compareParts([17, 0, 21], [17, 0, 21, 1]), -1);
  assert.equal(compareParts([17, 0, 21, 1], [17, 0, 21]), 1);
  assert.equal(compareParts([17, 0, 21], [17, 0, 21]), 0);
  assert.equal(compareParts([21, 0, 13], [17, 0, 21, 1]), 1);
});

test("patch: Temurin 17.0.21+9 is affected (below 17.0.21.1)", () => {
  const v = parseJavaVersion(TEMURIN_17_0_21);
  assert.ok(v);
  assert.equal(patchVerdict(v), "affected");
});

test("patch: Oracle 17.0.21.1 is fixed", () => {
  const v = parseJavaVersion(ORACLE_17_FIXED);
  assert.ok(v);
  assert.equal(patchVerdict(v), "fixed");
});

test("patch: 17.0.5 is not affected (below 17.0.6)", () => {
  const v = parseJavaVersion(
    `openjdk version "17.0.5" 2022-10-18\nOpenJDK Runtime Environment (build 17.0.5+8)`,
  );
  assert.ok(v);
  assert.equal(patchVerdict(v), "not-affected");
});

test("patch: Java 11 is not affected", () => {
  const v = parseJavaVersion(TEMURIN_11);
  assert.ok(v);
  assert.equal(patchVerdict(v), "not-affected");
});

test("patch: 21.0.13 affected, 21.0.13.1 fixed", () => {
  const a = parseJavaVersion(
    `openjdk version "21.0.13" 2026-10-20\nOpenJDK Runtime Environment (build 21.0.13+7)`,
  );
  const b = parseJavaVersion(
    `openjdk version "21.0.13.1" 2026-11-17\nOpenJDK Runtime Environment (build 21.0.13.1+1)`,
  );
  assert.ok(a && b);
  assert.equal(patchVerdict(a), "affected");
  assert.equal(patchVerdict(b), "fixed");
});

test("patch: 25.0.5 affected, 25.0.5.1 fixed; 27.0.1 affected, 27.0.1.1 fixed", () => {
  const cases = [
    [`openjdk version "25.0.5" 2026-10-20`, "affected"],
    [`openjdk version "25.0.5.1" 2026-11-17`, "fixed"],
    [`openjdk version "27.0.1" 2026-10-20`, "affected"],
    [`openjdk version "27.0.1.1" 2026-11-17`, "fixed"],
  ];
  for (const [text, expected] of cases) {
    const v = parseJavaVersion(text);
    assert.ok(v, text);
    assert.equal(patchVerdict(v), expected, text);
  }
});

test("patch: 8u511 perf affected, 8u513 perf fixed", () => {
  const a = parseJavaVersion(
    `java version "1.8.0_511"\nJava(TM) SE Runtime Environment (build 1.8.0_511-b33-perf)`,
  );
  const b = parseJavaVersion(
    `java version "1.8.0_513"\nJava(TM) SE Runtime Environment (build 1.8.0_513-b01-perf)`,
  );
  assert.ok(a && b);
  assert.equal(patchVerdict(a), "affected");
  assert.equal(patchVerdict(b), "fixed");
});

test("patch: future line 28 is unknown, never silently safe", () => {
  const v = parseJavaVersion(
    `openjdk version "28.0.1" 2027-01-01\nOpenJDK Runtime Environment (build 28.0.1+1)`,
  );
  assert.ok(v);
  assert.equal(patchVerdict(v), "unknown");
});

// --- CPU flags ---

test("cpu: all four flags present", () => {
  const cpu = cpuAll();
  assert.equal(cpu.hasAll, true);
  assert.deepEqual(cpu.missing, []);
  assert.deepEqual([...cpu.present].sort(), [...REQUIRED_FLAGS].sort());
});

test("cpu: missing vbmi is detected", () => {
  const cpu = cpuNoVbmi();
  assert.equal(cpu.hasAll, false);
  assert.deepEqual(cpu.missing, ["avx512vbmi"]);
});

test("cpu: sysctl-style Features line parses", () => {
  const flags = parseFlags(
    "machdep.cpu.features: FPU VME AVX512F AVX512BW AVX512VBMI BMI2",
  );
  assert.ok(flags.includes("avx512vbmi"));
  assert.ok(flags.includes("bmi2"));
});

test("cpu: arm64 text with no flags is not VBMI-capable", () => {
  const flags = parseFlags(
    "Features : fp asimd evtstrm aes pmull sha1 sha2 crc32",
  );
  const cpu = cpuFromFlags(flags, "arm64", "fixture");
  assert.equal(cpu.hasAll, false);
  assert.equal(cpu.missing.length, 4);
});

// --- intrinsics flags ---

test("intrinsics: -XX:-UseBASE64Intrinsics switches it off", () => {
  const s = intrinsicsOff();
  assert.equal(s.on, false);
  assert.equal(s.offFlag, "-XX:-UseBASE64Intrinsics");
});

test("intrinsics: -XX:UseAVX=2 switches it off", () => {
  const s = intrinsicsFromFlags("-Xmx2g -XX:UseAVX=2", "environment");
  assert.equal(s.on, false);
  assert.equal(s.offFlag, "-XX:UseAVX=2");
});

test("intrinsics: default is on", () => {
  const s = intrinsicsOn();
  assert.equal(s.on, true);
  assert.equal(s.offFlag, null);
});

// --- verdict matrix ---

function verdictFor(versionText, cpu, intrinsics) {
  const version = versionText ? parseJavaVersion(versionText) : null;
  return decideVerdict({
    version,
    cpu,
    intrinsics,
    rawVersion: versionText ?? "",
  });
}

test("verdict: affected version + all flags + intrinsics on is EXPOSED", () => {
  const r = verdictFor(TEMURIN_17_0_21, cpuAll(), intrinsicsOn());
  assert.equal(r.verdict, "EXPOSED");
});

test("verdict: fixed version is SAFE even on a VBMI CPU", () => {
  const r = verdictFor(ORACLE_17_FIXED, cpuAll(), intrinsicsOn());
  assert.equal(r.verdict, "SAFE");
});

test("verdict: Java 11 is SAFE on a VBMI CPU", () => {
  const r = verdictFor(TEMURIN_11, cpuAll(), intrinsicsOn());
  assert.equal(r.verdict, "SAFE");
});

test("verdict: affected version on a CPU without vbmi is SAFE", () => {
  const r = verdictFor(TEMURIN_17_0_21, cpuNoVbmi(), intrinsicsOn());
  assert.equal(r.verdict, "SAFE");
  assert.match(r.deciding, /avx512vbmi/);
});

test("verdict: affected version with intrinsics off is SAFE", () => {
  const r = verdictFor(TEMURIN_17_0_21, cpuAll(), intrinsicsOff());
  assert.equal(r.verdict, "SAFE");
  assert.match(r.deciding, /UseBASE64Intrinsics/);
});

test("verdict: affected version with unknown CPU is AT-RISK, not SAFE", () => {
  const r = verdictFor(TEMURIN_17_0_21, cpuUnknown(), intrinsicsOn());
  assert.equal(r.verdict, "AT-RISK");
});

test("verdict: affected version on arm64 is SAFE", () => {
  const cpu = cpuFromFlags(
    parseFlags("Features : fp asimd"),
    "arm64",
    "fixture",
  );
  const r = verdictFor(TEMURIN_17_0_21, cpu, intrinsicsOn());
  assert.equal(r.verdict, "SAFE");
});

test("verdict: unparseable version is UNKNOWN", () => {
  const r = verdictFor("garbage\n", cpuAll(), intrinsicsOn());
  assert.equal(r.verdict, "UNKNOWN");
});

test("verdict: OpenJ9 affected version is SAFE by detection", () => {
  const text = `openjdk version "17.0.21" 2026-10-20\nIBM Semeru Runtime Open Edition (build 17.0.21+9)\nEclipse OpenJ9 OpenJDK 64-Bit Server VM (build 0.52.0, mixed mode)`;
  const r = verdictFor(text, cpuAll(), intrinsicsOn());
  assert.equal(r.verdict, "SAFE");
});

test("verdict: future line 28 is UNKNOWN", () => {
  const r = verdictFor(
    `openjdk version "28.0.1" 2027-01-01`,
    cpuAll(),
    intrinsicsOn(),
  );
  assert.equal(r.verdict, "UNKNOWN");
});

// --- decode-site scanner ---

test("decode: Base64.getDecoder() in source is a REVIEW site", () => {
  const sites = scanSourceText(
    `import java.util.Base64;\nbyte[] data = Base64.getDecoder().decode(header);\n`,
    "Auth.java",
  );
  assert.equal(sites.length, 1);
  assert.equal(sites[0].severity, "REVIEW");
  assert.equal(sites[0].line, 2);
});

test("decode: getUrlDecoder and getMimeDecoder are flagged", () => {
  const sites = scanSourceText(
    `Base64.getUrlDecoder().decode(token);\nBase64.getMimeDecoder().decode(body);\n`,
    "Api.java",
  );
  assert.equal(sites.length, 2);
});

test("decode: getEncoder is NOT flagged", () => {
  const sites = scanSourceText(
    `String out = Base64.getEncoder().encodeToString(data);\n`,
    "Encode.java",
  );
  assert.equal(sites.length, 0);
});

test("decode: commented-out decode call is NOT flagged", () => {
  const sites = scanSourceText(
    `// Base64.getDecoder().decode(old);\n`,
    "Old.java",
  );
  assert.equal(sites.length, 0);
});

test("decode: jar bytes with Base64 + getDecoder are a REVIEW site", () => {
  const buf = Buffer.from(
    "PK\x03\x04java/util/Base64\x00getDecoder()V",
    "latin1",
  );
  const sites = scanJarBytes(buf, "app.jar");
  assert.equal(sites.length, 1);
  assert.equal(sites[0].kind, "jar-string");
});

test("decode: jar bytes without decoder strings are clean", () => {
  const buf = Buffer.from(
    "PK\x03\x04com/example/Main\x00getEncoder()V",
    "latin1",
  );
  assert.equal(scanJarBytes(buf, "app.jar").length, 0);
});
