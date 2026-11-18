/**
 * E2E tests: run the built CLI against fixture JDK dirs in tmp.
 * Each fixture JDK is a fake `java` shell script printing a RECORDED
 * or representative -version output (see test/unit.test.js header for
 * provenance). No real JDK is needed for these tests; one live test
 * below uses the real Temurin 17.0.21+9 JRE when it is present on the
 * build machine, and skips otherwise.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
const CLI = new URL("../dist/cli.js", import.meta.url).pathname;

const TEMURIN_17_0_21 = `openjdk version "17.0.21" 2026-10-20
OpenJDK Runtime Environment Temurin-17.0.21+9 (build 17.0.21+9)
OpenJDK 64-Bit Server VM Temurin-17.0.21+9 (build 17.0.21+9, mixed mode, sharing)`;

const ORACLE_17_FIXED = `java version "17.0.21.1" 2026-11-17 LTS
Java(TM) SE Runtime Environment (build 17.0.21.1+4-LTS)
Java HotSpot(TM) 64-Bit Server VM (build 17.0.21.1+4-LTS, mixed mode, sharing)`;

const TEMURIN_11 = `openjdk version "11.0.33" 2026-10-20
OpenJDK Runtime Environment Temurin-11.0.33+10 (build 11.0.33+10)
OpenJDK 64-Bit Server VM Temurin-11.0.33+10 (build 11.0.33+10, mixed mode)`;

const CPU_VBMI = "flags : fpu vme avx512f avx512bw avx512vbmi bmi2 sse4_2\n";
const CPU_NO_VBMI = "flags : fpu vme avx512f avx512bw bmi2 sse4_2\n";

async function fixtureJdk(root, name, versionText) {
  const home = join(root, name);
  await mkdir(join(home, "bin"), { recursive: true });
  const script = `#!/bin/sh\ncat >&2 <<'EOF'\n${versionText}\nEOF\nexit 0\n`;
  const bin = join(home, "bin", "java");
  await writeFile(bin, script);
  await chmod(bin, 0o755);
  return home;
}

async function fixtureCpu(root, name, text) {
  const path = join(root, name);
  await writeFile(path, text);
  return path;
}

/** Run the CLI, capturing exit code even on non-zero exit. */
async function cli(args) {
  try {
    const { stdout, stderr } = await run("node", [CLI, ...args], {
      timeout: 20000,
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return {
      code: err.code ?? 1,
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? "",
    };
  }
}

test("e2e: check EXPOSED on vulnerable Temurin + VBMI cpuinfo", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "java4shell-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = await fixtureJdk(root, "temurin-17", TEMURIN_17_0_21);
  const cpu = await fixtureCpu(root, "cpuinfo-vbmi.txt", CPU_VBMI);
  const r = await cli(["check", home, "--cpuinfo", cpu]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /verdict: EXPOSED/);
  assert.match(r.stdout, /17\.0\.21/);
});

test("e2e: check SAFE on fixed Oracle build + VBMI cpuinfo", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "java4shell-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = await fixtureJdk(root, "oracle-17-fixed", ORACLE_17_FIXED);
  const cpu = await fixtureCpu(root, "cpuinfo-vbmi.txt", CPU_VBMI);
  const r = await cli(["check", home, "--cpuinfo", cpu]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /verdict: SAFE/);
});

test("e2e: check SAFE on Java 11 + VBMI cpuinfo", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "java4shell-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = await fixtureJdk(root, "temurin-11", TEMURIN_11);
  const cpu = await fixtureCpu(root, "cpuinfo-vbmi.txt", CPU_VBMI);
  const r = await cli(["check", home, "--cpuinfo", cpu]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /verdict: SAFE/);
  assert.match(r.stdout, /no AVX-512 Base64 intrinsic/);
});

test("e2e: check SAFE on vulnerable version + CPU without vbmi", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "java4shell-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = await fixtureJdk(root, "temurin-17", TEMURIN_17_0_21);
  const cpu = await fixtureCpu(root, "cpuinfo-novbmi.txt", CPU_NO_VBMI);
  const r = await cli(["check", home, "--cpuinfo", cpu]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /verdict: SAFE/);
  assert.match(r.stdout, /avx512vbmi/);
});

test("e2e: mitigation flag moves EXPOSED to SAFE", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "java4shell-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = await fixtureJdk(root, "temurin-17", TEMURIN_17_0_21);
  const cpu = await fixtureCpu(root, "cpuinfo-vbmi.txt", CPU_VBMI);
  const flags = join(root, "jvm.flags");
  await writeFile(flags, "-Xmx2g -XX:-UseBASE64Intrinsics\n");
  const r = await cli(["check", home, "--cpuinfo", cpu, "--jvm-flags", flags]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /verdict: SAFE/);
  assert.match(r.stdout, /UseBASE64Intrinsics/);
});

test("e2e: check on a non-JDK dir exits 2", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "java4shell-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const r = await cli(["check", root]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /not a JDK home/);
});

test("e2e: check --json shape", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "java4shell-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = await fixtureJdk(root, "temurin-17", TEMURIN_17_0_21);
  const cpu = await fixtureCpu(root, "cpuinfo-vbmi.txt", CPU_VBMI);
  const r = await cli(["check", home, "--cpuinfo", cpu, "--json"]);
  assert.equal(r.code, 1);
  const data = JSON.parse(r.stdout);
  assert.equal(data.cve, "CVE-2026-114938");
  assert.equal(data.installs.length, 1);
  assert.equal(data.installs[0].verdict, "EXPOSED");
  assert.equal(data.installs[0].version, "17.0.21");
});

test("e2e: scan fleet of three fixtures reports each verdict", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "java4shell-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const vuln = await fixtureJdk(root, "temurin-17", TEMURIN_17_0_21);
  const fixed = await fixtureJdk(root, "oracle-17-fixed", ORACLE_17_FIXED);
  const old = await fixtureJdk(root, "temurin-11", TEMURIN_11);
  const cpu = await fixtureCpu(root, "cpuinfo-vbmi.txt", CPU_VBMI);
  // --json + filter by home: a CI runner may have its own system JDKs
  // under /usr/lib/jvm, so exact fleet counts are not asserted here.
  const r = await cli([
    "scan",
    "--dirs",
    vuln,
    fixed,
    old,
    "--cpuinfo",
    cpu,
    "--json",
  ]);
  assert.equal(r.code, 1);
  const data = JSON.parse(r.stdout);
  const byHome = new Map(data.installs.map((i) => [i.home, i]));
  assert.equal(byHome.get(vuln).verdict, "EXPOSED");
  assert.equal(byHome.get(fixed).verdict, "SAFE");
  assert.equal(byHome.get(old).verdict, "SAFE");
  assert.equal(data.cve, "CVE-2026-114938");
});

test("e2e: decode-scan finds sites in source and reports REVIEW", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "java4shell-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const app = join(root, "app");
  await mkdir(app, { recursive: true });
  await writeFile(
    join(app, "Auth.java"),
    "import java.util.Base64;\npublic class Auth {\n  byte[] d = Base64.getDecoder().decode(h);\n}\n",
  );
  await writeFile(
    join(app, "Util.java"),
    "public class Util {\n  String e = Base64.getEncoder().encodeToString(b);\n}\n",
  );
  const r = await cli(["decode-scan", app]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /1 Base64 decode site/);
  assert.match(r.stdout, /Auth\.java:3/);
  assert.match(r.stdout, /REVIEW only/);
});

test("e2e: decode-scan on clean dir exits 0", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "java4shell-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const app = join(root, "app");
  await mkdir(app, { recursive: true });
  await writeFile(join(app, "Main.java"), "public class Main {}\n");
  const r = await cli(["decode-scan", app]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /0 Base64 decode site/);
});

test("e2e: playbook prints all seven steps", async () => {
  const r = await cli(["playbook"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /UseBASE64Intrinsics/);
  assert.match(r.stdout, /Do NOT probe/);
  assert.match(r.stdout, /17\.0\.21\.1/);
});

test("e2e: explain CVE prints both CVSS scores", async () => {
  const r = await cli(["explain", "CVE-2026-114938"]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /9\.2/);
  assert.match(r.stdout, /8\.1/);
  assert.match(r.stdout, /no public PoC/);
});

test("e2e: init writes a valid config", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "java4shell-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const { stdout } = await run("node", [CLI, "init"], {
    cwd: root,
    timeout: 20000,
  });
  assert.match(stdout, /wrote java4shell\.config\.json/);
  const config = JSON.parse(
    await readFile(join(root, "java4shell.config.json"), "utf8"),
  );
  assert.equal(config.cve, "CVE-2026-114938");
});

test("e2e: --version and unknown command", async () => {
  const v = await cli(["--version"]);
  assert.equal(v.code, 0);
  assert.match(v.stdout, /java4shell 0\.1\.0/);
  const bad = await cli(["frobnicate"]);
  assert.equal(bad.code, 2);
});

test("e2e: real Temurin 17.0.21+9 JRE probes as affected (live, skips if absent)", async (t) => {
  const realHome = "/tmp/realjdk/jdk-17.0.21+9-jre";
  try {
    await readFile(join(realHome, "bin", "java"));
  } catch {
    t.skip("real Temurin 17.0.21+9 JRE not present on this machine");
    return;
  }
  const root = await mkdtemp(join(tmpdir(), "java4shell-e2e-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const cpu = await fixtureCpu(root, "cpuinfo-vbmi.txt", CPU_VBMI);
  const r = await cli(["check", realHome, "--cpuinfo", cpu]);
  assert.equal(r.code, 1);
  assert.match(r.stdout, /verdict: EXPOSED/);
  assert.match(r.stdout, /Temurin-17\.0\.21\+9/);
});
