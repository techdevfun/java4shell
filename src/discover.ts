/**
 * JDK discovery and probing.
 *
 * A JDK install is a directory holding bin/java. Discovery order:
 * PATH `java`, JAVA_HOME, well-known install dirs per OS, then any
 * --dirs the operator passes. Each install is probed by running
 * `<dir>/bin/java -version` (stderr) with a short timeout. The raw
 * output is kept as evidence; a probe failure is UNKNOWN, never SAFE.
 */
import { execFile } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);

export interface JdkInstall {
  /** JDK home directory. */
  home: string;
  /** Path to the java binary that was probed. */
  javaBin: string;
  /** How this install was found (PATH, JAVA_HOME, well-known dir, --dirs). */
  source: string;
  /** Raw `java -version` output (stdout + stderr), or "" on failure. */
  rawVersion: string;
  /** Probe error, when the binary could not be run. */
  probeError: string | null;
}

export function isJdkHome(dir: string): boolean {
  try {
    return statSync(join(dir, "bin", "java")).isFile();
  } catch {
    return false;
  }
}

function javaBinFor(home: string): string {
  return join(home, "bin", "java");
}

/** Well-known JDK install roots per platform. */
export function wellKnownRoots(): string[] {
  if (process.platform === "darwin") {
    return ["/Library/Java/JavaVirtualMachines"];
  }
  if (process.platform === "win32") {
    return ["C:\\Program Files\\Java", "C:\\Program Files\\Eclipse Adoptium"];
  }
  return ["/usr/lib/jvm", "/opt", "/usr/local"];
}

/** List child dirs of a root that look like JDK homes (one level deep). */
export function scanRoot(root: string): { home: string; source: string }[] {
  const found: { home: string; source: string }[] = [];
  if (isJdkHome(root)) {
    found.push({ home: root, source: `well-known dir ${root}` });
    return found;
  }
  let children: string[];
  try {
    children = readdirSync(root);
  } catch {
    return found;
  }
  for (const child of children) {
    const home = join(root, child);
    if (isJdkHome(home)) {
      found.push({ home, source: `well-known dir ${root}` });
    }
  }
  return found;
}

export interface DiscoverOptions {
  extraDirs: string[];
  includePath: boolean;
}

/** Discover JDK installs. Deduplicated by resolved home path. */
export function discoverJdks(options: DiscoverOptions): JdkInstall[] {
  const seen = new Set<string>();
  const installs: JdkInstall[] = [];
  const add = (home: string, source: string) => {
    const resolved = resolve(home);
    if (seen.has(resolved)) return;
    seen.add(resolved);
    installs.push({
      home: resolved,
      javaBin: javaBinFor(resolved),
      source,
      rawVersion: "",
      probeError: null,
    });
  };
  if (options.includePath) {
    const pathJava = process.env.PATH?.split(":").find((dir) => {
      try {
        return statSync(join(dir, "java")).isFile();
      } catch {
        return false;
      }
    });
    if (pathJava) {
      // PATH java usually lives in <home>/bin; the home is its parent.
      const binDir = resolve(pathJava);
      const home = resolve(binDir, "..");
      if (isJdkHome(home)) add(home, "PATH");
    }
    const javaHome = process.env.JAVA_HOME;
    if (javaHome && isJdkHome(javaHome)) add(javaHome, "JAVA_HOME");
  }
  for (const root of wellKnownRoots()) {
    for (const hit of scanRoot(root)) add(hit.home, hit.source);
  }
  for (const dir of options.extraDirs) {
    if (isJdkHome(dir)) {
      add(dir, "--dirs");
    } else {
      // A dir that is not a JDK home is reported by the caller; here we
      // still record it so the CLI can print a clear warning.
      const resolved = resolve(dir);
      if (!seen.has(resolved)) {
        seen.add(resolved);
        installs.push({
          home: resolved,
          javaBin: javaBinFor(resolved),
          source: "--dirs (not a JDK home: no bin/java)",
          rawVersion: "",
          probeError: "not a JDK home: no bin/java",
        });
      }
    }
  }
  return installs;
}

/** Run `<jdk>/bin/java -version` and capture the raw output. */
export async function probeJdk(install: JdkInstall): Promise<JdkInstall> {
  if (install.probeError) return install;
  try {
    const { stdout, stderr } = await run(install.javaBin, ["-version"], {
      timeout: 15000,
    });
    return { ...install, rawVersion: `${stdout}${stderr}`.trim() };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    // execFile puts the child output on the error object; a non-zero
    // exit from `java -version` still carries the version text.
    const out = (err as { stdout?: string; stderr?: string }).stdout ?? "";
    const errOut = (err as { stdout?: string; stderr?: string }).stderr ?? "";
    const combined = `${out}${errOut}`.trim();
    if (combined.length > 0) {
      return { ...install, rawVersion: combined };
    }
    return {
      ...install,
      probeError: `could not run ${install.javaBin}: ${message}`,
    };
  }
}

/** True when the path exists (used to check --cpuinfo / --jvm-flags files). */
export function fileExists(path: string): boolean {
  try {
    return existsSync(path);
  } catch {
    return false;
  }
}
