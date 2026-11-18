/**
 * Base64 decode-site scanner.
 *
 * Finds places where an application decodes Base64 - the input path
 * the Java4Shell flaw needs. Every hit is REVIEW: a decode site
 * reachable from untrusted input is a candidate for exposure, never
 * proof of exploitability. This tool never claims an application is
 * exploitable, and it never sends the crashing input anywhere.
 *
 * Sources: .java / .kt / .scala / .groovy files (text search for
 * Base64.getDecoder / getUrlDecoder / getMimeDecoder), and .jar /
 * .class files (byte search for the `java/util/Base64` and
 * `getDecoder` strings). Only the decode calls are flagged, never
 * Base64.getEncoder.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative } from "node:path";

export interface DecodeSite {
  file: string;
  line: number | null;
  kind: "source" | "jar-string";
  snippet: string;
  severity: "REVIEW";
}

const SOURCE_EXTS = new Set([".java", ".kt", ".scala", ".groovy"]);
const DECODE_CALLS = [
  "Base64.getDecoder()",
  "Base64.getUrlDecoder()",
  "Base64.getMimeDecoder()",
  "getDecoder().decode",
  "getUrlDecoder().decode",
  "getMimeDecoder().decode",
];

const JAR_MARKERS = [
  "java/util/Base64",
  "getDecoder",
  "getUrlDecoder",
  "getMimeDecoder",
];

/** Find decode calls in one source file. Returns one site per line hit. */
export function scanSourceText(text: string, file: string): DecodeSite[] {
  const sites: DecodeSite[] = [];
  const lines = text.split("\n");
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) return;
    for (const call of DECODE_CALLS) {
      if (line.includes(call)) {
        sites.push({
          file,
          line: index + 1,
          kind: "source",
          snippet: trimmed.slice(0, 160),
          severity: "REVIEW",
        });
        return;
      }
    }
  });
  return sites;
}

/** Byte-level search of a jar/class buffer for Base64 decoder strings. */
export function scanJarBytes(buf: Buffer, file: string): DecodeSite[] {
  const text = buf.toString("latin1");
  const found = JAR_MARKERS.filter((m) => text.includes(m));
  if (found.length === 0) return [];
  // A jar that only mentions the encoder is not a decode site.
  const hasDecoder = found.some(
    (m) => m !== "java/util/Base64" || text.includes("getDecoder"),
  );
  if (!hasDecoder) return [];
  return [
    {
      file,
      line: null,
      kind: "jar-string",
      snippet: `byte strings found: ${found.join(", ")}`,
      severity: "REVIEW",
    },
  ];
}

function walk(dir: string, out: string[]): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (entry === ".git" || entry === "node_modules" || entry === "target")
        continue;
      walk(full, out);
    } else if (st.isFile()) {
      out.push(full);
    }
  }
}

/** Scan a directory tree for decode sites. */
export function scanCodeDir(root: string): DecodeSite[] {
  const files: string[] = [];
  walk(root, files);
  const sites: DecodeSite[] = [];
  for (const file of files) {
    const ext = extname(file).toLowerCase();
    try {
      if (SOURCE_EXTS.has(ext)) {
        const text = readFileSync(file, "utf8");
        sites.push(...scanSourceText(text, relative(root, file)));
      } else if (ext === ".jar" || ext === ".class") {
        const buf = readFileSync(file);
        sites.push(...scanJarBytes(buf, relative(root, file)));
      }
    } catch {
      // Unreadable file: skip, do not crash the scan.
    }
  }
  return sites;
}
