/**
 * First-hour playbook for CVE-2026-114938 (Java4Shell).
 * All facts checked 2026-11-18 against the Calif write-up, the
 * OpenJDK advisory, Oracle November 2026 CPU, and the CISA alert.
 */

export interface PlaybookStep {
  step: string;
  detail: string;
}

export const PLAYBOOK_STEPS: PlaybookStep[] = [
  {
    step: "1. Find every JDK, not just the system one",
    detail:
      "Run `java4shell scan` on each host. Bundled runtimes inside apps, containers and appliances count: Keycloak, Jenkins, Jira and Confluence often ship their own JDK, and `java -version` on PATH will not see it.",
  },
  {
    step: "2. Patch internet-facing pre-auth apps first",
    detail:
      "Calif demonstrated pre-auth RCE on default configs of Keycloak, Jira, Confluence, JFrog Artifactory, Jenkins and PingFederate. Patch those hosts first, then Kafka, Solr, Elasticsearch, Gerrit and Spinnaker (post-auth in the Calif demo). Fixed Oracle builds: 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1, 8u513-perf. Confirm the exact fixed build in your vendor advisory: Corretto 17.0.21.1.2 carries the fix; Temurin 17.0.21+9 does not.",
  },
  {
    step: "3. Where patching must wait, switch the fast path off",
    detail:
      "Add `-XX:-UseBASE64Intrinsics` to the JVM flags of the service (or `-XX:UseAVX=2`, which also disables the AVX-512 path) and restart the JVM. This is a mitigation, not a fix: patch as soon as the vendor build is available.",
  },
  {
    step: "4. Verify, do not assume",
    detail:
      "Re-run `java4shell scan` after patching or flagging: the verdict must move to SAFE with the deciding condition named (fixed build, or mitigation flag). Also confirm the flag is in the running process arguments, not only in a config file that no launcher reads.",
  },
  {
    step: "5. Check the CPU before declaring a host safe",
    detail:
      "A host is only safe by CPU when it lacks one of avx512f, avx512bw, avx512vbmi or bmi2. Check the host the JVM runs on, not the container image: pass --cpuinfo with the host cpuinfo when scanning from inside a container.",
  },
  {
    step: "6. Do NOT probe with the crashing input",
    detail:
      "Do not send the malformed Base64 string to a live JVM to see if it crashes. The trigger is a heap out-of-bounds write: a probe can corrupt a running service. Decide exposure from version + CPU + flags, which is what this tool does.",
  },
  {
    step: "7. Watch for exploitation reports",
    detail:
      "As of 18/11/2026 there are no reports of exploitation in the wild and the CVE is not in the CISA KEV catalog. That can change quickly after disclosure: re-check the CISA alert and your vendor advisory before closing the incident.",
  },
];

export const EXPLAIN_TOPICS: Record<string, string[]> = {
  "CVE-2026-114938": [
    "Java4Shell (CVE-2026-114938): heap out-of-bounds write in the HotSpot AVX-512 Base64 decoder.",
    "Disclosed 17/11/2026 by Calif (researcher Quang Luong); fixed the same day by Oracle (November 2026 CPU) and the OpenJDK project.",
    "CVSS 4.0: 9.2 Critical (Calif). CVSS 3.1: 8.1 High (Oracle). Both numbers, always.",
    "Trigger, as published: a 65-byte crafted Base64 input (64 'A' characters + '=') makes the decoder write 62 bytes past its heap output buffer.",
    "No exploitation in the wild reported as of 18/11/2026; Calif published a safe trigger-only reproducer, not a weaponised exploit; the per-product exploits are withheld. Not in CISA KEV as of 18/11/2026.",
    "Sources: calif.io/java4shell (200, 18/11/2026), openjdk.org vulnerability advisories (200), CISA alert 17/11/2026 (200), Oracle November 2026 CPU.",
  ],
  EXPOSED: [
    "EXPOSED means all three conditions line up on this host: an affected patch level, an x86-64 CPU with all four AVX-512 VBMI flags, and Base64 intrinsics on.",
    "Action: patch to the fixed build for the line, or switch the fast path off with -XX:-UseBASE64Intrinsics and restart. Then re-run `check` and confirm SAFE.",
  ],
  "AT-RISK": [
    "AT-RISK means the version is in the affected range but a condition could not be read (CPU flags unknown, usually because /proc/cpuinfo is not available).",
    "Action: run on the host itself, or pass --cpuinfo with the host cpuinfo, to decide. Never treat AT-RISK as SAFE.",
  ],
  SAFE: [
    "SAFE means at least one condition does not line up: fixed build, version below 17.0.6, CPU lacks an AVX-512 VBMI flag, not x86-64, intrinsics off, or a non-HotSpot VM detected.",
    "SAFE covers only CVE-2026-114938. It does not mean the host is safe from every Java flaw.",
  ],
  UNKNOWN: [
    "UNKNOWN means the tool could not decide: the version string did not parse, `java -version` failed, or no JDK was found.",
    "Action: check the JDK path by hand and pass it with `check <jdk-dir>`.",
  ],
  intrinsics: [
    "UseBASE64Intrinsics is a HotSpot flag, on by default. It selects the hand-written AVX-512 assembly decoder that carries the flaw.",
    "Switch it off with -XX:-UseBASE64Intrinsics. -XX:UseAVX=2 also disables the AVX-512 path. Either flag is a mitigation, not a fix: patch as soon as the vendor build is available.",
    "The flag must be in the flags the JVM actually starts with. Check the running process arguments, not only a config file.",
  ],
  cpu: [
    "The vulnerable code runs only on x86-64 CPUs with avx512f, avx512bw, avx512vbmi and bmi2 - all four.",
    "Intel Xeon Ice Lake, Sapphire Rapids, Emerald Rapids, Granite Rapids; AMD Zen 4 and newer. ARM64 is not affected.",
    "Linux: grep the flags line of /proc/cpuinfo. This tool reads that file on the host it runs on; pass --cpuinfo with the host file when scanning from a container.",
  ],
  versions: [
    "Affected: OpenJDK 17.0.6 and later, including lines 21, 25 and 27, any vendor build derived from OpenJDK.",
    "Fixed Oracle builds (17/11/2026): 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1, 8u513-perf. Corretto 17.0.21.1.2 carries the fix. Temurin 17.0.21+9 does not.",
    "Not affected: standard Java 8 and 11. Affected exception: Oracle Java SE 8 Enterprise Performance Pack 8u511b33-perf.",
  ],
};
