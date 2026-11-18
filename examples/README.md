# Examples

## Recorded `java -version` outputs

- `java-version-temurin-17.0.21.txt` - RECORDED 18/11/2026 by running
  the real Eclipse Temurin 17.0.21+9 JRE (downloaded from the Adoptium
  release `jdk-17.0.21+9`) on this build machine. This build is
  VULNERABLE to CVE-2026-114938 (below the fixed 17.0.21.1).
- `java-version-temurin-11.0.33.txt` - RECORDED 18/11/2026 by running
  the real Eclipse Temurin 11.0.33+10 JRE on this build machine. Java
  11 has no AVX-512 Base64 intrinsic: NOT AFFECTED.
- `java-version-oracle-17.0.21.1.txt` - REPRESENTATIVE FORMAT, not a
  live run: the version number and build (17.0.21.1+4) are from the
  Oracle November 2026 CPU / Hadrian write-up, 17/11/2026; the
  three-line layout is the standard Oracle `java -version` format.
  This build is FIXED.

## CPU flag fixtures

- `cpuinfo-no-vbmi.txt` - RECORDED 18/11/2026: the real `flags` line
  of this build machine's /proc/cpuinfo (AMD EPYC 7D13, x86-64). It
  has `bmi2` but none of avx512f / avx512bw / avx512vbmi: a host like
  this is SAFE by CPU.
- `cpuinfo-vbmi.txt` - SYNTHETIC: the same recorded flags line with
  `avx512f avx512bw avx512vbmi bmi2` appended, to show what a
  vulnerable host (Intel Xeon Ice Lake+, AMD Zen 4+) reports.

## Sample app

- `sample-app/Auth.java` - one `Base64.getDecoder().decode` call on a
  header value: a REVIEW site for `decode-scan`.
- `sample-app/Util.java` - `Base64.getEncoder()` only: `decode-scan`
  must NOT flag it.

## Try them

```sh
node dist/cli.js check /tmp/realjdk/jdk-17.0.21+9-jre --cpuinfo examples/cpuinfo-vbmi.txt
# verdict: EXPOSED (recorded vulnerable build + VBMI flags)

node dist/cli.js check /tmp/realjdk/jdk-11.0.33+10-jre --cpuinfo examples/cpuinfo-vbmi.txt
# verdict: SAFE (Java 11 has no AVX-512 Base64 intrinsic)

node dist/cli.js decode-scan examples/sample-app
# 1 Base64 decode site (REVIEW only)
```
