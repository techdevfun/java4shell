#!/usr/bin/env bash
# Capture the demo transcript from the REAL CLI (no hand-edited output).
# Fixture JDKs are fake `java` shell scripts printing RECORDED
# -version outputs (see examples/ for provenance):
#   - Temurin 17.0.21+9 (recorded from the real JRE, 18/11/2026): VULNERABLE
#   - Oracle 17.0.21.1 (representative format, fixed build): FIXED
#   - Temurin 11.0.33+10 (recorded from the real JRE, 18/11/2026): NOT AFFECTED
# cpuinfo fixtures are in examples/ (vbmi = synthetic flags line,
# no-vbmi = recorded flags line of this build machine).
# Part 5 applies the mitigation flag to the vulnerable install and
# shows `check` moving EXPOSED -> SAFE.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH=/tmp/java4shell-demo
BIN="$SCRATCH/bin"
rm -rf "$SCRATCH"
mkdir -p "$BIN" "$ROOT/demo"
ln -sf "$ROOT/dist/cli.js" "$BIN/java4shell"
chmod +x "$ROOT/dist/cli.js"
export PATH="$BIN:$PATH"

WORK="$SCRATCH/fleet"
mkdir -p "$WORK"
make_fake_jdk() {
  local name="$1" version_file="$2"
  mkdir -p "$WORK/$name/bin"
  cat > "$WORK/$name/bin/java" <<EOF
#!/bin/sh
cat "$version_file" >&2
exit 0
EOF
  chmod +x "$WORK/$name/bin/java"
}
make_fake_jdk "temurin-17-vuln" "$ROOT/examples/java-version-temurin-17.0.21.txt"
make_fake_jdk "oracle-17-fixed" "$ROOT/examples/java-version-oracle-17.0.21.1.txt"
make_fake_jdk "temurin-11-safe" "$ROOT/examples/java-version-temurin-11.0.33.txt"

CPU_VBMI="$ROOT/examples/cpuinfo-vbmi.txt"
APP="$SCRATCH/sample-app"
cp -r "$ROOT/examples/sample-app" "$APP"
FLAGS="$SCRATCH/jvm.flags"
printf -- "-Xmx2g -XX:-UseBASE64Intrinsics\n" > "$FLAGS"

OUT="$ROOT/demo/transcript.txt"
{
  echo "# java4shell demo - real CLI output on fixture JDKs"
  echo "# (fake java binaries print RECORDED -version outputs from"
  echo "#  examples/; cpuinfo fixtures are in examples/; the fleet"
  echo "#  below is synthetic, the version strings are recorded)"
  echo ""
  echo "\$ java4shell scan --dirs temurin-17-vuln oracle-17-fixed temurin-11-safe --cpuinfo cpuinfo-vbmi.txt"
  java4shell scan --dirs "$WORK/temurin-17-vuln" "$WORK/oracle-17-fixed" "$WORK/temurin-11-safe" --cpuinfo "$CPU_VBMI" || echo "exit: $?"
  echo ""
  echo "\$ java4shell check temurin-17-vuln --cpuinfo cpuinfo-vbmi.txt"
  java4shell check "$WORK/temurin-17-vuln" --cpuinfo "$CPU_VBMI" || echo "exit: $?"
  echo ""
  echo "\$ java4shell decode-scan sample-app"
  java4shell decode-scan "$APP" || echo "exit: $?"
  echo ""
  echo "\$ java4shell playbook"
  java4shell playbook
  echo ""
  echo "# Mitigation: add -XX:-UseBASE64Intrinsics to the JVM flags, restart"
  echo "\$ java4shell check temurin-17-vuln --cpuinfo cpuinfo-vbmi.txt --jvm-flags jvm.flags"
  java4shell check "$WORK/temurin-17-vuln" --cpuinfo "$CPU_VBMI" --jvm-flags "$FLAGS" || echo "exit: $?"
} > "$OUT" 2>&1

echo "transcript written: $OUT ($(wc -l < "$OUT") lines)"
