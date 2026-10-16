#!/usr/bin/env bash
# Run the auraAV detection test-suite against the synthetic corpus.
#
# Exits non-zero if any expectation fails, so it works as a CI gate.
set -uo pipefail

BIN="${AURAAV_BIN:-/app/auraav}"
CORPUS="${CORPUS_DIR:-/tmp/auraav-corpus}"
GEN="${GENERATE_SH:-/app/generate.sh}"
LOG="${LOG_FILE:-/tmp/auraav-scan.json}"

echo "==================================================================="
echo " auraAV detection test harness"
echo "   binary : $BIN"
echo "   corpus : $CORPUS"
echo "==================================================================="

"$GEN" "$CORPUS" >/dev/null

echo
echo "--- scan log (sensitivity=high, JSON) ---"
"$BIN" --json --all --sensitivity high scan "$CORPUS" --no-history 2>/dev/null | tee "$LOG"
echo

# Expected verdicts: "name=min-verdict" where min-verdict is Clean|Suspicious|Malicious.
expectations=(
  # generic
  "eicar.com=Malicious"
  "reverse_shell.sh=Suspicious"
  "encoded.ps1=Suspicious"
  "downloader.sh=Suspicious"
  "ransomware_note.txt=Suspicious"
  "meterpreter.bin=Suspicious"
  "packed.bin=Suspicious"
  "dropper.bin=Suspicious"
  "high_entropy.bin=Suspicious"
  # linux
  "linux_reverse_shell.sh=Suspicious"
  "crypto_miner.sh=Suspicious"
  "linux_persistence.sh=Suspicious"
  "elf_clean.bin=Clean"
  "elf_upx.bin=Suspicious"
  # macos
  "com.evil.agent.plist=Suspicious"
  "macos_dropper.js=Suspicious"
  "macos_gatekeeper.sh=Suspicious"
  "macos_reverse_shell.sh=Suspicious"
  "macho_clean.bin=Clean"
  "macho_upx.bin=Suspicious"
  # clean controls
  "clean.txt=Clean"
  "clean.sh=Clean"
  "clean.py=Clean"
  "clean.js=Clean"
)

rank() { case "$1" in Clean) echo 0;; Suspicious) echo 1;; Malicious) echo 2;; *) echo -1;; esac; }

pass=0
fail=0
printf '%-24s %-12s %-12s %s\n' "FILE" "EXPECTED" "GOT" "RESULT"
printf '%s\n' "-------------------------------------------------------------------------"

for spec in "${expectations[@]}"; do
  name="${spec%%=*}"
  want="${spec##*=}"
  got=$(jq -r --arg n "$name" \
        '.[] | select((.file_path | split("/") | last) == $n) | .verdict' "$LOG" 2>/dev/null)
  [ -z "$got" ] && got="MISSING"

  ok="FAIL"
  if [ "$want" = "Clean" ]; then
    [ "$got" = "Clean" ] && ok="ok"
  else
    # threat: got must be >= want
    [ "$(rank "$got")" -ge "$(rank "$want")" ] && ok="ok"
  fi

  printf '%-24s %-12s %-12s %s\n' "$name" "$want" "$got" "$ok"
  if [ "$ok" = "ok" ]; then pass=$((pass+1)); else fail=$((fail+1)); fi
done

echo "-------------------------------------------------------------------------"
echo "passed: $pass   failed: $fail"
echo

if [ "$fail" -ne 0 ]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
