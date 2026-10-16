// auraAV detection rules (YARA-like subset).
// Supported: rule/strings/condition, text ("..."), hex ({ AA BB }), regex (/.../).
// Conditions: "any of them", "all of them", "N of them".

rule EICAR_Test_File
  family = EICAR
  type = Known
  severity = 1.0
  strings:
    $magic = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
  condition:
    any of them

rule Suspicious_PowerShell_Download
  family = PowerShellDownloader
  type = Downloader
  severity = 0.75
  strings:
    $a = "IEX"
    $b = "DownloadString"
    $c = "Invoke-Expression"
    $d = "Net.WebClient"
    $e = "-EncodedCommand"
  condition:
    2 of them

rule Suspicious_PowerShell_Encoded
  family = PowerShellObfuscated
  type = Script
  severity = 0.8
  strings:
    $a = "-enc "
    $b = "-EncodedCommand"
    $c = "FromBase64String"
    $d = "FromBase64String"
  condition:
    any of them

rule Suspicious_Shell_Reverse_Shell
  family = ReverseShell
  type = Backdoor
  severity = 0.8
  strings:
    $a = "/dev/tcp/"
    $b = "bash -i"
    $c = "nc -e"
    $d = "ncat -e"
    $e = "socat exec"
  condition:
    2 of them

rule Suspicious_Download_Execute
  family = DownloadExecute
  type = Downloader
  severity = 0.75
  strings:
    $a = "curl "
    $b = "wget "
    $c = "chmod +x"
    $d = "| sh"
    $e = "| bash"
  condition:
    3 of them

rule Suspicious_Encoded_PowerShell
  family = ObfuscatedScript
  type = Script
  severity = 0.7
  strings:
    $a = "-EncodedCommand"
    $b = "FromBase64String"
    $c = "IEX("
  condition:
    2 of them

rule Ransomware_Note_Indicators
  family = Ransomware
  type = Ransomware
  severity = 0.6
  strings:
    $a = "your files have been encrypted"
    $b = "send bitcoin"
    $c = "decrypt your files"
    $d = "pay the ransom"
  condition:
    any of them

rule Reverse_Shell_Python
  family = ReverseShell
  type = Backdoor
  severity = 0.8
  strings:
    $a = "socket.socket"
    $b = "connect(("
    $c = "os.dup2"
    $e = "/bin/sh"
  condition:
    3 of them

rule Mimikatz_Indicators
  family = CredentialTheft
  type = Backdoor
  severity = 0.85
  strings:
    $a = "sekurlsa"
    $b = "lsadump"
    $c = "sekurlsa::logonpasswords"
    $d = "sekurlsa::wdigest"
  condition:
    any of them

rule Meterpreter_Metasploit
  family = Meterpreter
  type = Backdoor
  severity = 0.85
  strings:
    $a = "meterpreter"
    $b = "Meterpreter"
    $c = "metsrv"
  condition:
    any of them

rule Linux_Crypto_Miner
  family = CryptoMiner
  type = Suspicious
  severity = 0.7
  strings:
    $a = "stratum+tcp"
    $b = "stratum+ssl"
    $c = "xmrig"
    $d = "--donate-level"
    $e = "mining.pool"
  condition:
    2 of them

rule Linux_Persistence
  family = Persistence
  type = Suspicious
  severity = 0.6
  strings:
    $a = "@reboot"
    $b = "/etc/cron.d"
    $c = "crontab -l"
    $d = "LD_PRELOAD"
  condition:
    2 of them

rule Linux_Reverse_Shell_Socat
  family = ReverseShell
  type = Backdoor
  severity = 0.75
  strings:
    $a = "nc -e"
    $b = "socat exec"
    $c = "bash -i"
    $d = "/dev/tcp/"
  condition:
    2 of them

rule MacOS_LaunchAgent_Persistence
  family = Persistence
  type = Suspicious
  severity = 0.6
  strings:
    $a = "RunAtLoad"
    $b = "LaunchAgents"
    $c = "LaunchDaemons"
    $d = "ProgramArguments"
    $e = "KeepAlive"
  condition:
    3 of them

rule MacOS_Gatekeeper_Bypass
  family = GatekeeperBypass
  type = Suspicious
  severity = 0.65
  strings:
    $a = "xattr -d com.apple.quarantine"
    $b = "spctl --master-disable"
    $c = "xattr -c"
  condition:
    2 of them

rule MacOS_JXA_Downloader
  family = JXADownloader
  type = Downloader
  severity = 0.75
  strings:
    $a = "ObjC.import"
    $b = "NSURL"
    $c = "NSData"
    $d = "writeToFile"
    $e = "NSTask"
  condition:
    3 of them

rule Suspicious_Kernel_Module
  family = Rootkit
  type = Rootkit
  severity = 0.65
  strings:
    $a = "sys_call_table"
    $b = "kallsyms_lookup_name"
    $c = "register_kprobe"
    $d = "hook_syscall"
  condition:
    2 of them
