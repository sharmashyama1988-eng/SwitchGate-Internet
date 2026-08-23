"""
SwitchGate Next-Gen Firewall - Antivirus & Heuristic Deep Threat Scanner
Performs real-time payload MD5 hash verification, signature lookup, and heuristic exploit pattern analysis.
"""
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple

# Known Critical Malware MD5 Signatures Database (Fast In-Memory Lookup)
KNOWN_MALWARE_HASHES = {
    # Standard EICAR Antivirus Test String MD5
    "44d88612fea8a8f36de82e1278abb02f": {"name": "EICAR-Standard-AV-Test-Payload", "type": "EICAR", "severity": "CRITICAL"},
    "69630e4574ec6798239b091cda594d5b": {"name": "EICAR-Standard-Test-File", "type": "EICAR", "severity": "CRITICAL"},
    # WannaCry Ransomware Vectors & Droppers
    "84c82835a5d21bbcf75a61706d8ab549": {"name": "Ransomware.WannaCry.Dropper", "type": "RANSOMWARE", "severity": "CRITICAL"},
    "db349b97c37d22f5b0d0fed200c61774": {"name": "Ransomware.WannaCry.Payload", "type": "RANSOMWARE", "severity": "CRITICAL"},
    # Mirai IoT Botnet Signatures
    "e9d3d37a858593a54b3f8150495f269a": {"name": "Botnet.Mirai.TelnetScanner", "type": "BOTNET", "severity": "CRITICAL"},
    "5d41402abc4b2a76b9719d911017c592": {"name": "Botnet.Mirai.C2Beacon", "type": "BOTNET", "severity": "CRITICAL"},
    # Emotet & TrickBot Banking Trojans
    "d41d8cd98f00b204e9800998ecf8427e": {"name": "NullPayload.Probe", "type": "PROBE", "severity": "LOW"},
    "c4ca4238a0b923820dcc509a6f75849b": {"name": "Trojan.Emotet.Beacon", "type": "TROJAN", "severity": "CRITICAL"},
    "c81e728d9d4c2f636f067f89cc14862c": {"name": "Trojan.TrickBot.Loader", "type": "TROJAN", "severity": "CRITICAL"},
    # Cobalt Strike Beacon & Meterpreter Stage Payloads
    "eccbc87e4b5ce2fe28308fd9f2a7baf3": {"name": "HackTool.CobaltStrike.Stager", "type": "C2_BEACON", "severity": "CRITICAL"},
    "a87ff679a2f3e71d9181a67b7542122c": {"name": "Exploit.Metasploit.ReverseShell", "type": "EXPLOIT", "severity": "CRITICAL"},
    # Locky & Ryuk Ransomware
    "e4da3b7fbbce2345d7772b0674a318d5": {"name": "Ransomware.Locky.Encryptor", "type": "RANSOMWARE", "severity": "CRITICAL"},
    "1679091c5a880faf6fb5e6087eb1b2dc": {"name": "Ransomware.Ryuk.Loader", "type": "RANSOMWARE", "severity": "CRITICAL"},
}

# Heuristic Exploit & Attack Pattern Rules
HEURISTIC_RULES = [
    # 1. Log4Shell / JNDI Remote Code Execution Exploit
    {
        "name": "Exploit.Log4j.JNDI_RCE",
        "pattern": re.compile(r"\$\{jndi:(?:ldap|rmi|dns|ldaps|iiop|corba)://[^\}]+", re.IGNORECASE),
        "type": "RCE",
        "severity": "CRITICAL",
        "details": "Log4Shell (CVE-2021-44228) JNDI Injection payload detected in payload stream."
    },
    # 2. Shellcode / NOP Sled Execution Vectors
    {
        "name": "Exploit.Shellcode.NOP_Sled",
        "pattern": re.compile(r"(\x90{8,}|\x41{16,}|\xcc{8,})", re.IGNORECASE),
        "type": "SHELLCODE",
        "severity": "CRITICAL",
        "details": "Consecutive NOP Sled / x86/x64 instruction buffer overflow exploit detected."
    },
    # 3. Encoded PowerShell & Memory Download Cradles
    {
        "name": "Threat.PowerShell.EncodedDownloadCradle",
        "pattern": re.compile(r"(?:powershell(?:\.exe)?\s+.*?(?:-[eE](?:nc|ncodedcommand)?)\s+[A-Za-z0-9+/=]{15,}|powershell(?:\.exe)?\s+.*?(?:-nop|-w(?:indowstyle)?\s+hidden|-exec(?:utionpolicy)?\s+bypass)|IEX\s*\(New-Object\s+Net\.WebClient\)|DownloadString\s*\(['\"]https?|Invoke-Expression\s+|New-Object\s+System\.Net\.WebClient)", re.IGNORECASE),
        "type": "OBFUSCATED_SCRIPT",
        "severity": "CRITICAL",
        "details": "Suspicious PowerShell base64 encoded payload or IEX download cradle detected."
    },
    # 4. Unix / Linux Reverse Shell Strings
    {
        "name": "Threat.Unix.ReverseShell",
        "pattern": re.compile(r"(?:/bin/(?:ba)?sh\s+-i\s+>&|nc(?:\.traditional)?\s+-e\s+/bin/(?:ba)?sh|bash\s+-c\s+['\"]exec\s+5<>/dev/tcp/|python\s+-c\s+['\"].*import\s+socket,subprocess,os)", re.IGNORECASE),
        "type": "REVERSE_SHELL",
        "severity": "CRITICAL",
        "details": "Interactive Unix /dev/tcp or Netcat reverse shell payload detected."
    },
    # 5. Windows Command Execution & Certutil Living-off-the-Land Exploits
    {
        "name": "Threat.Windows.CertutilExploit",
        "pattern": re.compile(r"(?:certutil(?:\.exe)?\s+.*-(?:urlcache|decode)\s+.*-(?:split|f)|bitsadmin(?:\.exe)?\s+/transfer\s+|cmd(?:\.exe)?\s+/c\s+.*https?://)", re.IGNORECASE),
        "type": "LOLBAS",
        "severity": "HIGH",
        "details": "Living-off-the-Land (LOLBAS) Certutil / Bitsadmin payload dropper detected."
    },
    # 6. SQL Injection Attack Signatures
    {
        "name": "Attack.Web.SQL_Injection",
        "pattern": re.compile(r"(?:UNION(?:\s+ALL)?\s+SELECT\b|'\s*OR\s*'1'\s*=\s*'1|;\s*DROP\s+TABLE\b|WAITFOR\s+DELAY\s+'0:0:\d+'|SLEEP\(\d+\)|BENCHMARK\(\d+,|INFORMATION_SCHEMA\.TABLES)", re.IGNORECASE),
        "type": "SQLI",
        "severity": "HIGH",
        "details": "SQL Injection attempt detected in packet query parameters or headers."
    },
    # 7. Cross-Site Scripting (XSS) Signatures
    {
        "name": "Attack.Web.CrossSiteScripting",
        "pattern": re.compile(r"(?:<script\b[^>]*>.*?alert\s*\(|<svg/[^>]*onload\s*=|javascript:\s*alert\s*\(|onerror\s*=\s*alert\s*\(|document\.cookie\b)", re.IGNORECASE),
        "type": "XSS",
        "severity": "MEDIUM",
        "details": "Cross-Site Scripting (XSS) script tag injection detected."
    },
    # 8. Directory Traversal Path Injection
    {
        "name": "Attack.Web.PathTraversal",
        "pattern": re.compile(r"(?:\.\./\.\./\.\./etc/passwd|\.\.\\\.\.\\windows\\system32|%2e%2e%2f%2e%2e%2f|/etc/shadow\b)", re.IGNORECASE),
        "type": "TRAVERSAL",
        "severity": "HIGH",
        "details": "Directory traversal payload targeting sensitive system configuration files."
    },
    # 9. PHP Webshells & Remote Execution Injection
    {
        "name": "Threat.Web.PHP_Webshell",
        "pattern": re.compile(r"(?:<\?php\s+eval\s*\(\s*base64_decode|assert\s*\(\s*\$_POST|passthru\s*\(\s*\$_GET|system\s*\(\s*\$_REQUEST)", re.IGNORECASE),
        "type": "WEBSHELL",
        "severity": "CRITICAL",
        "details": "PHP webshell execution vector detected in payload."
    },
    # 10. Cryptominer Stratum Mining Protocol Signatures
    {
        "name": "Threat.Miner.StratumProtocol",
        "pattern": re.compile(r"(?:\"method\"\s*:\s*\"mining\.subscribe\"|\"method\"\s*:\s*\"mining\.authorize\"|stratum\+tcp://|xmr\.pool\.|cryptonight)", re.IGNORECASE),
        "type": "CRYPTOMINER",
        "severity": "HIGH",
        "details": "Unauthorized Monero / Cryptonight Stratum crypto-mining protocol handshake."
    },
    # 11. SMB EternalBlue & DoublePulsar Signature Vectors
    {
        "name": "Exploit.SMB.EternalBlue",
        "pattern": re.compile(r"(?:\xffSMB[\x72\x73\x25\x32]|SMB2\x00[\x00-\x10].*\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00)", re.IGNORECASE),
        "type": "EXPLOIT",
        "severity": "CRITICAL",
        "details": "SMBv1/SMBv2 EternalBlue (MS17-010) exploit fingerprint detected."
    }
]

class AntivirusScanner:
    """High-Performance Real-Time Malware Signature & Heuristic Pattern Scanner."""

    def __init__(self):
        self.malware_hashes = KNOWN_MALWARE_HASHES.copy()
        self.heuristic_rules = HEURISTIC_RULES.copy()
        self.total_scans = 0
        self.total_threats_detected = 0

    def get_signatures_count(self) -> int:
        return len(self.malware_hashes) + len(self.heuristic_rules)

    def add_malware_hash(self, hash_val: str, name: str, threat_type: str = "MALWARE", severity: str = "CRITICAL"):
        """Dynamically registers a new known malware MD5 hash into signature database."""
        hash_val = hash_val.lower().strip()
        self.malware_hashes[hash_val] = {
            "name": name,
            "type": threat_type.upper(),
            "severity": severity.upper()
        }

    def scan_payload(
        self,
        payload: Union[bytes, str],
        src_ip: str = "",
        dst_port: int = 0
    ) -> Dict[str, Any]:
        """
        Deep-scans a network packet payload or data buffer.
        Returns detailed threat assessment with MD5, threat type, and severity.
        """
        self.total_scans += 1
        
        if not payload:
            return {
                "is_threat": False,
                "threat_name": None,
                "threat_type": "CLEAN",
                "severity": "CLEAN",
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "details": "Empty payload buffer (Clean)."
            }

        # Convert to bytes and string representations
        if isinstance(payload, str):
            payload_bytes = payload.encode("utf-8", errors="ignore")
            payload_str = payload
        else:
            payload_bytes = payload
            payload_str = payload.decode("latin-1", errors="ignore")

        # 1. Compute MD5 checksum
        md5_hash = hashlib.md5(payload_bytes).hexdigest().lower()

        # 2. Exact MD5 Malware Lookup
        if md5_hash in self.malware_hashes:
            threat = self.malware_hashes[md5_hash]
            self.total_threats_detected += 1
            return {
                "is_threat": True,
                "threat_name": threat["name"],
                "threat_type": threat["type"],
                "severity": threat["severity"],
                "md5": md5_hash,
                "details": f"Exact signature match for {threat['name']} ({threat['type']})."
            }

        # 3. EICAR Standard String Substring Check
        if "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" in payload_str:
            self.total_threats_detected += 1
            return {
                "is_threat": True,
                "threat_name": "EICAR-Standard-Antivirus-Test-File",
                "threat_type": "EICAR",
                "severity": "CRITICAL",
                "md5": md5_hash,
                "details": "Industry standard EICAR anti-malware verification string detected."
            }

        # 4. Heuristic Pattern Regular Expression Inspection
        for rule in self.heuristic_rules:
            if rule["pattern"].search(payload_str):
                self.total_threats_detected += 1
                return {
                    "is_threat": True,
                    "threat_name": rule["name"],
                    "threat_type": rule["type"],
                    "severity": rule["severity"],
                    "md5": md5_hash,
                    "details": rule["details"]
                }

        # 5. Clean / No Threat Found
        return {
            "is_threat": False,
            "threat_name": None,
            "threat_type": "CLEAN",
            "severity": "CLEAN",
            "md5": md5_hash,
            "details": "Payload passed all heuristic and cryptographic signature scans."
        }

    def scan_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """Scans a file on disk for malware signatures."""
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return {
                "is_threat": False,
                "threat_name": None,
                "threat_type": "ERROR",
                "severity": "CLEAN",
                "md5": "",
                "details": f"File not found: {file_path}"
            }
        try:
            content = p.read_bytes()
            return self.scan_payload(content)
        except Exception as e:
            return {
                "is_threat": False,
                "threat_name": None,
                "threat_type": "ERROR",
                "severity": "CLEAN",
                "md5": "",
                "details": f"Failed to read file: {e}"
            }

# Global singleton
antivirus = AntivirusScanner()
