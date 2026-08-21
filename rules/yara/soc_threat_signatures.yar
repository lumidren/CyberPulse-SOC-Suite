/*
    YARA Rulebase for CyberPulse SOC Suite
    Detects Memory Dumper Binaries, Ransomware Canaries, and Obfuscated PowerShell Interpreters
*/

rule Detect_Mimikatz_Memory_Dumper {
    meta:
        description = "Detects Mimikatz memory scraping strings and LSASS manipulation artifacts"
        author = "lumidren"
        technique = "T1003.001"
        date = "2026-08-21"
        severity = "Critical"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "lsasrv.dll" ascii wide nocase
        $s3 = "mimikatz" ascii wide nocase
        $s4 = "wdigest.dll" ascii wide nocase
        $s5 = "privilege::debug" ascii wide nocase
        $s6 = "sekurlsa::minidump" ascii wide nocase
    condition:
        2 of ($s*)
}

rule Detect_Ransomware_Canary_Note {
    meta:
        description = "Detects generic ransomware extortion note patterns and canary indicator text"
        author = "lumidren"
        technique = "T1486"
        date = "2026-08-21"
        severity = "Critical"
    strings:
        $r1 = "Your personal files are encrypted" ascii wide nocase
        $r2 = "HOW_TO_DECRYPT" ascii wide nocase
        $r3 = "Send bitcoin to the following address" ascii wide nocase
        $r4 = "decrypt your files" ascii wide nocase
        $r5 = "Tor Browser" ascii wide nocase
    condition:
        2 of ($r*)
}

rule Detect_Obfuscated_PowerShell_Download_Cradle {
    meta:
        description = "Detects obfuscated PowerShell web download cradles and bypass arguments"
        author = "lumidren"
        technique = "T1059.001"
        date = "2026-08-21"
        severity = "High"
    strings:
        $p1 = "Net.WebClient" ascii wide nocase
        $p2 = "DownloadString" ascii wide nocase
        $p3 = "IEX" ascii wide nocase
        $p4 = "-EncodedCommand" ascii wide nocase
        $p5 = "ExecutionPolicy Bypass" ascii wide nocase
        $p6 = "FromBase64String" ascii wide nocase
    condition:
        3 of ($p*)
}
