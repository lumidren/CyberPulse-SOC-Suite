-- ==============================================================================
-- CyberPulse SOC Suite: Production Osquery SQL Threat Hunting Queries
-- Framework: MITRE ATT&CK Enterprise Matrix
-- Author: lumidren (https://github.com/lumidren/CyberPulse-SOC-Suite)
-- ==============================================================================

-- 1. Hunt for Suspicious Scheduled Tasks Executing Script Interpreters (T1053.005)
SELECT 
    name, 
    action, 
    path, 
    enabled, 
    hidden 
FROM scheduled_tasks 
WHERE action LIKE '%powershell%' 
   OR action LIKE '%cmd.exe%' 
   OR action LIKE '%wscript%' 
   OR action LIKE '%http%'
   OR path LIKE '%Temp%';

-- 2. Hunt for Unsigned or Suspicious Processes Accessing LSASS Memory Space (T1003.001)
SELECT 
    p.pid, 
    p.name, 
    p.path, 
    p.cmdline, 
    p.parent, 
    u.username 
FROM processes p 
JOIN users u ON p.uid = u.uid 
WHERE p.name IN ('mimikatz.exe', 'procdump.exe', 'procdump64.exe', 'dumpert.exe')
   OR p.path LIKE 'C:\Windows\Temp\%'
   OR p.path LIKE 'C:\Users\%\AppData\Local\Temp\%';

-- 3. Hunt for Disabled Windows Defender Real-Time Monitoring Registry Keys (T1562.001)
SELECT 
    path, 
    name, 
    data 
FROM registry 
WHERE path LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\%'
  AND name IN ('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection')
  AND data = '1';

-- 4. Hunt for Suspicious Listening Ports on User Endpoints (T1110 / C2)
SELECT 
    p.name, 
    p.pid, 
    l.port, 
    l.address, 
    l.protocol 
FROM listening_ports l 
JOIN processes p ON l.pid = p.pid 
WHERE l.port IN (3389, 4444, 1337, 8080, 9001) 
  AND p.name NOT IN ('svchost.exe', 'System');

-- 5. Hunt for Canary Ransomware Extensions in User Profiles (T1486)
SELECT 
    path, 
    filename, 
    size, 
    mtime 
FROM file 
WHERE path LIKE 'C:\Users\%\Documents\%%' 
  AND (filename LIKE '%.locked' OR filename LIKE '%.encrypted' OR filename = 'HOW_TO_DECRYPT.txt');
