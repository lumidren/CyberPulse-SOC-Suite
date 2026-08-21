// CyberPulse SOC Web Operations Center Logic

let alertsData = [];
let totalAlerts = 0;
let criticalAlerts = 0;
let mitreCounts = {
    't1003': 0,
    't1110': 0,
    't1053': 0,
    't1059': 0,
    't1562': 0,
    't1486': 0
};
let activeWebhookUrl = "";

// Leaflet Cyber Map State
let map;
let datacenterMarker;
let activeAttackLayers = [];

const DATACENTER_COORDS = [40.7128, -74.0060]; // New York

// Attack Data Presets (client-side fallback & API trigger)
const ATTACK_PRESETS = {
    't1003': {
        technique_id: 'T1003.001',
        rule_name: 'Possible LSASS Memory Dumping via Sysmon Event 10',
        severity: 'CRITICAL',
        computer_name: 'WIN-DC01.corp.local',
        source_ip: '185.220.101.33',
        action: 'ISOLATE_HOST_AND_KILL_PROCESS',
        action_log: '[WinRM TLS 5986 -> WIN-DC01] Injected WFP emergency isolation filter. Terminated PID 4812 (mimikatz.exe).',
        intel: {
            ip: '185.220.101.33',
            reputation: 'MALICIOUS',
            abuse_score: '95/100',
            vt_positives: '38 / 72 Security Vendors',
            country: 'Russia (RU) 🇷🇺',
            isp: 'BadHost Ltd / C2 Harvester',
            lat: 55.7558,
            lon: 37.6173
        }
    },
    't1110': {
        technique_id: 'T1110.001',
        rule_name: 'High Volume Brute Force Authentication Spike',
        severity: 'HIGH',
        computer_name: 'CORP-RDP-GW01',
        source_ip: '185.220.101.5',
        action: 'BLOCK_SOURCE_IP_FIREWALL',
        action_log: '[pfSense Gateway 10.0.0.1:8443] Injected packet drop rule: DROP INBOUND TCP/UDP from 185.220.101.5/32 on WAN.',
        intel: {
            ip: '185.220.101.5',
            reputation: 'MALICIOUS',
            abuse_score: '98/100',
            vt_positives: '42 / 72 Security Vendors',
            country: 'Germany (DE) 🇩🇪',
            isp: 'Hostinger International / Scanner',
            lat: 52.5200,
            lon: 13.4050
        }
    },
    't1053': {
        technique_id: 'T1053.005',
        rule_name: 'Suspicious Scheduled Task Creation for Persistence',
        severity: 'HIGH',
        computer_name: 'WIN-WORKSTATION09',
        source_ip: '10.0.2.15',
        action: 'REMOVE_SCHEDULED_TASK',
        action_log: '[WinRM TLS 5986 -> WIN-WORKSTATION09] Unregistered malicious scheduled task \\SystemHealthUpdate via Unregister-ScheduledTask.',
        intel: {
            ip: '10.0.2.15 (Internal Host)',
            reputation: 'INTERNAL COMPROMISED',
            abuse_score: 'N/A (LAN)',
            vt_positives: 'N/A',
            country: 'Internal Domain 🏢',
            isp: 'CORP.LOCAL Intranet',
            lat: 40.7128,
            lon: -74.0060
        }
    },
    't1059': {
        technique_id: 'T1059.001',
        rule_name: 'Obfuscated PowerShell Execution Detected',
        severity: 'HIGH',
        computer_name: 'CORP-FINANCE-02',
        source_ip: '10.0.4.88',
        action: 'TERMINATE_PROCESS_TREE',
        action_log: '[WinRM -> CORP-FINANCE-02] Terminated process tree for powershell.exe. Dispatched ADSI account lockout for CORP\\m.worker.',
        intel: {
            ip: '10.0.4.88 (Internal Host)',
            reputation: 'SUSPICIOUS SCRIPT',
            abuse_score: 'N/A',
            vt_positives: '54 / 72 (PowerShell.Empire.Stager Hash)',
            country: 'Internal Network 🏢',
            isp: 'CORP Finance Segment',
            lat: 40.7128,
            lon: -74.0060
        }
    },
    't1562': {
        technique_id: 'T1562.001',
        rule_name: 'Windows Defender Real-Time Protection Disabled',
        severity: 'CRITICAL',
        computer_name: 'WIN-WORKSTATION09',
        source_ip: '91.240.118.172',
        action: 'REVERT_DEFENDER_POLICY_AND_ISOLATE',
        action_log: '[WinRM TLS 5986 -> WIN-WORKSTATION09] Re-enabled Windows Defender Real-Time Protection via Set-MpPreference. Host isolated from domain.',
        intel: {
            ip: '91.240.118.172',
            reputation: 'MALICIOUS',
            abuse_score: '88/100',
            vt_positives: '33 / 72 Security Vendors',
            country: 'Ukraine (UA) 🇺🇦',
            isp: 'Hostlife LLC / C2 Stager',
            lat: 50.4501,
            lon: 30.5234
        }
    },
    't1486': {
        technique_id: 'T1486',
        rule_name: 'Rapid Ransomware Canary File Encryption Detected',
        severity: 'CRITICAL',
        computer_name: 'CORP-FINANCE-02',
        source_ip: '193.142.146.210',
        action: 'KILL_RANSOMWARE_PROCESS_AND_RESTORE_VSS',
        action_log: '[WinRM -> CORP-FINANCE-02] Terminated ransomware PID 6140. Initiated automated canary restore from Volume Shadow Copy Snapshot #41.',
        intel: {
            ip: '193.142.146.210',
            reputation: 'MALICIOUS',
            abuse_score: '92/100',
            vt_positives: '49 / 72 Security Vendors',
            country: 'Romania (RO) 🇷🇴',
            isp: 'M247 Europe / Ransomware C2',
            lat: 44.4268,
            lon: 26.1025
        }
    }
};

// Initialize Map on Page Load
window.addEventListener('DOMContentLoaded', () => {
    initCyberMap();
});

function initCyberMap() {
    try {
        map = L.map('cyber-map', {
            center: [30, 0],
            zoom: 2,
            minZoom: 1.5,
            maxZoom: 6,
            zoomControl: false,
            attributionControl: false
        });

        // CartoDB DarkMatter Tiles
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            subdomains: 'abcd',
            maxZoom: 19
        }).addTo(map);

        // Add SOC Datacenter Target Marker
        const dcIcon = L.divIcon({
            className: 'dc-marker',
            iconSize: [14, 14]
        });
        datacenterMarker = L.marker(DATACENTER_COORDS, { icon: dcIcon }).addTo(map);
        datacenterMarker.bindPopup('<b>🏢 Enterprise SOC Gateway (New York Datacenter)</b>');
    } catch (e) {
        console.warn("Leaflet Map failed to load (offline):", e);
    }
}

function renderAttackOnMap(lat, lon, country, ip, technique) {
    if (!map || !lat || !lon) return;
    if (lat === DATACENTER_COORDS[0] && lon === DATACENTER_COORDS[1]) return; // Skip internal LAN IPs

    // Create Pulsing Attacker Marker
    const attackerIcon = L.divIcon({
        className: 'pulsing-marker',
        iconSize: [12, 12]
    });
    const attackerMarker = L.marker([lat, lon], { icon: attackerIcon }).addTo(map);
    attackerMarker.bindPopup(`<b>🚨 Threat Source:</b> ${country}<br><b>IP:</b> ${ip}<br><b>Tactic:</b> ${technique}`).openPopup();

    // Draw glowing animated attack vector line to Datacenter
    const attackLine = L.polyline([[lat, lon], DATACENTER_COORDS], {
        color: '#FF2A55',
        weight: 2,
        opacity: 0.85,
        dashArray: '6, 6'
    }).addTo(map);

    activeAttackLayers.push(attackerMarker, attackLine);

    // Auto-clean old layers after 10 seconds to keep map clean
    setTimeout(() => {
        if (map.hasLayer(attackerMarker)) map.removeLayer(attackerMarker);
        if (map.hasLayer(attackLine)) map.removeLayer(attackLine);
    }, 10000);
}

function saveWebhookUrl() {
    const input = document.getElementById('webhook-input');
    const statusText = document.getElementById('webhook-status');
    const url = input.value.trim();
    if (url.startsWith('http')) {
        activeWebhookUrl = url;
        statusText.innerText = "● Webhook Active (Broadcasting Live Alerts)";
        statusText.className = "webhook-status-text status-online";
    } else {
        activeWebhookUrl = "";
        statusText.innerText = "Local Mode (Offline)";
        statusText.className = "webhook-status-text";
    }
}

async function triggerAttack(attackType) {
    if (attackType === 'random') {
        const types = ['t1003', 't1110', 't1053', 't1059', 't1562', 't1486'];
        const selected = types[Math.floor(Math.random() * types.length)];
        return executeAttackPreset(selected);
    }
    
    // Try backend API first, fallback to client simulation
    try {
        const response = await fetch('/api/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                type: attackType,
                webhook_url: activeWebhookUrl 
            })
        });
        if (response.ok) {
            const data = await response.json();
            processAlertObject(data.alert);
            return;
        }
    } catch (e) {
        // Silent fallback to client simulation
    }
    
    executeAttackPreset(attackType);
}

function executeAttackPreset(key) {
    const preset = ATTACK_PRESETS[key];
    const timestamp = new Date().toLocaleTimeString();

    const alert = {
        id: 'ALT-' + Math.floor(1000 + Math.random() * 9000),
        time: timestamp,
        rule_name: preset.rule_name,
        severity: preset.severity,
        technique_id: preset.technique_id,
        computer_name: preset.computer_name,
        source_ip: preset.source_ip,
        status: 'CONTAINED',
        action_log: preset.action_log,
        intel: preset.intel,
        pipeline_timing: {
            stage1_detection_ms: Math.floor(1380 + Math.random() * 60),
            stage2_threat_intel_ms: Math.floor(590 + Math.random() * 70),
            stage3_containment_ms: Math.floor(1090 + Math.random() * 80),
            total_pipeline_sec: 3.16
        },
        key: key
    };

    processAlertObject(alert);
}

function processAlertObject(alert) {
    alertsData.unshift(alert);
    totalAlerts++;
    if (alert.severity === 'CRITICAL') criticalAlerts++;

    // Update Header Counts
    document.getElementById('total-alerts-count').innerText = totalAlerts;
    document.getElementById('critical-alerts-count').innerText = criticalAlerts;

    // Update MITRE Matrix
    if (mitreCounts.hasOwnProperty(alert.key)) {
        mitreCounts[alert.key]++;
        const badge = document.getElementById(`hits-${alert.key}`);
        if (badge) badge.innerText = `${mitreCounts[alert.key]} Hits`;
        const cell = document.getElementById(`mitre-${alert.key}`);
        if (cell) cell.classList.add('active-hit');
    }

    // Render Table Row
    renderAlertRow(alert);

    // Append SOAR Log Terminal
    appendSoarLog(alert.time, alert.action_log);

    // Auto inspect intel for latest alert
    showIntelDetails(alert);

    // Render GeoIP vector on Threat Map
    if (alert.intel && alert.intel.lat && alert.intel.lon) {
        renderAttackOnMap(alert.intel.lat, alert.intel.lon, alert.intel.country, alert.source_ip, alert.technique_id);
    }
}

function renderAlertRow(alert) {
    const tbody = document.getElementById('alerts-tbody');
    const emptyRow = document.getElementById('empty-row');
    if (emptyRow) emptyRow.remove();

    const tr = document.createElement('tr');
    tr.onclick = () => showIntelDetails(alert);

    const sevClass = alert.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high';

    tr.innerHTML = `
        <td>${alert.time}</td>
        <td><span class="${sevClass}">${alert.severity}</span></td>
        <td><strong>${alert.rule_name}</strong></td>
        <td><code>${alert.technique_id}</code></td>
        <td>${alert.computer_name}</td>
        <td><code>${alert.source_ip}</code></td>
        <td><span class="status-contained">● AUTO-CLOSED</span></td>
    `;

    tbody.insertBefore(tr, tbody.firstChild);
}

function showIntelDetails(alert) {
    const container = document.getElementById('intel-details-container');
    const intel = alert.intel;
    const timing = alert.pipeline_timing || {
        stage1_detection_ms: 1410,
        stage2_threat_intel_ms: 630,
        stage3_containment_ms: 1140,
        total_pipeline_sec: 3.18
    };

    container.innerHTML = `
        <div class="intel-box">
            <div class="intel-row"><span class="key">Target Alert:</span> <span class="val">${alert.id} (${alert.technique_id})</span></div>
            <div class="intel-row"><span class="key">Queried Target:</span> <span class="val">${intel.ip}</span></div>
            <div class="intel-row"><span class="key">Reputation:</span> <span class="val text-critical">${intel.reputation}</span></div>
            <div class="intel-row"><span class="key">VirusTotal Detections:</span> <span class="val">${intel.vt_positives}</span></div>
            <div class="intel-row"><span class="key">AbuseIPDB Score:</span> <span class="val">${intel.abuse_score}</span></div>
            <div class="intel-row"><span class="key">Geo-Location:</span> <span class="val">${intel.country}</span></div>
            <div class="intel-row"><span class="key">ISP / Org:</span> <span class="val">${intel.isp}</span></div>
            <hr style="border: 0; border-top: 1px solid rgba(255,255,255,0.08); margin: 0.4rem 0;">
            <div class="intel-row"><span class="key">⚡ Stage 1 Ingestion/Sigma:</span> <span class="val">${timing.stage1_detection_ms} ms</span></div>
            <div class="intel-row"><span class="key">⚡ Stage 2 Async Intel:</span> <span class="val">${timing.stage2_threat_intel_ms} ms</span></div>
            <div class="intel-row"><span class="key">⚡ Stage 3 Containment:</span> <span class="val">${timing.stage3_containment_ms} ms</span></div>
            <div class="intel-row"><span class="key" style="color: var(--status-green);">🛡️ Total Telemetry-to-Containment:</span> <span class="val" style="color: var(--status-green);">${timing.total_pipeline_sec}s</span></div>
        </div>
    `;
}

function appendSoarLog(time, logText) {
    const terminal = document.getElementById('soar-terminal');
    const line = document.createElement('div');
    line.className = 'term-line';
    line.innerHTML = `<span class="term-time">[${time}]</span> <span class="term-highlight">[SOAR ACTION]</span> ${logText}`;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

function clearAlerts() {
    alertsData = [];
    totalAlerts = 0;
    criticalAlerts = 0;
    mitreCounts = { 't1003': 0, 't1110': 0, 't1053': 0, 't1059': 0, 't1562': 0, 't1486': 0 };

    document.getElementById('total-alerts-count').innerText = '0';
    document.getElementById('critical-alerts-count').innerText = '0';
    
    ['t1003', 't1110', 't1053', 't1059', 't1562', 't1486'].forEach(k => {
        const badge = document.getElementById(`hits-${k}`);
        if (badge) badge.innerText = '0 Hits';
        const cell = document.getElementById(`mitre-${k}`);
        if (cell) cell.classList.remove('active-hit');
    });

    const tbody = document.getElementById('alerts-tbody');
    tbody.innerHTML = `
        <tr id="empty-row">
            <td colspan="7" class="text-center placeholder-text">Waiting for attack telemetry... Click an attack button on the left to simulate a threat.</td>
        </tr>
    `;

    document.getElementById('intel-details-container').innerHTML = `
        <p class="placeholder-text">Select an alert from the stream to view VirusTotal, AbuseIPDB, GeoIP and sub-second pipeline latency metrics.</p>
    `;
}
