// AegisSOC Web Dashboard Logic & Event Handlers

let alertsData = [];
let totalAlerts = 0;
let criticalAlerts = 0;
let mitreCounts = {
    't1003': 0,
    't1110': 0,
    't1053': 0,
    't1059': 0
};

// Attack Data Presets (client-side fallback & API trigger)
const ATTACK_PRESETS = {
    't1003': {
        technique_id: 'T1003.001',
        rule_name: 'Possible LSASS Memory Dumping via Sysmon Event 10',
        severity: 'CRITICAL',
        computer_name: 'WIN-DC01.corp.local',
        source_ip: '185.220.101.33',
        action: 'ISOLATE_HOST_AND_KILL_PROCESS',
        action_log: 'Isolated host WIN-DC01 via EDR API. Terminated malicious process PID 4812 (mimikatz.exe).',
        intel: {
            ip: '185.220.101.33',
            reputation: 'MALICIOUS',
            abuse_score: '98/100',
            vt_positives: '42 / 72 Security Vendors',
            country: 'Russia (RU)',
            isp: 'BadHost Ltd / TOR Exit Node'
        }
    },
    't1110': {
        technique_id: 'T1110.001',
        rule_name: 'High Volume Brute Force Authentication Spike',
        severity: 'HIGH',
        computer_name: 'CORP-RDP-GW01',
        source_ip: '185.220.101.5',
        action: 'BLOCK_SOURCE_IP_FIREWALL',
        action_log: 'Pushed automated firewall rule: BLOCK INBOUND TCP/UDP from 185.220.101.5 on Perimeter Gateway.',
        intel: {
            ip: '185.220.101.5',
            reputation: 'MALICIOUS',
            abuse_score: '95/100',
            vt_positives: '38 / 72 Security Vendors',
            country: 'Germany (DE)',
            isp: 'Hostinger International / Scanner'
        }
    },
    't1053': {
        technique_id: 'T1053.005',
        rule_name: 'Suspicious Scheduled Task Creation for Persistence',
        severity: 'HIGH',
        computer_name: 'WIN-WORKSTATION09',
        source_ip: '10.0.2.15',
        action: 'REMOVE_SCHEDULED_TASK',
        action_log: 'Purged malicious scheduled task \\SystemHealthUpdate on WIN-WORKSTATION09 via PowerShell Remoting.',
        intel: {
            ip: '10.0.2.15 (Internal Host)',
            reputation: 'INTERNAL COMPROMISED',
            abuse_score: 'N/A (LAN)',
            vt_positives: 'N/A',
            country: 'Internal Domain',
            isp: 'CORP.LOCAL Intranet'
        }
    },
    't1059': {
        technique_id: 'T1059.001',
        rule_name: 'Obfuscated PowerShell Execution Detected',
        severity: 'HIGH',
        computer_name: 'CORP-FINANCE-02',
        source_ip: '10.0.4.88',
        action: 'TERMINATE_PROCESS_TREE',
        action_log: 'Terminated process tree for powershell.exe on CORP-FINANCE-02. Revoked user session for CORP\\m.worker.',
        intel: {
            ip: '10.0.4.88 (Internal Host)',
            reputation: 'SUSPICIOUS SCRIPT',
            abuse_score: 'N/A',
            vt_positives: '54 / 72 (PowerShell.Empire.Stager Hash)',
            country: 'Internal Network',
            isp: 'CORP Finance Segment'
        }
    }
};

async function triggerAttack(attackType) {
    if (attackType === 'random') {
        const types = ['t1003', 't1110', 't1053', 't1059'];
        const selected = types[Math.floor(Math.random() * types.length)];
        return executeAttackPreset(selected);
    }
    
    // Try backend API first, fallback to client simulation
    try {
        const response = await fetch('/api/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: attackType })
        });
        if (response.ok) {
            const data = await response.json();
            processAlertObject(data.alert);
            return;
        }
    } catch (e) {
        // Silent fallback to client simulation if server offline
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
        document.getElementById(`hits-${alert.key}`).innerText = `${mitreCounts[alert.key]} Hits`;
        const cell = document.getElementById(`mitre-${alert.key}`);
        cell.classList.add('active-hit');
    }

    // Render Table Row
    renderAlertRow(alert);

    // Append SOAR Log Terminal
    appendSoarLog(alert.time, alert.action_log);

    // Auto inspect intel for latest alert
    showIntelDetails(alert);
}

function renderAlertRow(alert) {
    const tbody = document.getElementById('alerts-tbody');
    
    // Remove placeholder if present
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
    mitreCounts = { 't1003': 0, 't1110': 0, 't1053': 0, 't1059': 0 };

    document.getElementById('total-alerts-count').innerText = '0';
    document.getElementById('critical-alerts-count').innerText = '0';
    
    ['t1003', 't1110', 't1053', 't1059'].forEach(k => {
        document.getElementById(`hits-${k}`).innerText = '0 Hits';
        document.getElementById(`mitre-${k}`).classList.remove('active-hit');
    });

    const tbody = document.getElementById('alerts-tbody');
    tbody.innerHTML = `
        <tr id="empty-row">
            <td colspan="7" class="text-center placeholder-text">Waiting for attack telemetry... Click an attack button on the left to simulate a threat.</td>
        </tr>
    `;

    document.getElementById('intel-details-container').innerHTML = `
        <p class="placeholder-text">Select an alert from the stream to view VirusTotal & AbuseIPDB threat intelligence enrichment details.</p>
    `;
}
