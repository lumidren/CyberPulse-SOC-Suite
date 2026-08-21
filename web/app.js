// ==============================================================================
// CyberPulse SOC Suite: Enterprise Operations Console JavaScript Controller
// Author: lumidren (https://github.com/lumidren/CyberPulse-SOC-Suite)
// ==============================================================================

let map;
let datacenterMarker;
let activeAttackLayers = [];
let incidentsData = [];
let activeIncidentId = null;
let customWebhookUrl = "";

const DATACENTER_COORDS = [40.7128, -74.0060]; // New York

// Initialize on DOM Ready
document.addEventListener("DOMContentLoaded", () => {
    initLeafletMap();
    loadIncidents();
    loadMetrics();
    loadDetections();
    loadHealthStatus();
    
    // Poll metrics & health periodically
    setInterval(loadMetrics, 15000);
});

// Tab Switching Controller
function switchTab(tabId) {
    document.querySelectorAll(".tab-content").forEach(el => el.classList.remove("active"));
    document.querySelectorAll(".nav-btn").forEach(el => el.classList.remove("active"));
    
    const targetTab = document.getElementById(tabId);
    if (targetTab) {
        targetTab.classList.add("active");
    }
    
    // Highlight active nav button
    const btn = Array.from(document.querySelectorAll(".nav-btn")).find(b => b.getAttribute("onclick")?.includes(tabId));
    if (btn) btn.classList.add("active");

    if (tabId === "tab-overview" && map) {
        setTimeout(() => map.invalidateSize(), 200);
    }
}

// Leaflet Map Initialization
function initLeafletMap() {
    const mapElement = document.getElementById("cyber-threat-map");
    if (!mapElement) return;

    map = L.map('cyber-threat-map', {
        center: [30.0, 10.0],
        zoom: 2,
        minZoom: 1,
        maxZoom: 7,
        zoomControl: true,
        attributionControl: false
    });

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(map);

    // Enterprise Datacenter Marker (New York)
    const dcIcon = L.divIcon({
        className: 'dc-marker-icon',
        html: '<div style="background:#38bdf8;width:14px;height:14px;border-radius:50%;border:2px solid white;box-shadow:0 0 12px #38bdf8;"></div>',
        iconSize: [14, 14],
        iconAnchor: [7, 7]
    });

    datacenterMarker = L.marker(DATACENTER_COORDS, { icon: dcIcon }).addTo(map);
    datacenterMarker.bindPopup("<strong>🏛️ SOC Datacenter (New York Gateway)</strong><br>10.0.0.0/24 Core Segment");
}

// Draw Animated Vector Arc on Map
function drawAttackTrajectory(sourceLat, sourceLon, country, technique, ip) {
    if (!map) return;

    const sourceCoords = [sourceLat, sourceLon];
    const attackerIcon = L.divIcon({
        className: 'attacker-radar-icon',
        html: '<div style="background:#ef4444;width:12px;height:12px;border-radius:50%;border:2px solid white;box-shadow:0 0 10px #ef4444;"></div>',
        iconSize: [12, 12],
        iconAnchor: [6, 6]
    });

    const marker = L.marker(sourceCoords, { icon: attackerIcon }).addTo(map);
    marker.bindPopup(`<strong>⚔️ Adversary Origin: ${country}</strong><br>IP: ${ip}<br>Technique: ${technique}`).openPopup();

    const polyline = L.polyline([sourceCoords, DATACENTER_COORDS], {
        color: '#ef4444',
        weight: 3,
        opacity: 0.8,
        dashArray: '8, 8'
    }).addTo(map);

    activeAttackLayers.push(marker, polyline);

    // Keep map clean
    if (activeAttackLayers.length > 8) {
        const oldLayer1 = activeAttackLayers.shift();
        const oldLayer2 = activeAttackLayers.shift();
        if (oldLayer1) map.removeLayer(oldLayer1);
        if (oldLayer2) map.removeLayer(oldLayer2);
    }
}

// Adversary Emulation Trigger
async function triggerSimulation(attackType) {
    try {
        const response = await fetch("/api/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                type: attackType,
                webhook_url: customWebhookUrl
            })
        });
        const data = await response.json();
        if (data.status === "SUCCESS" && data.incident) {
            const inc = data.incident;
            const intel = inc.threat_intel?.ip_reputation || {};
            if (intel.lat && intel.lon) {
                drawAttackTrajectory(intel.lat, intel.lon, intel.country || "Adversary", inc.telemetry?.technique_id, inc.telemetry?.source_ip);
            }
            loadIncidents();
            loadMetrics();
        }
    } catch (err) {
        console.error("Simulation error:", err);
    }
}

// Load Incidents Table
async function loadIncidents() {
    try {
        const response = await fetch("/api/incidents");
        const data = await response.json();
        incidentsData = data.incidents || [];
        
        document.getElementById("kpiIncidents").innerText = incidentsData.length;
        const tbody = document.getElementById("incidentTableBody");
        const select = document.getElementById("incidentSelect");

        if (incidentsData.length === 0) {
            tbody.innerHTML = `<tr><td colspan="9" class="empty-state">No incidents recorded yet. Launch an attack above to observe the pipeline!</td></tr>`;
            select.innerHTML = `<option value="">No incidents available</option>`;
            return;
        }

        tbody.innerHTML = incidentsData.map(inc => {
            const sev = inc.rule?.severity || "HIGH";
            const sevClass = sev === "CRITICAL" ? "badge-red" : "badge-orange";
            const score = inc.risk_assessment?.final_score || 0;
            const scoreClass = score >= 85 ? "badge-red" : (score >= 70 ? "badge-orange" : "badge-yellow");

            return `
                <tr>
                    <td><strong>${inc.incident_id}</strong></td>
                    <td>${new Date(inc.created_at).toLocaleTimeString()} UTC</td>
                    <td><code>${inc.telemetry?.computer_name || 'N/A'}</code></td>
                    <td>${inc.threat_intel?.ip_reputation?.flag || '🌐'} ${inc.telemetry?.source_ip || 'N/A'}</td>
                    <td><span class="${sevClass}">${inc.rule?.rule_name}</span> <small>(${inc.telemetry?.technique_id})</small></td>
                    <td><span class="${scoreClass}">${score} / 100</span></td>
                    <td><code>${inc.containment_action?.action_type || 'N/A'}</code></td>
                    <td><span class="badge-green">${inc.status}</span></td>
                    <td><button class="btn-primary" onclick="inspectIncident('${inc.incident_id}')"><i class="fa-solid fa-magnifying-glass"></i></button></td>
                </tr>
            `;
        }).join("");

        // Populate dropdown
        select.innerHTML = incidentsData.map(inc => `<option value="${inc.incident_id}">${inc.incident_id} - ${inc.rule?.rule_name} (${inc.risk_assessment?.final_score} / 100)</option>`).join("");

        if (!activeIncidentId && incidentsData.length > 0) {
            activeIncidentId = incidentsData[0].incident_id;
            loadIncidentDetails();
        }
    } catch (err) {
        console.error("Load incidents error:", err);
    }
}

// Inspect single incident and navigate to Incident Tab
function inspectIncident(incId) {
    activeIncidentId = incId;
    const select = document.getElementById("incidentSelect");
    if (select) select.value = incId;
    loadIncidentDetails();
    switchTab("tab-incident");
}

// Load Incident Details & Timeline
async function loadIncidentDetails() {
    const incId = document.getElementById("incidentSelect")?.value || activeIncidentId;
    if (!incId) return;

    try {
        const response = await fetch(`/api/incidents/${incId}`);
        const data = await response.json();
        const inc = data.incident;
        if (!inc) return;

        activeIncidentId = incId;

        // Dossier Card
        document.getElementById("dossierTitle").innerHTML = `<i class="fa-solid fa-folder-open"></i> Incident ${inc.incident_id}`;
        document.getElementById("dosIncId").innerText = inc.incident_id;
        document.getElementById("dosCorrId").innerText = inc.correlation_id || "N/A";
        document.getElementById("dosHost").innerText = inc.telemetry?.computer_name || "N/A";
        document.getElementById("dosUser").innerText = inc.telemetry?.user || "N/A";
        document.getElementById("dosOrigin").innerText = `${inc.threat_intel?.ip_reputation?.country || 'N/A'} (${inc.telemetry?.source_ip})`;
        document.getElementById("dosMitre").innerText = `${inc.telemetry?.technique_id} - ${inc.telemetry?.technique_name}`;

        // Risk Meter
        const risk = inc.risk_assessment || { final_score: 85.0, risk_level: "CRITICAL", factors: {} };
        document.getElementById("riskMeterBar").style.width = `${risk.final_score}%`;
        document.getElementById("riskScoreVal").innerText = `${risk.final_score} / 100`;
        document.getElementById("riskLevelVal").innerText = risk.risk_level;

        const factors = risk.factors || {};
        document.getElementById("factorsGrid").innerHTML = `
            <div>• Asset Criticality: <strong>${factors.asset_criticality || 0}/100</strong></div>
            <div>• User Privilege: <strong>${factors.user_privilege || 0}/100</strong></div>
            <div>• ATT&CK Tactic: <strong>${factors.tactic_weight || 0}/100</strong></div>
            <div>• Threat Intel Score: <strong>${factors.threat_intel_score || 0}/100</strong></div>
        `;

        // Observables
        const observables = inc.observables || [];
        document.getElementById("observablesList").innerHTML = observables.map(o => `
            <span class="obs-pill"><strong>${o.type}:</strong> ${o.value}</span>
        `).join("");

        // TheHive Case
        const th = inc.thehive_case || {};
        document.getElementById("thehiveTitle").innerText = `Case #${th.case_id || 'N/A'} - ${th.title || 'N/A'}`;
        const tasks = th.tasks || [];
        document.getElementById("thehiveTasks").innerHTML = tasks.map(t => `
            <div>[✓] Task ${t.id}: ${t.title} (<em>${t.status}</em>)</div>
        `).join("");

        // Timeline
        const timeline = inc.timeline || [];
        document.getElementById("timelineContainer").innerHTML = timeline.map(item => `
            <div class="timeline-item">
                <div class="timeline-time">${new Date(item.timestamp).toLocaleTimeString()} UTC - <span class="badge-blue">${item.stage}</span></div>
                <div class="timeline-title">${item.title}</div>
                <div class="timeline-detail">${item.detail}</div>
            </div>
        `).join("");

        // Analyst Notes
        const notes = inc.analyst_notes || [];
        document.getElementById("notesHistory").innerHTML = notes.map(n => `
            <div class="note-entry">
                <strong>${n.author}</strong> <small>(${new Date(n.timestamp).toLocaleTimeString()} UTC)</small><br>
                ${n.note}
            </div>
        `).join("");

        // Rollback Button State
        const rollbackBtn = document.getElementById("rollbackBtn");
        if (inc.status === "ROLLED_BACK") {
            rollbackBtn.disabled = true;
            rollbackBtn.innerHTML = `<i class="fa-solid fa-check"></i> Already Rolled Back`;
        } else {
            rollbackBtn.disabled = false;
            rollbackBtn.innerHTML = `<i class="fa-solid fa-rotate-left"></i> Rollback Containment`;
        }

    } catch (err) {
        console.error("Load incident details error:", err);
    }
}

// Rollback Active Incident Containment
async function rollbackActiveIncident() {
    if (!activeIncidentId) return;
    if (!confirm(`Are you sure you want to roll back containment for ${activeIncidentId}? This will restore network connectivity and reverse firewall rules.`)) return;

    try {
        const res = await fetch(`/api/incidents/${activeIncidentId}/rollback`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ actor: "analyst_lumidren" })
        });
        const data = await res.json();
        if (data.status === "SUCCESS") {
            alert(`[✓] Rollback Succeeded: ${data.rollback.log}`);
            loadIncidentDetails();
            loadIncidents();
        }
    } catch (err) {
        console.error("Rollback error:", err);
    }
}

// Add Analyst Note
async function addAnalystNote() {
    const input = document.getElementById("newNoteInput");
    const note = input?.value.trim();
    if (!note || !activeIncidentId) return;

    try {
        const res = await fetch(`/api/incidents/${activeIncidentId}/notes`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ note: note, author: "analyst_lumidren" })
        });
        const data = await res.json();
        if (data.status === "SUCCESS") {
            input.value = "";
            loadIncidentDetails();
        }
    } catch (err) {
        console.error("Add note error:", err);
    }
}

// Load Detection Catalogue
async function loadDetections() {
    try {
        const res = await fetch("/api/detections");
        const data = await res.json();
        const rules = data.rules || [];

        document.getElementById("detectionCatalogueBody").innerHTML = rules.map(r => `
            <tr>
                <td><strong>${r.detection_id}</strong></td>
                <td>${r.title}</td>
                <td><span class="badge-purple">${r.technique_id}</span></td>
                <td><span class="${r.severity === 'CRITICAL' ? 'badge-red' : 'badge-orange'}">${r.severity}</span></td>
                <td><code>${r.data_source}</code></td>
                <td><code>${r.sigma_rule}</code></td>
                <td><code>${r.wazuh_rule_id}</code></td>
                <td>${r.automated_response}</td>
                <td><span class="badge-green">${r.validation_status}</span></td>
            </tr>
        `).join("");
    } catch (err) {
        console.error("Load detections error:", err);
    }
}

// Run Purple Team Scenario
async function runPurpleScenario(scenarioKey) {
    switchTab("tab-purple");
    const resultsBox = document.getElementById("purpleResultsView");
    const summaryBox = document.getElementById("purpleSummaryBox");
    const tbody = document.getElementById("purpleTableBody");

    resultsBox.style.display = "block";
    summaryBox.innerHTML = `<h3><i class="fa-solid fa-spinner fa-spin"></i> Executing Purple Team Campaign (${scenarioKey})...</h3>`;
    tbody.innerHTML = `<tr><td colspan="10" class="empty-state">Emulating adversary tradecraft across sensors...</td></tr>`;

    try {
        const res = await fetch("/api/purple-team/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario: scenarioKey, webhook_url: customWebhookUrl })
        });
        const data = await res.json();

        summaryBox.innerHTML = `
            <div style="background:#1e1b4b;border:1px solid #6366f1;padding:14px;border-radius:8px;margin-bottom:14px;">
                <h3>🛡️ Campaign Result: ${data.scenario_name}</h3>
                <p>Threat Actor: <strong>${data.threat_actor}</strong> | Status: <span class="badge-green">${data.overall_status}</span> (${data.passed_stages}/${data.total_stages} Stages Verified)</p>
            </div>
        `;

        const stages = data.stage_results || [];
        tbody.innerHTML = stages.map(s => `
            <tr>
                <td><strong>Stage ${s.sequence}</strong></td>
                <td>${s.stage_name}</td>
                <td><span class="badge-purple">${s.technique_id}</span></td>
                <td><code>${s.expected_sensor}</code></td>
                <td><code>${s.expected_rule}</code></td>
                <td><code>${s.matched_rule}</code></td>
                <td><span class="badge-green">${s.status}</span></td>
                <td><strong>${s.risk_score} / 100</strong></td>
                <td><span class="badge-blue">${s.containment_action}</span></td>
                <td>${s.latency_sec}s</td>
            </tr>
        `).join("");

        loadIncidents();
        loadMetrics();
    } catch (err) {
        console.error("Purple scenario error:", err);
    }
}

// Load Health Diagnostics
async function loadHealthStatus() {
    try {
        const res = await fetch("/api/health");
        const data = await res.json();
        const services = data.services || {};

        document.getElementById("healthGrid").innerHTML = Object.entries(services).map(([key, s]) => {
            const isHealthy = s.status === "HEALTHY";
            const badgeClass = isHealthy ? "badge-green" : (s.status === "DEGRADED" ? "badge-yellow" : "badge-blue");

            return `
                <div class="health-card">
                    <div class="health-card-top">
                        <strong>${s.name}</strong>
                        <span class="${badgeClass}">${s.status}</span>
                    </div>
                    <div class="health-msg">${s.message}</div>
                    <div class="health-lat">Target: <code>${s.target}</code> | Latency: <strong>${s.latency_ms}ms</strong> | Mode: ${s.mode}</div>
                </div>
            `;
        }).join("");
    } catch (err) {
        console.error("Load health error:", err);
    }
}

// Load Real Metrics
async function loadMetrics() {
    try {
        const res = await fetch("/api/metrics");
        const data = await res.json();
        const kpis = data.operational_kpis || {};
        const p = data.latency_percentiles_sec || {};

        if (document.getElementById("kpiMttd")) document.getElementById("kpiMttd").innerText = `${kpis.mttd_sec || 1.40}s`;
        if (document.getElementById("kpiMttc")) document.getElementById("kpiMttc").innerText = `${kpis.mttc_sec || 1.15}s`;
        if (document.getElementById("kpiP95")) document.getElementById("kpiP95").innerText = `${p.p95 || 3.28}s`;
    } catch (err) {
        console.error("Load metrics error:", err);
    }
}

// Policy Mode Update
async function updatePolicyMode() {
    const select = document.getElementById("policyModeSelect");
    const mode = select?.value || "AUTOMATIC";
    try {
        await fetch("/api/policy/config", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode: mode })
        });
    } catch (err) {
        console.error("Policy mode error:", err);
    }
}

// Save Webhook
function saveWebhook() {
    const input = document.getElementById("webhookInput");
    const badge = document.getElementById("webhookStatusBadge");
    const val = input?.value.trim();

    if (val && val.startsWith("http")) {
        customWebhookUrl = val;
        badge.className = "webhook-badge active";
        badge.innerText = "CONNECTED";
        alert("[✓] Webhook connected! Incident alerts will be broadcast live.");
    } else {
        customWebhookUrl = "";
        badge.className = "webhook-badge standby";
        badge.innerText = "STANDBY";
    }
}
