// CyberPulse SOC Suite: mobile status view (roadmap F63). Read-only; text-only rendering.
const $ = (id) => document.getElementById(id);

async function refresh() {
    const s = await CP.api("/api/status/summary");
    if (!s || s.error) return;
    const kill = $("stKill");
    kill.textContent = s.kill_switch_engaged ? "AUTOMATION HALTED (kill switch engaged)" : "Automation running";
    kill.className = "st-card " + (s.kill_switch_engaged ? "st-alert" : "st-ok");
    $("stApprovals").textContent = s.pending_approvals;
    $("stOpen").textContent = s.open_cases;
    $("stUnassigned").textContent = s.unassigned_cases;
    $("stMode").textContent = s.policy_mode.replace("_", " ");
    const sev = $("stSeverity");
    sev.replaceChildren();
    for (const level of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
        const chip = CP.el("span", `${level} ${s.open_by_severity[level] || 0}`, `tw-sev tw-sev-${level.toLowerCase()}`);
        sev.appendChild(chip);
    }
    const recent = $("stRecent");
    recent.replaceChildren();
    if (!s.recent.length) recent.appendChild(CP.el("li", "No incidents yet."));
    for (const r of s.recent) {
        const li = CP.el("li");
        li.appendChild(CP.el("span", r.severity || "?", `tw-sev tw-sev-${(r.severity || "").toLowerCase()}`));
        li.appendChild(CP.el("span", ` ${r.rule || r.incident_id}` + (r.simulated ? " (simulated)" : "")));
        li.appendChild(CP.el("small", (r.at || "").slice(11, 19) + " UTC", "tw-muted"));
        recent.appendChild(li);
    }
    $("stUpdated").textContent = "updated " + new Date().toLocaleTimeString();
}

refresh();
// Poll only while the page is visible, to spare the phone's battery and the server
setInterval(() => { if (!document.hidden) refresh(); }, 30000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
