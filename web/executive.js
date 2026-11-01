// CyberPulse SOC Suite: executive summary (roadmap F64). Text-only rendering.
const $ = (id) => document.getElementById(id);

function fmt(sec) {
    if (sec === null || sec === undefined) return "not yet measured";
    if (sec < 1) return `${Math.round(sec * 1000)} ms`;
    if (sec < 120) return `${sec.toFixed(1)} s`;
    if (sec < 7200) return `${(sec / 60).toFixed(0)} minutes`;
    return `${(sec / 3600).toFixed(1)} hours`;
}

function fill(id, rows) {
    const dl = $(id);
    dl.replaceChildren();
    for (const [label, value] of rows) {
        dl.appendChild(CP.el("dt", label));
        dl.appendChild(CP.el("dd", value));
    }
}

async function load() {
    const s = await CP.api("/api/summary/executive");
    if (!s || s.error) return;
    $("exHeadline").textContent = s.headline;
    const sev = s.incidents.by_severity;
    fill("exIncidents", [["Total", s.incidents.total], ["From real telemetry", s.incidents.real],
                         ["Simulated (lab)", s.incidents.simulated],
                         ["Critical / High", `${sev.CRITICAL || 0} / ${sev.HIGH || 0}`]]);
    fill("exResponse", [["Contained", s.response.contained], ["Awaiting approval", s.response.awaiting_approval],
                        ["Rejected by an analyst", s.response.rejected], ["Alert only", s.response.alert_only],
                        ["Stopped by the kill switch", s.response.halted_by_kill_switch]]);
    fill("exCases", [["Open", s.cases.open], ["Resolved", s.cases.resolved], ["Unassigned", s.cases.unassigned]]);
    fill("exSpeed", [["Average time to detect", fmt(s.speed.mean_time_to_detect_sec)],
                     ["Average time to resolve", fmt(s.speed.mean_time_to_resolve_sec)]]);
    fill("exTactics", s.top_tactics.map((t) => [t.tactic, t.count]));
    const caveats = $("exCaveats");
    caveats.replaceChildren();
    s.caveats.forEach((c) => caveats.appendChild(CP.el("li", c)));
}

load();
