// ==============================================================================
// CyberPulse SOC Suite: triage workspace (roadmap F51+)
// All API data is rendered with textContent (CP.el); never as HTML.
// ==============================================================================

const $ = (id) => document.getElementById(id);
const state = { cases: [], selected: null };

function fmtDelay(sec) {
    if (sec === null || sec === undefined) return "detection delay unknown";
    if (sec < 1) return `detected after ${Math.round(sec * 1000)} ms`;
    if (sec < 120) return `detected after ${sec.toFixed(1)} s`;
    return `detected after ${(sec / 60).toFixed(1)} min`;
}

async function loadCases() {
    const data = await CP.api("/api/cases");
    if (!data) return;
    state.cases = data.cases || [];
    const list = $("caseList");
    list.replaceChildren();
    if (!state.cases.length) list.appendChild(CP.el("p", "No cases yet. Run a simulation from the console.", "section-desc"));
    for (const c of state.cases) {
        const b = CP.el("button", null, "tw-case" + (c.case_id === state.selected ? " active" : ""));
        b.appendChild(CP.el("strong", c.title));
        b.appendChild(CP.el("span", `${c.severity} · ${c.status} · ${c.incidents.length} incident(s)`));
        b.addEventListener("click", () => selectCase(c.case_id));
        list.appendChild(b);
    }
    if (!state.selected && state.cases.length) selectCase(state.cases[0].case_id);
}

async function selectCase(caseId) {
    state.selected = caseId;
    document.querySelectorAll(".tw-case").forEach((b, i) => b.classList.toggle("active", state.cases[i]?.case_id === caseId));
    const data = await CP.api(`/api/cases/${encodeURIComponent(caseId)}/timeline`);
    if (!data || data.error) return;
    $("caseTitle").textContent = `Attack timeline: ${data.title}`;
    const list = $("timeline");
    list.replaceChildren();
    for (const e of data.entries) {
        const li = CP.el("li");
        li.appendChild(CP.el("time", e.at ? e.at.replace("T", " ").slice(0, 19) + " UTC" : "time unknown"));
        const head = CP.el("strong", `${e.tactic} · ${e.technique}`);
        if (e.simulated) head.appendChild(CP.el("span", "SIMULATED", "tw-badge"));
        li.appendChild(head);
        li.appendChild(CP.el("span", e.rule));
        li.appendChild(CP.el("span", `${e.host || "?"} · ${e.user || "?"} · from ${e.source_ip || "?"}`, "tw-muted"));
        li.appendChild(CP.el("span", `${fmtDelay(e.detection_delay_sec)} · response ${e.response}`, "tw-muted"));
        list.appendChild(li);
    }
}

loadCases();
