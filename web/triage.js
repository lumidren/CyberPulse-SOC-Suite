// ==============================================================================
// CyberPulse SOC Suite: triage workspace (roadmap F51+)
// All API data is rendered with textContent (CP.el); never as HTML.
// ==============================================================================

const $ = (id) => document.getElementById(id);
const state = { queue: [], selected: null, case: null };

function analystName() {
    try { return localStorage.getItem("cp.analyst") || ""; } catch (e) { return ""; }
}
function setAnalystName(v) {
    try { localStorage.setItem("cp.analyst", v); } catch (e) { /* private mode: keep in memory only */ }
}

function fmtDelay(sec) {
    if (sec === null || sec === undefined) return "detection delay unknown";
    if (sec < 1) return `detected after ${Math.round(sec * 1000)} ms`;
    if (sec < 120) return `detected after ${sec.toFixed(1)} s`;
    return `detected after ${(sec / 60).toFixed(1)} min`;
}

// ------------------------------------------------------------------ F52 queue
async function loadQueue() {
    const mine = $("onlyMine").checked ? `?assignee=${encodeURIComponent(analystName())}` : "";
    const data = await CP.api(`/api/triage/queue${mine}`);
    if (!data) return;
    state.queue = data.queue || [];
    const list = $("caseList");
    list.replaceChildren();
    if (!state.queue.length) list.appendChild(CP.el("p", "Queue is empty.", "section-desc"));
    state.queue.forEach((c, i) => {
        const b = CP.el("button", null, "tw-case" + (c.case_id === state.selected ? " active" : ""));
        b.dataset.index = i;
        const top = CP.el("div", null, "tw-case-top");
        top.appendChild(CP.el("span", c.severity, `tw-sev tw-sev-${c.severity.toLowerCase()}`));
        top.appendChild(CP.el("span", c.status, "tw-status"));
        if (c.simulated) top.appendChild(CP.el("span", "SIMULATED", "tw-badge"));
        b.appendChild(top);
        b.appendChild(CP.el("strong", c.title));
        b.appendChild(CP.el("span", `${c.assignee ? "assigned to " + c.assignee : "unassigned"} · ${c.incidents} incident(s)` +
                                     ` · ${c.open_tasks} open task(s)` + (c.pending_responses ? ` · ${c.pending_responses} awaiting approval` : "")));
        b.addEventListener("click", () => selectCase(c.case_id));
        list.appendChild(b);
    });
    if ((!state.selected || !state.queue.some((c) => c.case_id === state.selected)) && state.queue.length) {
        selectCase(state.queue[0].case_id);
    }
}

async function selectCase(caseId) {
    state.selected = caseId;
    document.querySelectorAll(".tw-case").forEach((b) => b.classList.toggle("active", state.queue[b.dataset.index]?.case_id === caseId));
    const [detail, timeline, tree] = await Promise.all([
        CP.api(`/api/cases/${encodeURIComponent(caseId)}`),
        CP.api(`/api/cases/${encodeURIComponent(caseId)}/timeline`),
        CP.api(`/api/cases/${encodeURIComponent(caseId)}/process-tree`),
    ]);
    if (!detail || detail.error) return;
    state.case = detail.case;
    renderControls(detail.case);
    renderTimeline(timeline);
    renderTree(tree);
}

// ------------------------------------------------------------------ F53 process tree
function treeNode(node) {
    const li = CP.el("li", null, node.relation === "accessed" ? "tw-accessed" : "");
    const label = CP.el("span", node.name, node.alerts.filter(Boolean).length ? "tw-proc tw-proc-alert" : "tw-proc");
    if (node.command_line) label.title = node.command_line;
    li.appendChild(label);
    const rules = node.alerts.filter(Boolean);
    if (rules.length) li.appendChild(CP.el("span", ` ${[...new Set(rules)].join(", ")}`, "tw-muted"));
    if (node.children.length) {
        const ul = CP.el("ul");
        node.children.forEach((c) => ul.appendChild(treeNode(c)));
        li.appendChild(ul);
    }
    return li;
}

function renderTree(data) {
    const box = $("processTree");
    box.replaceChildren();
    if (!data || data.error || !data.hosts.some((h) => h.roots.length)) {
        box.appendChild(CP.el("p", "No process telemetry in this case.", "section-desc"));
        return;
    }
    for (const host of data.hosts) {
        if (!host.roots.length) continue;
        box.appendChild(CP.el("h4", host.host));
        const ul = CP.el("ul");
        host.roots.forEach((r) => ul.appendChild(treeNode(r)));
        box.appendChild(ul);
    }
}

function renderControls(c) {
    $("caseStatus").value = c.status;
    $("caseAssignee").textContent = c.assignee || "unassigned";
    const tasks = $("caseTasks");
    tasks.replaceChildren();
    for (const t of c.tasks) {
        const label = CP.el("label", null, "tw-task");
        const box = document.createElement("input");
        box.type = "checkbox";
        box.checked = t.status === "Done";
        box.addEventListener("change", () => update({ task: t.title, task_status: box.checked ? "Done" : "Open" }));
        label.appendChild(box);
        label.appendChild(CP.el("span", t.title));
        tasks.appendChild(label);
    }
}

function renderTimeline(data) {
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

async function update(change) {
    if (!state.selected) return;
    const analyst = analystName();
    if (!analyst) { $("caseMessage").textContent = "Enter your name first."; $("analystName").focus(); return; }
    const res = await CP.api(`/api/cases/${encodeURIComponent(state.selected)}`, {
        method: "POST", body: JSON.stringify(Object.assign({ analyst }, change)),
    });
    $("caseMessage").textContent = res && res.error ? res.error : "Saved.";
    await loadQueue();
    await selectCase(state.selected);
}

function init() {
    $("analystName").value = analystName();
    $("analystName").addEventListener("change", (e) => setAnalystName(e.target.value.trim()));
    $("onlyMine").addEventListener("change", loadQueue);
    $("caseStatus").addEventListener("change", (e) => update({ status: e.target.value }));
    $("assignMe").addEventListener("click", () => update({ assignee: analystName() }));
    $("addNote").addEventListener("click", () => {
        const note = $("caseNote").value.trim();
        if (note) { update({ note }); $("caseNote").value = ""; }
    });
    loadQueue();
}

init();
