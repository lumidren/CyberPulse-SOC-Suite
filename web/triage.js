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

// ------------------------------------------------------------------ F54 network graph
function svg(tag, attrs, text) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
    if (text !== undefined) node.textContent = text;
    return node;
}

async function loadNetwork() {
    const data = await CP.api("/api/graph/network");
    const box = $("networkGraph");
    box.replaceChildren();
    if (!data || !data.edges || !data.edges.length) {
        box.appendChild(CP.el("p", "No incidents with a source IP and host yet.", "section-desc"));
        return;
    }
    const sources = data.nodes.filter((n) => n.type === "source");
    const hosts = data.nodes.filter((n) => n.type === "host");
    const rowH = 34, width = 760, height = Math.max(sources.length, hosts.length) * rowH + 20;
    const pos = {};
    sources.forEach((n, i) => { pos[n.id] = [170, 20 + i * rowH]; });
    hosts.forEach((n, i) => { pos[n.id] = [width - 190, 20 + i * rowH]; });
    const root = svg("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "Source to host graph" });
    for (const e of data.edges) {
        const [x1, y1] = pos[e.source], [x2, y2] = pos[e.target];
        const line = svg("line", { x1, y1, x2, y2, class: "tw-edge", "stroke-width": Math.min(1 + e.count, 8) });
        line.appendChild(svg("title", {}, `${e.source} -> ${e.target}: ${e.count} incident(s), ${e.techniques.join(", ")}`));
        root.appendChild(line);
    }
    for (const n of data.nodes) {
        const [x, y] = pos[n.id];
        root.appendChild(svg("circle", { cx: x, cy: y, r: 6, class: `tw-node tw-node-${n.kind}` }));
        root.appendChild(svg("text", { x: n.type === "source" ? x - 12 : x + 12, y: y + 4,
                                       "text-anchor": n.type === "source" ? "end" : "start", class: "tw-node-label" }, n.id));
    }
    box.appendChild(root);
}

// ------------------------------------------------------------------ F55 MTTD / MTTR trend
function fmtDuration(sec) {
    if (sec === null || sec === undefined) return "not yet measured";
    if (sec < 1) return `${Math.round(sec * 1000)} ms`;
    if (sec < 120) return `${sec.toFixed(1)} s`;
    if (sec < 7200) return `${(sec / 60).toFixed(1)} min`;
    return `${(sec / 3600).toFixed(1)} h`;
}

async function loadTrend() {
    const data = await CP.api("/api/metrics/trend");
    const box = $("trendChart");
    box.replaceChildren();
    if (!data) return;
    $("trendBasis").textContent = data.basis;
    const points = data.points || [];
    if (!points.length) { box.appendChild(CP.el("p", "Not yet measured: no incidents with event times.", "section-desc")); return; }
    const series = [["mttd_sec", "MTTD", "tw-line-mttd"], ["mttr_sec", "MTTR", "tw-line-mttr"]];
    const width = 760, height = 220, pad = 40;
    const max = Math.max(...points.flatMap((p) => series.map(([k]) => p[k] || 0)), 0.001);
    const x = (i) => pad + (points.length === 1 ? (width - 2 * pad) / 2 : i * (width - 2 * pad) / (points.length - 1));
    const y = (v) => height - pad - (v / max) * (height - 2 * pad);
    const root = svg("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "MTTD and MTTR per day" });
    root.appendChild(svg("line", { x1: pad, y1: height - pad, x2: width - pad, y2: height - pad, class: "tw-axis" }));
    root.appendChild(svg("text", { x: pad, y: pad - 12, class: "tw-node-label" }, `max ${fmtDuration(max)}`));
    for (const [key, label, cls] of series) {
        const pts = points.map((p, i) => [i, p[key]]).filter(([, v]) => v !== null);
        if (pts.length > 1) root.appendChild(svg("polyline", { points: pts.map(([i, v]) => `${x(i)},${y(v)}`).join(" "), class: cls }));
        for (const [i, v] of pts) {
            const dot = svg("circle", { cx: x(i), cy: y(v), r: 4, class: cls });
            dot.appendChild(svg("title", {}, `${points[i].day} ${label}: ${fmtDuration(v)}`));
            root.appendChild(dot);
        }
    }
    points.forEach((p, i) => root.appendChild(svg("text", { x: x(i), y: height - pad + 16, "text-anchor": "middle", class: "tw-node-label" }, p.day.slice(5))));
    box.appendChild(root);
    const latest = points[points.length - 1];
    box.appendChild(CP.el("p", `Latest day ${latest.day}: MTTD ${fmtDuration(latest.mttd_sec)} over ${latest.incidents} incident(s); ` +
                               `MTTR ${fmtDuration(latest.mttr_sec)} over ${latest.resolved_cases} resolved case(s).`, "tw-muted"));
}

// ------------------------------------------------------------------ F56 top talkers / rules
async function loadTop() {
    const data = await CP.api("/api/stats/top");
    const box = $("topStats");
    box.replaceChildren();
    if (!data) return;
    for (const [key, title] of [["source_ips", "Source IPs"], ["hosts", "Hosts"], ["users", "Users"], ["rules", "Rules"]]) {
        const widget = CP.el("div", null, "tw-top-widget");
        widget.appendChild(CP.el("h4", title));
        const items = data[key] || [];
        if (!items.length) widget.appendChild(CP.el("p", "none yet", "tw-muted"));
        const max = Math.max(1, ...items.map((i) => i.count));
        for (const item of items) {
            const row = CP.el("div", null, "tw-bar-row");
            row.appendChild(CP.el("span", item.value, "tw-bar-label"));
            const bar = CP.el("span", null, "tw-bar");
            bar.style.width = `${Math.round((item.count / max) * 100)}%`;
            row.appendChild(bar);
            row.appendChild(CP.el("span", item.count, "tw-bar-count"));
            widget.appendChild(row);
        }
        box.appendChild(widget);
    }
}

// ------------------------------------------------------------------ F59 global search
let searchTimer = null;
async function runSearch() {
    const q = $("searchBox").value.trim();
    const box = $("searchResults");
    box.replaceChildren();
    if (q.length < 2) return;
    const data = await CP.api(`/api/search?q=${encodeURIComponent(q)}`);
    if (!data) return;
    if (!data.results.length) { box.appendChild(CP.el("p", "No matches.", "tw-muted")); return; }
    for (const r of data.results) {
        const b = CP.el("button", null, "tw-search-hit");
        b.appendChild(CP.el("strong", `${r.type === "case" ? "Case" : "Incident"} ${r.id}`));
        b.appendChild(CP.el("span", `${r.title || ""} · ${r.host || ""} · matched ${r.matched.join(", ")}`, "tw-muted"));
        if (r.case_id) b.addEventListener("click", () => { box.replaceChildren(); selectCase(r.case_id); });
        box.appendChild(b);
    }
    if (data.truncated) box.appendChild(CP.el("p", `Showing ${data.results.length} of ${data.total}; refine the search.`, "tw-muted"));
}

// ------------------------------------------------------------------ F60 saved hunts
async function loadHunts() {
    const data = await CP.api("/api/hunts");
    const box = $("huntList");
    box.replaceChildren();
    if (!data) return;
    for (const h of data.hunts) {
        const row = CP.el("div", null, "tw-hunt");
        const run = CP.el("button", h.name, "tw-hunt-run");
        run.title = `${h.query} (by ${h.owner}, run ${h.runs}x)`;
        run.addEventListener("click", () => { $("searchBox").value = h.query; CP.api(`/api/hunts/${encodeURIComponent(h.id)}/run`); runSearch(); });
        const del = CP.el("button", "\u2715", "pb-mini");
        del.title = "Delete hunt";
        del.addEventListener("click", async () => {
            await CP.api(`/api/hunts/${encodeURIComponent(h.id)}/delete`, { method: "POST", body: JSON.stringify({ analyst: analystName() }) });
            loadHunts();
        });
        row.appendChild(run);
        row.appendChild(del);
        box.appendChild(row);
    }
}

async function saveHunt() {
    const query = $("searchBox").value.trim();
    if (query.length < 2) { $("searchBox").focus(); return; }
    const name = window.prompt("Name for this hunt:", query.slice(0, 60));
    if (!name) return;
    const res = await CP.api("/api/hunts", { method: "POST", body: JSON.stringify({ name, query, analyst: analystName() || "unknown" }) });
    if (res && res.error) window.alert(res.error);
    loadHunts();
}

// ------------------------------------------------------------------ F62 keyboard shortcuts
const SHORTCUTS = {
    j: ["Next case in the queue", () => moveSelection(1)],
    k: ["Previous case in the queue", () => moveSelection(-1)],
    "/": ["Search", () => $("searchBox").focus()],
    a: ["Assign the case to me", () => update({ assignee: analystName() })],
    i: ["Mark Investigating", () => update({ status: "Investigating" })],
    r: ["Mark Resolved", () => update({ status: "Resolved" })],
    n: ["Write a note", () => $("caseNote").focus()],
    "?": ["Show or hide this help", () => { $("shortcutHelp").hidden = !$("shortcutHelp").hidden; }],
};

function moveSelection(delta) {
    if (!state.queue.length) return;
    const i = state.queue.findIndex((c) => c.case_id === state.selected);
    const next = Math.min(state.queue.length - 1, Math.max(0, (i < 0 ? 0 : i + delta)));
    selectCase(state.queue[next].case_id);
    document.querySelectorAll(".tw-case")[next]?.scrollIntoView({ block: "nearest" });
}

function onKey(event) {
    const target = event.target;
    // Never steal keys from text fields, and leave browser/OS shortcuts alone
    if (target.closest("input, textarea, select, [contenteditable]") || event.ctrlKey || event.metaKey || event.altKey) {
        if (event.key === "Escape") target.blur();
        return;
    }
    const entry = SHORTCUTS[event.key];
    if (!entry) return;
    // Write shortcuts are hidden for auditors; the server would refuse them anyway
    if ("air".includes(event.key) && document.documentElement.dataset.role === "auditor") return;
    event.preventDefault();
    entry[1]();
}

function renderShortcutHelp() {
    const list = $("shortcutList");
    for (const [key, [label]] of Object.entries(SHORTCUTS)) {
        const row = CP.el("div", null, "tw-shortcut");
        row.appendChild(CP.el("kbd", key));
        row.appendChild(CP.el("span", label));
        list.appendChild(row);
    }
}

function init() {
    $("analystName").value = analystName();
    $("analystName").addEventListener("change", (e) => setAnalystName(e.target.value.trim()));
    $("onlyMine").addEventListener("change", loadQueue);
    document.addEventListener("keydown", onKey);
    renderShortcutHelp();
    $("saveHunt").addEventListener("click", saveHunt);
    loadHunts();
    $("searchBox").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(runSearch, 250); });
    $("caseStatus").addEventListener("change", (e) => update({ status: e.target.value }));
    $("assignMe").addEventListener("click", () => update({ assignee: analystName() }));
    $("reviewDoc").addEventListener("click", () => {
        if (state.selected) window.open(`/api/cases/${encodeURIComponent(state.selected)}/review`, "_blank");
    });
    $("addNote").addEventListener("click", () => {
        const note = $("caseNote").value.trim();
        if (note) { update({ note }); $("caseNote").value = ""; }
    });
    loadQueue();
    loadNetwork();
    loadTrend();
    loadTop();
}

init();
