// ==============================================================================
// CyberPulse SOC Suite: Playbook editor (roadmap F33)
// Drafts are validated by POST /api/playbooks/validate and downloaded as YAML;
// the server never writes playbooks, so changes still go through code review.
// All text from the server is inserted with textContent, never as HTML.
// ==============================================================================

let csrfToken = null;
let playbooks = [];
let tasks = [];

async function api(url, options = {}) {
    options = Object.assign({ credentials: "same-origin" }, options);
    if ((options.method || "GET").toUpperCase() !== "GET") {
        if (!csrfToken) {
            const s = await (await fetch("/api/session", { credentials: "same-origin" })).json();
            if (!s.authenticated) { window.location.replace("/login.html"); return null; }
            csrfToken = s.csrf_token;
        }
        options.headers = Object.assign({ "Content-Type": "application/json", "X-CSRF-Token": csrfToken }, options.headers || {});
    }
    const res = await fetch(url, options);
    if (res.status === 401) { window.location.replace("/login.html"); return null; }
    return res.json();
}

const $ = (id) => document.getElementById(id);
const csv = (value) => value.split(",").map((s) => s.trim()).filter(Boolean);

function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
}

function draft() {
    const doc = { name: $("pbName").value.trim(), version: $("pbVersion").value.trim(), description: $("pbDescription").value.trim() };
    const rules = csv($("pbRules").value), techniques = csv($("pbTechniques").value);
    if (rules.length || techniques.length) {
        doc.match = {};
        if (rules.length) doc.match.rules = rules;
        if (techniques.length) doc.match.techniques = techniques;
    }
    const response = { require_approval: $("pbApproval").checked, notify: $("pbNotify").checked };
    if ($("pbAction").value) response.action = $("pbAction").value;
    if ($("pbMinRisk").value !== "") response.min_risk = Number($("pbMinRisk").value);
    doc.response = response;
    if (tasks.length) doc.tasks = tasks.slice();
    return doc;
}

// Minimal YAML writer for the playbook shape (strings are always quoted)
function toYaml(doc) {
    const q = (s) => JSON.stringify(String(s));
    const lines = [`name: ${q(doc.name)}`, `version: ${q(doc.version)}`, `description: ${q(doc.description)}`];
    if (doc.match) {
        lines.push("match:");
        for (const key of ["rules", "techniques"]) if (doc.match[key]) lines.push(`  ${key}: [${doc.match[key].map(q).join(", ")}]`);
    }
    lines.push("response:");
    for (const [key, value] of Object.entries(doc.response)) lines.push(`  ${key}: ${typeof value === "string" ? q(value) : value}`);
    if (doc.tasks) { lines.push("tasks:"); doc.tasks.forEach((t) => lines.push(`  - ${q(t)}`)); }
    return lines.join("\n") + "\n";
}

function renderTasks() {
    const list = $("pbTasks");
    list.replaceChildren();
    tasks.forEach((task, i) => {
        const item = el("li", task);
        for (const [label, fn] of [["↑", () => move(i, -1)], ["↓", () => move(i, 1)], ["✕", () => { tasks.splice(i, 1); refresh(); }]]) {
            const b = el("button", label, "pb-mini");
            b.addEventListener("click", fn);
            item.appendChild(b);
        }
        list.appendChild(item);
    });
}

function move(i, delta) {
    const j = i + delta;
    if (j < 0 || j >= tasks.length) return;
    [tasks[i], tasks[j]] = [tasks[j], tasks[i]];
    refresh();
}

function renderFlow(doc) {
    const flow = $("pbFlow");
    flow.replaceChildren();
    const m = doc.match ? [...(doc.match.rules || []), ...(doc.match.techniques || [])].join(", ") : "anything not matched elsewhere (default)";
    const steps = [
        ["Alert matches", m],
        ["Evidence collected", "always, before any containment (cannot be disabled)"],
        ["Proposed action", doc.response.action || "the rule's mapped action"],
        ["Risk gate", doc.response.min_risk !== undefined ? `contain only if risk ≥ ${doc.response.min_risk}, else alert only` : "none (policy decides)"],
        ["Approval", doc.response.require_approval ? "analyst approval always required" : "policy default (approval unless opt-in automatic TIER_1)"],
        ["Notify", doc.response.notify ? "chat notification (pseudonymised)" : "no notification"],
        ["Case tasks", doc.tasks ? `${doc.tasks.length} task(s)` : "none"],
    ];
    for (const [title, detail] of steps) {
        const li = el("li");
        li.appendChild(el("strong", title));
        li.appendChild(el("span", detail));
        flow.appendChild(li);
    }
}

function refresh() {
    renderTasks();
    const doc = draft();
    renderFlow(doc);
    $("pbYaml").textContent = toYaml(doc);
}

function load(pb) {
    $("pbName").value = pb.name || "";
    $("pbVersion").value = pb.version || "";
    $("pbDescription").value = pb.description || "";
    $("pbRules").value = ((pb.match || {}).rules || []).join(", ");
    $("pbTechniques").value = ((pb.match || {}).techniques || []).join(", ");
    const r = pb.response || {};
    $("pbAction").value = r.action || "";
    $("pbMinRisk").value = r.min_risk !== undefined ? r.min_risk : "";
    $("pbApproval").checked = !!r.require_approval;
    $("pbNotify").checked = r.notify !== false;
    tasks = (pb.tasks || []).slice();
    $("pbResult").textContent = "";
    refresh();
}

async function validate() {
    const result = await api("/api/playbooks/validate", { method: "POST", body: JSON.stringify({ yaml: toYaml(draft()) }) });
    if (!result) return;
    const box = $("pbResult");
    box.replaceChildren();
    box.className = "pb-result " + (result.valid ? "ok" : "bad");
    box.appendChild(el("p", result.valid ? "Valid." : "Not valid:"));
    (result.errors || []).forEach((e) => box.appendChild(el("p", e)));
    (result.warnings || []).forEach((w) => box.appendChild(el("p", `Warning: ${w}`)));
    box.appendChild(el("p", `Would handle: ${(result.routes || []).join(", ") || "no current rule"}`));
}

function download() {
    const doc = draft();
    const blob = new Blob([toYaml(doc)], { type: "text/yaml" });
    const a = el("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${(doc.name || "playbook").replace(/[^a-z0-9_-]/gi, "-")}.yml`;
    a.click();
    URL.revokeObjectURL(a.href);
}

async function init() {
    const data = await api("/api/playbooks");
    if (!data) return;
    playbooks = data.playbooks;
    const select = $("pbAction");
    select.appendChild(el("option", "(rule's mapped action)"));
    select.firstChild.value = "";
    data.allowed_actions.forEach((a) => { const o = el("option", a); o.value = a; select.appendChild(o); });
    const list = $("pbList");
    playbooks.forEach((pb) => {
        const item = el("li");
        const b = el("button", `${pb.name} (${pb.version})`, "pb-item");
        b.addEventListener("click", () => load(pb));
        item.appendChild(b);
        item.appendChild(el("small", pb.file));
        list.appendChild(item);
    });
    for (const id of ["pbName", "pbVersion", "pbDescription", "pbRules", "pbTechniques", "pbAction", "pbMinRisk", "pbApproval", "pbNotify"]) {
        $(id).addEventListener("input", refresh);
        $(id).addEventListener("change", refresh);
    }
    $("pbTaskAdd").addEventListener("click", () => {
        const v = $("pbTaskInput").value.trim();
        if (v) { tasks.push(v); $("pbTaskInput").value = ""; refresh(); }
    });
    $("pbNew").addEventListener("click", () => load({ name: "", version: "1.0.0", description: "", response: { notify: true, require_approval: true } }));
    $("pbValidate").addEventListener("click", validate);
    $("pbDownload").addEventListener("click", download);
    if (playbooks.length) load(playbooks[0]);
}

init();
