// CyberPulse SOC Suite: hunting workbench (roadmap F66+). Text-only rendering.
const $ = (id) => document.getElementById(id);
const FIELDS = ["host", "source_ip", "user", "process", "parent_process", "command_line", "hash", "technique",
                "event_id", "source", "target_user", "destination"];
const trail = [];

function cell(text) { return CP.el("td", text === null || text === undefined ? "" : text); }

async function pivot(field, value, push = true) {
    const data = await CP.api(`/api/hunt/pivot?field=${encodeURIComponent(field)}&value=${encodeURIComponent(value)}`);
    if (!data) return;
    if (data.error) { $("pivotSummary").textContent = data.error; return; }
    if (push) trail.push([field, value]);
    renderCrumbs();
    $("pivotField").value = field;
    $("pivotValue").value = value;
    $("pivotSummary").textContent = `${data.events} event(s), ${data.alerted} alerted` +
        (data.first_seen ? `, ${data.first_seen.slice(0, 19)} to ${data.last_seen.slice(0, 19)} UTC` : "");
    const related = $("related");
    related.replaceChildren();
    for (const [other, items] of Object.entries(data.related)) {
        const box = CP.el("div", null, "tw-top-widget");
        box.appendChild(CP.el("h4", other.replace("_", " ")));
        for (const item of items) {
            const b = CP.el("button", `${item.value} (${item.count})`, "hw-pivot");
            b.title = `Pivot on ${other} = ${item.value}`;
            b.addEventListener("click", () => pivot(other, item.value));
            box.appendChild(b);
        }
        related.appendChild(box);
    }
    const rows = $("pivotRows");
    rows.replaceChildren();
    for (const e of data.sample) {
        const tr = CP.el("tr");
        [e.seen_at.slice(11, 19), e.rule || "-", e.host, e.user, e.source_ip, e.event_id,
         e.command_line || e.process].forEach((v) => tr.appendChild(cell(v)));
        rows.appendChild(tr);
    }
}

function renderCrumbs() {
    const nav = $("breadcrumbs");
    nav.replaceChildren();
    trail.forEach(([field, value], i) => {
        const b = CP.el("button", `${field}=${value}`, "hw-crumb");
        b.addEventListener("click", () => { trail.splice(i + 1); pivot(field, value, false); });
        nav.appendChild(b);
    });
}

async function runStack() {
    const field = $("stackField").value, whereField = $("stackWhereField").value;
    let url = `/api/hunt/stack?field=${encodeURIComponent(field)}`;
    if (whereField) url += `&where_field=${encodeURIComponent(whereField)}&where_value=${encodeURIComponent($("stackWhereValue").value.trim())}`;
    const data = await CP.api(url);
    if (!data) return;
    if (data.error) { $("stackSummary").textContent = data.error; return; }
    $("stackSummary").textContent = `${data.with_value} value(s) in ${data.events} event(s), ${data.distinct} distinct; ` +
        `${data.tail} in the long tail (seen ${data.tail_limit} time(s) or fewer).`;
    const rows = $("stackRows");
    rows.replaceChildren();
    for (const r of data.rows) {
        const tr = CP.el("tr", null, r.tail ? "hw-tail" : "");
        const valueCell = CP.el("td");
        const b = CP.el("button", r.value, "hw-pivot");
        b.addEventListener("click", () => { trail.length = 0; pivot(field, r.value); window.scrollTo(0, 0); });
        valueCell.appendChild(b);
        tr.appendChild(valueCell);
        [r.count, `${(r.share * 100).toFixed(1)}%`, r.tail ? "yes" : "", r.alerted || ""].forEach((v) => tr.appendChild(cell(v)));
        rows.appendChild(tr);
    }
}

async function loadTemplates() {
    const data = await CP.api("/api/hunt/templates");
    const box = $("templates");
    box.replaceChildren();
    if (!data) return;
    for (const t of data.templates) {
        const card = CP.el("div", null, "hw-template");
        card.appendChild(CP.el("strong", t.name));
        card.appendChild(CP.el("span", t.hypothesis, "tw-muted"));
        card.appendChild(CP.el("span", `ATT&CK ${t.attack.join(", ")} · needs ${t.data_sources.join(", ")}`, "tw-muted"));
        const run = CP.el("button", "Run hunt", "btn-secondary");
        run.addEventListener("click", () => runTemplate(t.id));
        card.appendChild(run);
        box.appendChild(card);
    }
}

async function runTemplate(id) {
    const data = await CP.api(`/api/hunt/templates/${encodeURIComponent(id)}/run`);
    const box = $("templateResult");
    box.replaceChildren();
    if (!data || data.error) return;
    box.appendChild(CP.el("h4", data.template.name));
    const ol = CP.el("ol", null, "hw-steps");
    for (const s of data.steps) {
        const li = CP.el("li");
        const label = s.step.type === "search" ? `search "${s.step.query}"`
            : s.step.type === "stack" ? `stack ${s.step.field}` + (s.step.where_field ? ` where ${s.step.where_field}=${s.step.where_value}` : "")
            : `pivot ${s.step.field}=${s.step.value}`;
        li.appendChild(CP.el("strong", `${label}: ${s.finding}`));
        if (s.step.note) li.appendChild(CP.el("span", s.step.note, "tw-muted"));
        if (s.step.type === "stack") {
            (s.result.rows || []).filter((r) => r.tail).slice(0, 10).forEach((r) => {
                const b = CP.el("button", `${r.value} (${r.count})`, "hw-pivot");
                b.addEventListener("click", () => { trail.length = 0; pivot(s.step.field, r.value); });
                li.appendChild(b);
            });
        }
        ol.appendChild(li);
    }
    box.appendChild(ol);
    box.appendChild(CP.el("p", `Usually benign: ${data.template.benign.join("; ")}`, "tw-muted"));
    box.appendChild(CP.el("p", `Next: ${data.template.next_steps.join("; ")}`, "tw-muted"));
}

async function findBeacons() {
    const data = await CP.api("/api/hunt/beacons");
    const rows = $("beaconRows");
    rows.replaceChildren();
    if (!data) return;
    if (!data.beacons.length) { const tr = CP.el("tr"); tr.appendChild(CP.el("td", "No regular beacons in stored conn logs.")); rows.appendChild(tr); }
    for (const b of data.beacons) {
        const tr = CP.el("tr");
        [b.source_ip, b.destination, b.port, b.connections, `${b.mean_interval_sec}s`, b.jitter_cv].forEach((v) => tr.appendChild(cell(v)));
        rows.appendChild(tr);
    }
}

function init() {
    const select = $("pivotField");
    FIELDS.forEach((f) => { const o = CP.el("option", f); o.value = f; select.appendChild(o); });
    for (const id of ["stackField", "stackWhereField"]) {
        FIELDS.forEach((f) => { const o = CP.el("option", f); o.value = f; $(id).appendChild(o); });
    }
    $("stackField").value = "process";
    loadTemplates();
    $("findBeacons").addEventListener("click", findBeacons);
    $("stackForm").addEventListener("submit", (e) => { e.preventDefault(); runStack(); });
    $("pivotForm").addEventListener("submit", (e) => {
        e.preventDefault();
        const value = $("pivotValue").value.trim();
        if (value) { trail.length = 0; pivot(select.value, value); }
    });
}

init();
