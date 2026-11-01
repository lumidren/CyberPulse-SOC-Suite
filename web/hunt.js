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

function init() {
    const select = $("pivotField");
    FIELDS.forEach((f) => { const o = CP.el("option", f); o.value = f; select.appendChild(o); });
    $("pivotForm").addEventListener("submit", (e) => {
        e.preventDefault();
        const value = $("pivotValue").value.trim();
        if (value) { trail.length = 0; pivot(select.value, value); }
    });
}

init();
