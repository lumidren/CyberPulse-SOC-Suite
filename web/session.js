// ==============================================================================
// CyberPulse SOC Suite: shared session helper for the secondary console pages.
// Uses the HttpOnly session cookie; adds the CSRF token to state-changing calls.
// ==============================================================================

const CP = (() => {
    let csrf = null;

    async function token() {
        if (csrf) return csrf;
        const s = await (await fetch("/api/session", { credentials: "same-origin" })).json();
        if (!s.authenticated) { window.location.replace("/login.html"); return null; }
        csrf = s.csrf_token;
        return csrf;
    }

    async function api(url, options = {}) {
        options = Object.assign({ credentials: "same-origin" }, options);
        if ((options.method || "GET").toUpperCase() !== "GET") {
            options.headers = Object.assign({ "Content-Type": "application/json", "X-CSRF-Token": await token() },
                                            options.headers || {});
        }
        const res = await fetch(url, options);
        if (res.status === 401) { window.location.replace("/login.html"); return null; }
        const data = await res.json().catch(() => ({}));
        return res.ok ? data : Object.assign({ error: data.error || data.message || `HTTP ${res.status}` }, data);
    }

    // Build DOM nodes with textContent only: API data is never parsed as HTML
    function el(tag, text, className) {
        const node = document.createElement(tag);
        if (text !== undefined && text !== null) node.textContent = String(text);
        if (className) node.className = className;
        return node;
    }

    return { api, el };
})();
