// CyberPulse SOC Suite: dark/light theme (roadmap F58).
// Loaded in <head> so the theme is applied before first paint. Default follows the OS
// setting; an explicit choice is remembered per browser.
(() => {
    const KEY = "cp.theme";
    const saved = (() => { try { return localStorage.getItem(KEY); } catch (e) { return null; } })();
    const prefersLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
    document.documentElement.dataset.theme = saved || (prefersLight ? "light" : "dark");

    function label(btn) {
        const light = document.documentElement.dataset.theme === "light";
        btn.textContent = light ? "Dark mode" : "Light mode";
        btn.setAttribute("aria-pressed", String(light));
    }

    document.addEventListener("DOMContentLoaded", () => {
        const btn = document.getElementById("themeToggle");
        if (!btn) return;
        label(btn);
        btn.addEventListener("click", () => {
            const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
            document.documentElement.dataset.theme = next;
            try { localStorage.setItem(KEY, next); } catch (e) { /* storage blocked: theme lasts for this page */ }
            label(btn);
        });
    });
})();
