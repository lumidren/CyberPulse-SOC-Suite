// CyberPulse SOC Lab: login page. Exchanges the API key for an HttpOnly session cookie.
document.getElementById("loginForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = document.getElementById("apiKeyInput");
    const error = document.getElementById("loginError");
    error.innerText = "";
    try {
        const res = await fetch("/api/session", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({ api_key: input.value })
        });
        input.value = "";
        if (res.ok) {
            window.location.replace("/");
            return;
        }
        const data = await res.json().catch(() => ({}));
        error.innerText = data.error || `Sign-in failed (${res.status}).`;
    } catch (err) {
        error.innerText = "Server unreachable.";
    }
});
