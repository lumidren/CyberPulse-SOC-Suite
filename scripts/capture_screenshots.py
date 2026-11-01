#!/usr/bin/env python3
"""
Console screenshots for the README, taken from a throwaway local lab server.

    pip install playwright                 # optional tool, not in requirements*.txt
    python scripts/capture_screenshots.py  # writes docs/img/*.png

Starts server.py on a free loopback port with a random one-off API key and
CYBERPULSE_LAB_MODE=true, runs a few lab simulations so the views have
synthetic incidents to show, captures each page, then stops the server.
Nothing leaves the machine except the browser's map-tile and icon-font
requests that the console makes on any load. Set CHROME_PATH to use an
installed Chrome or Edge instead of Playwright's bundled browser.
"""

import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "img")
SIMULATIONS = ["t1003", "t1558", "t1003_dcsync", "t1110", "t1562", "cloud_entra"]
DESKTOP = {"width": 1440, "height": 900}
PHONE = {"width": 390, "height": 844}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(url, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2):  # nosec B310 - http://127.0.0.1 server started above
                return
        except OSError:
            time.sleep(0.3)
    raise SystemExit(f"server did not answer at {url}")


def post(base, key, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-API-Key": key})
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 - http://127.0.0.1 server started above
        return json.load(resp)


def main():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise SystemExit("playwright is not installed: pip install playwright") from None

    port, key = free_port(), secrets.token_urlsafe(24)
    base = f"http://127.0.0.1:{port}"
    env = dict(os.environ, PORT=str(port), CYBERPULSE_API_KEY=key, CYBERPULSE_LAB_MODE="true",
               CYBERPULSE_ENV="development")
    server = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py")], cwd=ROOT, env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_for(base + "/healthz")
        for attack in SIMULATIONS:
            post(base, key, "/api/simulate", {"type": attack})
        os.makedirs(OUT, exist_ok=True)
        with sync_playwright() as pw:
            launch = {"executable_path": os.environ["CHROME_PATH"]} if os.environ.get("CHROME_PATH") else {}
            browser = pw.chromium.launch(**launch)
            context = browser.new_context(viewport=DESKTOP, color_scheme="dark")
            page = context.new_page()
            page.request.post(base + "/api/session", data={"api_key": key})

            def shot(name, url, setup=None, full_page=False):
                page.goto(base + url, wait_until="networkidle")
                if setup:
                    setup()
                page.wait_for_timeout(800)
                page.screenshot(path=os.path.join(OUT, name), full_page=full_page)
                print(f"wrote docs/img/{name}")

            shot("console-overview.png", "/index.html")
            shot("console-incident.png", "/index.html",
                 lambda: page.click("button.nav-btn:has-text('Incident DFIR')"))
            shot("triage.png", "/triage.html",
                 lambda: page.locator(".tw-case").first.click())
            shot("playbooks.png", "/playbooks.html", lambda: page.locator(".pb-item").first.click())
            shot("executive.png", "/executive.html")
            page.emulate_media(color_scheme="light")
            page.evaluate("localStorage.setItem('cp.theme', 'light')")
            shot("console-light.png", "/index.html")
            page.evaluate("localStorage.removeItem('cp.theme')")

            phone = browser.new_context(viewport=PHONE, device_scale_factor=2, color_scheme="dark",
                                        is_mobile=True, has_touch=True)
            mobile = phone.new_page()
            mobile.request.post(base + "/api/session", data={"api_key": key})
            mobile.goto(base + "/status.html", wait_until="networkidle")
            mobile.wait_for_timeout(800)
            mobile.screenshot(path=os.path.join(OUT, "status-mobile.png"))
            print("wrote docs/img/status-mobile.png")
            browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    main()
