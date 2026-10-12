"""Screenshots of the real back office, taken in CI from the shop just installed.

The two modules in the pictures are stub folders (a config.xml each) named after modules
that have published advisories. Everything else is the module running in PrestaShop.
"""
import glob
import os
import re

from playwright.sync_api import sync_playwright

base = os.environ["BASE_URL"]
shop = os.environ["PS"]
out = os.environ["ARTIFACTS"]
import urllib.request

try:
    urllib.request.urlopen(f"{base}/admin/index.php?controller=AdminLogin", timeout=60)
except Exception:
    pass
admin = os.path.basename(next(d for d in sorted(glob.glob(os.path.join(shop, "admin*"))) if os.path.isdir(os.path.join(d, "themes"))))
os.makedirs(out, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1400, "height": 900}, device_scale_factor=2)
    page.goto(f"{base}/{admin}/index.php?controller=AdminLogin")
    page.fill("#email", os.environ["ADMIN_EMAIL"])
    page.fill("#passwd", os.environ["ADMIN_PASSWORD"])
    page.click("#submit_login")
    page.wait_for_load_state("networkidle")

    href = page.locator("a[href*='ruvelo_securityalerts/alerts']").first.get_attribute("href")
    page.screenshot(path=f"{out}/dashboard.png", full_page=False)
    page.goto(base + href if href.startswith("/") else href)
    page.wait_for_load_state("networkidle")
    page.screenshot(path=f"{out}/alerts.png", full_page=True)

    page.goto(f"{base}/{admin}/index.php?controller=AdminModules&configure=ruvelo_securityalerts")
    page.wait_for_load_state("networkidle")
    if "Invalid token" in page.content():
        page.click("a.btn-default, a[href*='token']")
        page.wait_for_load_state("networkidle")
    page.screenshot(path=f"{out}/settings.png", full_page=True)
    browser.close()
print("screenshots:", sorted(os.listdir(out)))
