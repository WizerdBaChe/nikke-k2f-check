"""Regenerate docs/assets/hero.png: the first screen of the built player guide (docs/index.html).

Usage: python docs/assets/build_hero.py
Needs: pip install playwright && playwright install chromium
"""
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
PAGE = HERE.parent / "index.html"
OUT = HERE / "hero.png"
VIEWPORT = {"width": 1440, "height": 860}


def main() -> None:
    if not PAGE.is_file():
        raise SystemExit(f"build the page first: {PAGE} not found")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport=VIEWPORT, device_scale_factor=1, color_scheme="light")
        page.goto(PAGE.as_uri())
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(OUT), full_page=False)
        browser.close()
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
