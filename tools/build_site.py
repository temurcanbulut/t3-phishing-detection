"""Create an honest static URL-only client. No backend is implied by this build."""

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "T3-Phishing-Detection"))
from app import app
from flask import render_template

destination = ROOT / "site"
assets = destination / "assets"
assets.mkdir(parents=True, exist_ok=True)
with app.test_request_context():
    html = render_template(
        "index.html", runtime="static", safe_browsing_enabled=False, asset_prefix="assets"
    )
(destination / "index.html").write_text(html, encoding="utf-8")
for name in ("styles.css", "workspace.css", "facts.css", "app.mjs", "url-local.mjs", "reports.mjs", "facts.mjs", "logo.png"):
    shutil.copyfile(ROOT / "T3-Phishing-Detection" / "static" / name, assets / name)
print(destination)
