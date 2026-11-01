"""Generate the offline site from the single server asset/template source."""

import argparse
import shutil
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

ROOT = Path(__file__).resolve().parents[1]
ASSETS = (
    "styles.css",
    "workspace.css",
    "facts.css",
    "app.mjs",
    "url-local.mjs",
    "reports.mjs",
    "facts.mjs",
    "logo.png",
)


def build_site(destination):
    destination = Path(destination)
    assets = destination / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    environment = Environment(
        loader=FileSystemLoader(ROOT / "T3-Phishing-Detection/templates"),
        autoescape=select_autoescape(),
        undefined=StrictUndefined,
    )
    html = environment.get_template("index.html").render(
        runtime="static", safe_browsing_enabled=False, asset_prefix="assets"
    )
    (destination / "index.html").write_text(html, encoding="utf-8")
    for name in ASSETS:
        shutil.copyfile(ROOT / "T3-Phishing-Detection/static" / name, assets / name)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "site")
    print(build_site(parser.parse_args().output))
