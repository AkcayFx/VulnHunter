"""Render the latest HTML report in docs/assets to report-preview.png (for README)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"
OUT = ASSETS / "report-preview.png"


def main() -> None:
    try:
        from html2image import Html2Image
    except ImportError:
        print("Install: pip install html2image", file=sys.stderr)
        sys.exit(1)

    html_files = sorted(ASSETS.glob("vulnhunter_*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not html_files:
        print(f"No vulnhunter_*.html under {ASSETS}", file=sys.stderr)
        sys.exit(1)

    html = html_files[0]
    ASSETS.mkdir(parents=True, exist_ok=True)
    hti = Html2Image(output_path=str(ASSETS))
    hti.screenshot(html_file=str(html.resolve()), save_as=OUT.name, size=(1400, 2400))
    print(f"Wrote {OUT} from {html.name}")


if __name__ == "__main__":
    main()
