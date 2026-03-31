# Repository demo assets

- **`report-preview.png`** — Screenshot of the HTML security report (for README / docs).
- **`vulnhunter_scanme.nmap.org_*.html`** / **`.json`** — Sample output from a scan against the public demo host `scanme.nmap.org` (Nmap Project test machine).

## Regenerate the screenshot

After you have at least one `vulnhunter_*.html` in this folder:

```bash
pip install html2image
python scripts/capture_report_screenshot.py
```

## Regenerate the report (new scan)

```bash
vulnhunter scan scanme.nmap.org --lightweight -o docs/assets
```

Then run the screenshot command above. Scans can take a long time and require a configured LLM API key in `.env`.
