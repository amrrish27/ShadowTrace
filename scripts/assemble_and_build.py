# -*- coding: utf-8 -*-
"""
Master Build Script:
1. Assembles chapter modules into a polished HTML report
2. Compiles to PDF via Microsoft Edge
3. Verifies page count with pypdf
4. Copies PDF to Downloads
"""
import base64
import pathlib
import subprocess
import sys
import pypdf

SCRIPTS_DIR = pathlib.Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPTS_DIR))

from chapters.cover_and_toc import get_cover_and_toc
from chapters.ch01_to_03 import get_ch01_to_03
from chapters.ch04_to_06 import get_ch04_to_06
from chapters.ch07_to_09 import get_ch07_to_09
from chapters.ch10_to_12 import get_ch10_to_12
from chapters.ch13_to_15 import get_ch13_to_15

DOCS_DIR = pathlib.Path(r"c:\Users\acer\Downloads\shadowtrace\ShadowTrace\docs")
LOGO_WEBP = pathlib.Path(r"C:\Users\acer\.gemini\antigravity\brain\ecdfc198-e8a7-4dc8-879b-21f8dcbf1a2d\.user_uploaded\media_1793626236593_4d4f9678.webp")

with open(LOGO_WEBP, "rb") as f:
    logo_b64 = base64.b64encode(f.read()).decode("ascii")

# ──────────────────────────────────────────────────────────────────────────────
# MASTER CSS — polished professional report styling
# ──────────────────────────────────────────────────────────────────────────────
STYLES = """
  /* ── Google Fonts ───────────────────────────────────────────── */
  @import url('https://fonts.googleapis.com/css2?family=Inter:ital,wght@0,300;0,400;0,500;0,600;0,700;0,800;1,400&family=JetBrains+Mono:wght@400;500&display=swap');

  /* ── Page geometry & running footer ─────────────────────────── */
  @page {
    size: A4;
    margin: 20mm 18mm 22mm 18mm;
    @bottom-left {
      content: "ShadowTrace — Internship Project Report | HackHalt Cyber Security";
      font-family: 'Inter', sans-serif;
      font-size: 7pt;
      color: #94A3B8;
    }
    @bottom-right {
      content: "Page " counter(page) " of " counter(pages);
      font-family: 'Inter', sans-serif;
      font-size: 7.5pt;
      color: #64748B;
      font-weight: 600;
    }
  }

  @page :first {
    @bottom-left  { content: none; }
    @bottom-right { content: none; }
  }

  /* ── Reset ───────────────────────────────────────────────────── */
  *, *::before, *::after {
    box-sizing: border-box;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
  }

  /* ── Base typography ─────────────────────────────────────────── */
  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    font-size: 10pt;
    line-height: 1.6;
    color: #1E293B;
    background: #FFFFFF;
    margin: 0;
    padding: 0;
    counter-reset: page 1;
  }

  /* ── COVER PAGE ──────────────────────────────────────────────── */
  .cover-page {
    min-height: 247mm;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: space-between;
    text-align: center;
    padding: 14mm 16mm 10mm;
    page-break-after: always;
    break-after: page;
    page-break-inside: avoid;
    break-inside: avoid;
    position: relative;
    background: #FFFFFF;
  }

  /* top blue accent strip */
  .cover-page::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 6px;
    background: linear-gradient(90deg, #1D4ED8 0%, #0EA5E9 100%);
  }

  .cover-logo-container { margin-bottom: 4mm; }

  .cover-logo {
    width: 110px;
    height: 110px;
    object-fit: contain;
    display: block;
    margin: 0 auto;
  }

  .cover-company {
    font-size: 13pt;
    font-weight: 800;
    color: #1D4ED8;
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-top: 6px;
  }

  .cover-company-sub {
    font-size: 8.5pt;
    color: #475569;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    font-weight: 500;
    margin-top: 2px;
  }

  .cover-title-box { margin: 10mm 0 6mm; }

  .cover-doc-type {
    display: inline-block;
    background: #EFF6FF;
    color: #1D4ED8;
    font-size: 8pt;
    font-weight: 700;
    padding: 4px 18px;
    border-radius: 999px;
    border: 1.5px solid #BFDBFE;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 10px;
  }

  .cover-main-title {
    font-size: 40pt;
    font-weight: 800;
    color: #0F172A;
    letter-spacing: 6px;
    line-height: 1.1;
    margin-bottom: 0;
  }

  .cover-title-rule {
    width: 60px;
    height: 4px;
    background: #1D4ED8;
    margin: 10px auto 12px;
    border-radius: 2px;
  }

  .cover-subtitle {
    font-size: 11pt;
    color: #334155;
    font-weight: 400;
    line-height: 1.5;
    max-width: 580px;
    margin: 0 auto;
  }

  /* meta info card on cover */
  .cover-meta-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0;
    width: 100%;
    max-width: 600px;
    border: 1px solid #CBD5E1;
    border-radius: 10px;
    overflow: hidden;
    font-size: 8.5pt;
    text-align: left;
    margin: 8mm auto 0;
  }

  .cover-meta-item {
    padding: 8px 14px;
    border-bottom: 1px solid #E2E8F0;
    border-right: 1px solid #E2E8F0;
  }
  .cover-meta-item:nth-child(even) { border-right: none; }
  .cover-meta-item:nth-last-child(-n+2) { border-bottom: none; }

  .cover-meta-item strong {
    display: block;
    color: #64748B;
    font-size: 6.5pt;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 2px;
    font-weight: 600;
  }

  .cover-meta-item span {
    color: #0F172A;
    font-weight: 600;
    font-size: 8.5pt;
  }

  .cover-footer {
    font-size: 7.5pt;
    color: #94A3B8;
    border-top: 1px solid #E2E8F0;
    padding-top: 8px;
    width: 100%;
    margin-top: 8mm;
  }

  /* ── CHAPTER HEADERS ─────────────────────────────────────────── */
  .chapter-header {
    page-break-before: always;
    break-before: page;
    page-break-inside: avoid;
    break-inside: avoid;
    page-break-after: avoid;
    break-after: avoid;
    margin-bottom: 16px;
  }

  .chapter-header-first {
    page-break-before: avoid !important;
    break-before: avoid !important;
  }

  .chapter-kicker {
    font-size: 8pt;
    font-weight: 700;
    letter-spacing: 2.5px;
    text-transform: uppercase;
    color: #FFFFFF;
    background: #1D4ED8;
    display: inline-block;
    padding: 3px 12px;
    border-radius: 3px 3px 0 0;
    margin-bottom: 0;
  }

  h1.chapter-title {
    font-size: 17pt;
    font-weight: 800;
    color: #0F172A;
    margin: 0 0 4px;
    padding: 10px 14px 10px;
    border-left: 5px solid #1D4ED8;
    background: #F8FAFC;
    border-radius: 0 6px 6px 0;
    page-break-before: avoid;
    break-before: avoid;
    line-height: 1.2;
  }

  /* ── Section headings ────────────────────────────────────────── */
  .chapter-number { display: none; } /* handled by .chapter-kicker */

  h2 {
    font-size: 11.5pt;
    font-weight: 700;
    color: #1E3A8A;
    border-bottom: 1.5px solid #BFDBFE;
    padding-bottom: 4px;
    margin-top: 1.6em;
    margin-bottom: 0.5em;
    page-break-after: avoid;
    break-after: avoid;
  }

  h3 {
    font-size: 10.5pt;
    font-weight: 600;
    color: #1E293B;
    margin-top: 1.2em;
    margin-bottom: 0.3em;
    page-break-after: avoid;
    break-after: avoid;
  }

  h3::before {
    content: '▸ ';
    color: #3B82F6;
    font-size: 9pt;
  }

  /* ── Body text ───────────────────────────────────────────────── */
  p {
    margin: 0 0 0.85em;
    text-align: justify;
    text-justify: inter-word;
    orphans: 3;
    widows: 3;
  }

  ul, ol {
    margin: 0 0 0.9em;
    padding-left: 20px;
  }

  li {
    margin-bottom: 0.35em;
    text-align: justify;
  }

  /* ── Code ────────────────────────────────────────────────────── */
  code {
    font-family: 'JetBrains Mono', Consolas, monospace;
    font-size: 8pt;
    background: #F1F5F9;
    color: #0F172A;
    padding: 1px 5px;
    border-radius: 3px;
    border: 1px solid #CBD5E1;
  }

  pre {
    font-family: 'JetBrains Mono', Consolas, monospace;
    background: #F8FAFC;
    color: #0F172A;
    border: 1px solid #CBD5E1;
    border-left: 4px solid #3B82F6;
    padding: 10px 14px;
    border-radius: 0 6px 6px 0;
    font-size: 7.5pt;
    line-height: 1.5;
    margin: 0.9em 0;
    page-break-inside: avoid;
    break-inside: avoid;
    white-space: pre-wrap;
    word-break: break-all;
    overflow-x: hidden;
  }

  pre code {
    background: none;
    border: none;
    padding: 0;
    font-size: inherit;
    color: inherit;
  }

  /* ── Tables ──────────────────────────────────────────────────── */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 1em 0;
    font-size: 8.8pt;
    page-break-inside: auto;
  }

  thead { display: table-header-group; }

  th {
    background: #1E3A8A;
    color: #FFFFFF;
    font-weight: 600;
    padding: 8px 10px;
    border: 1px solid #1E3A8A;
    text-align: left;
    vertical-align: top;
    font-size: 8pt;
    letter-spacing: 0.3px;
  }

  td {
    padding: 7px 10px;
    border: 1px solid #CBD5E1;
    text-align: left;
    vertical-align: top;
  }

  tr { page-break-inside: avoid; }

  tr:nth-child(odd) td  { background: #FFFFFF; }
  tr:nth-child(even) td { background: #F8FAFC; }

  /* ── Callouts ────────────────────────────────────────────────── */
  .callout {
    padding: 10px 14px 10px 16px;
    border-radius: 4px;
    margin: 1em 0;
    border-left: 4px solid;
    font-size: 9pt;
    page-break-inside: avoid;
    break-inside: avoid;
  }

  .callout-info     { background: #EFF6FF; border-color: #3B82F6; color: #1E3A8A; }
  .callout-warn     { background: #FFFBEB; border-color: #F59E0B; color: #78350F; }
  .callout-security { background: #FEF2F2; border-color: #EF4444; color: #7F1D1D; }

  /* ── Severity badges ─────────────────────────────────────────── */
  .badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 999px;
    font-size: 7pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .badge-critical { background: #FEE2E2; color: #991B1B; border: 1px solid #FECACA; }
  .badge-high     { background: #FFEDD5; color: #9A3412; border: 1px solid #FED7AA; }
  .badge-medium   { background: #FEF3C7; color: #92400E; border: 1px solid #FDE68A; }
  .badge-low      { background: #DBEAFE; color: #1E40AF; border: 1px solid #BFDBFE; }
  .badge-info     { background: #F1F5F9; color: #475569; border: 1px solid #CBD5E1; }

  /* ── ASCII diagram boxes ─────────────────────────────────────── */
  .diagram-box {
    background: #F8FAFC;
    border: 1px solid #CBD5E1;
    border-left: 4px solid #3B82F6;
    border-radius: 0 6px 6px 0;
    padding: 10px 14px;
    margin: 1em 0;
    font-family: 'JetBrains Mono', monospace;
    font-size: 7pt;
    line-height: 1.38;
    color: #0F172A;
    white-space: pre;
    page-break-inside: avoid;
    break-inside: avoid;
    overflow-x: hidden;
  }

  /* ── TOC table overrides ─────────────────────────────────────── */
  table.toc-table th { display: none; }
  table.toc-table { border: none; margin: 0; }
  table.toc-table td {
    border: none;
    border-bottom: 1px dotted #CBD5E1;
    padding: 4px 4px;
    background: transparent !important;
  }
  table.toc-table tr:last-child td { border-bottom: none; }
"""

# Build final HTML
html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ShadowTrace — Engineering Documentation & Internship Report</title>
<style>
{STYLES}
</style>
</head>
<body>
{get_cover_and_toc(logo_b64)}
{get_ch01_to_03()}
{get_ch04_to_06()}
{get_ch07_to_09()}
{get_ch10_to_12()}
{get_ch13_to_15()}
</body>
</html>
"""

html_out = DOCS_DIR / "ShadowTrace_Internship_Report.html"
html_out.write_text(html_content, encoding="utf-8")
print(f"HTML written: {html_out}  ({len(html_content):,} bytes)")

# ── Compile PDF ──────────────────────────────────────────────────────────────
pdf_out = DOCS_DIR / "ShadowTrace_Internship_Report.pdf"
edge_exe = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

print("Compiling PDF via Microsoft Edge headless...")
subprocess.run([
    edge_exe,
    "--headless=new",
    "--disable-gpu",
    "--run-all-compositor-stages-before-draw",
    "--no-pdf-header-footer",
    f"--print-to-pdf={pdf_out.resolve()}",
    html_out.resolve().as_uri(),
], check=True)

# ── Verify ───────────────────────────────────────────────────────────────────
reader  = pypdf.PdfReader(str(pdf_out))
total   = len(reader.pages)
empty   = [i+1 for i,p in enumerate(reader.pages) if len(p.extract_text().strip().split()) == 0]
sparse  = [(i+1, len(p.extract_text().strip().split())) for i,p in enumerate(reader.pages)
           if 0 < len(p.extract_text().strip().split()) < 30]

print(f"\n{'='*50}")
print(f"SUCCESS  |  Total pages : {total}")
print(f"Empty    : {empty}")
print(f"Sparse   : {sparse}")
print(f"{'='*50}")

# ── Copy to Downloads ────────────────────────────────────────────────────────
downloads_pdf = pathlib.Path(r"c:\Users\acer\Downloads\ShadowTrace_Internship_Report.pdf")
downloads_pdf.write_bytes(pdf_out.read_bytes())
print(f"Copied to {downloads_pdf}  ({downloads_pdf.stat().st_size / 1024:.0f} KB)")
