# -*- coding: utf-8 -*-
"""
Master Build Script:
1. Assembles all chapter modules into ShadowTrace_Internship_Report.html
2. Compiles HTML to PDF via Microsoft Edge
3. Verifies page count and quality using pypdf
4. Copies result to Downloads folder
"""
import base64
import os
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

html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ShadowTrace — Comprehensive Project Documentation & Internship Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

  @page {{
    size: A4;
    margin: 18mm 16mm 18mm 16mm;
  }}

  * {{
    box-sizing: border-box;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
  }}

  body {{
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    font-size: 9.8pt;
    line-height: 1.55;
    color: #111827;
    background: #FFFFFF;
    margin: 0;
    padding: 0;
  }}

  .cover-page {{
    box-sizing: border-box;
    height: 254mm;
    max-height: 254mm;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    text-align: center;
    padding: 10mm 15mm;
    page-break-after: always;
    break-after: page;
    page-break-inside: avoid;
    break-inside: avoid;
    overflow: hidden;
  }}

  .cover-logo-container {{
    margin-top: 10mm;
    margin-bottom: 5mm;
  }}

  .cover-logo {{
    max-height: 130px;
    max-width: 240px;
    object-fit: contain;
  }}

  .cover-company {{
    font-size: 15pt;
    font-weight: 800;
    color: #0284C7;
    letter-spacing: 2.5px;
    text-transform: uppercase;
    margin-top: 8px;
  }}

  .cover-company-sub {{
    font-size: 9.5pt;
    color: #334155;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    font-weight: 500;
  }}

  .cover-title-box {{
    margin: 20px 0;
  }}

  .cover-doc-type {{
    display: inline-block;
    background: #EFF6FF;
    color: #1E3A8A;
    font-size: 9.5pt;
    font-weight: 700;
    padding: 5px 16px;
    border-radius: 999px;
    border: 1.5px solid #BFDBFE;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-bottom: 12px;
  }}

  .cover-main-title {{
    font-size: 36pt;
    font-weight: 800;
    color: #1E3A8A;
    letter-spacing: 2px;
    line-height: 1.15;
    margin-bottom: 10px;
  }}

  .cover-divider {{
    width: 80px;
    height: 4px;
    background: #2563EB;
    margin: 14px auto;
    border-radius: 2px;
  }}

  .cover-subtitle {{
    font-size: 12pt;
    color: #1E293B;
    font-weight: 500;
    line-height: 1.45;
    max-width: 620px;
    margin: 0 auto;
  }}

  .cover-meta-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin: 15px auto 5px auto;
    max-width: 620px;
    text-align: left;
    background: #FFFFFF;
    border: 1px solid #CBD5E1;
    border-radius: 8px;
    padding: 14px 18px;
    font-size: 9pt;
  }}

  .cover-meta-item strong {{
    display: block;
    color: #475569;
    font-size: 7.5pt;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 2px;
  }}

  .cover-meta-item span {{
    color: #0F172A;
    font-weight: 600;
  }}

  .cover-footer {{
    margin-top: 10px;
    font-size: 8pt;
    color: #64748B;
    border-top: 1px solid #E2E8F0;
    padding-top: 8px;
  }}

  .chapter-header {{
    page-break-before: always;
    break-before: page;
    page-break-inside: avoid;
    break-inside: avoid;
    page-break-after: avoid;
    break-after: avoid;
  }}

  .chapter-header-first {{
    page-break-before: avoid !important;
    break-before: avoid !important;
  }}

  h1.chapter-title {{
    font-size: 18pt;
    font-weight: 800;
    color: #1E3A8A;
    border-bottom: 2.5px solid #2563EB;
    padding-bottom: 6px;
    margin-top: 0;
    margin-bottom: 14px;
    page-break-before: avoid;
    break-before: avoid;
  }}

  .chapter-number {{
    font-size: 9.5pt;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: #2563EB;
    font-weight: 700;
    margin-bottom: 3px;
  }}

  h2 {{
    font-size: 12.5pt;
    color: #1E293B;
    border-left: 4px solid #3B82F6;
    padding-left: 8px;
    margin-top: 1.35em;
    margin-bottom: 0.4em;
    page-break-after: avoid;
    break-after: avoid;
  }}

  h3 {{
    font-size: 10.5pt;
    color: #334155;
    margin-top: 1.15em;
    margin-bottom: 0.35em;
    page-break-after: avoid;
    break-after: avoid;
  }}

  p {{
    margin-top: 0;
    margin-bottom: 0.85em;
    text-align: justify;
    text-justify: inter-word;
    orphans: 3;
    widows: 3;
  }}

  ul, ol {{
    margin-top: 0;
    margin-bottom: 0.9em;
    padding-left: 22px;
  }}

  li {{
    margin-bottom: 0.35em;
    text-align: justify;
  }}

  code {{
    font-family: 'JetBrains Mono', Consolas, Monaco, monospace;
    font-size: 8.5pt;
    background: #F1F5F9;
    color: #0F172A;
    padding: 2px 4px;
    border-radius: 4px;
    border: 1px solid #CBD5E1;
  }}

  pre {{
    font-family: 'JetBrains Mono', Consolas, Monaco, monospace;
    background: #F8FAFC;
    color: #0F172A;
    border: 1px solid #CBD5E1;
    border-left: 4px solid #2563EB;
    padding: 10px 12px;
    border-radius: 6px;
    font-size: 7.8pt;
    line-height: 1.42;
    margin: 0.9em 0;
    page-break-inside: avoid;
    break-inside: avoid;
    overflow-x: hidden;
    white-space: pre-wrap;
    word-break: break-all;
  }}

  table {{
    width: 100%;
    border-collapse: collapse;
    margin: 1em 0;
    font-size: 8.8pt;
    page-break-inside: auto;
    break-inside: auto;
  }}

  tr {{
    page-break-inside: avoid;
    break-inside: avoid;
  }}

  th, td {{
    padding: 7px 9px;
    border: 1px solid #CBD5E1;
    text-align: left;
    vertical-align: top;
  }}

  th {{
    background: #F1F5F9;
    color: #0F172A;
    font-weight: 700;
  }}

  tr:nth-child(even) td {{
    background: #F8FAFC;
  }}

  .callout {{
    padding: 10px 14px;
    border-radius: 6px;
    margin: 1em 0;
    border-left: 4px solid;
    font-size: 9.2pt;
    page-break-inside: avoid;
    break-inside: avoid;
  }}

  .callout-info {{
    background: #EFF6FF;
    border-color: #3B82F6;
    color: #1E40AF;
  }}

  .callout-warn {{
    background: #FFFBEB;
    border-color: #F59E0B;
    color: #92400E;
  }}

  .callout-security {{
    background: #FEF2F2;
    border-color: #EF4444;
    color: #991B1B;
  }}

  .badge {{
    display: inline-block;
    padding: 2px 6px;
    border-radius: 999px;
    font-size: 7.5pt;
    font-weight: 700;
    text-transform: uppercase;
  }}

  .badge-critical {{ background: #FEE2E2; color: #991B1B; border: 1px solid #F87171; }}
  .badge-high {{ background: #FFEDD5; color: #9A3412; border: 1px solid #FB923C; }}
  .badge-medium {{ background: #FEF3C7; color: #92400E; border: 1px solid #FCD34D; }}
  .badge-low {{ background: #E0F2FE; color: #075985; border: 1px solid #7DD3FC; }}
  .badge-info {{ background: #F1F5F9; color: #475569; border: 1px solid #CBD5E1; }}

  .diagram-box {{
    background: #F8FAFC;
    border: 1px solid #CBD5E1;
    border-left: 4px solid #2563EB;
    border-radius: 6px;
    padding: 10px 12px;
    margin: 1em 0;
    font-family: 'JetBrains Mono', monospace;
    font-size: 7.5pt;
    line-height: 1.35;
    color: #0F172A;
    white-space: pre;
    page-break-inside: avoid;
    break-inside: avoid;
    overflow-x: hidden;
  }}
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
print(f"Generated HTML report at {html_out} ({len(html_content)} bytes)")

pdf_out = DOCS_DIR / "ShadowTrace_Internship_Report.pdf"
edge_exe = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

print("Compiling PDF via Microsoft Edge...")
cmd = [
    edge_exe,
    "--headless=new",
    "--disable-gpu",
    "--run-all-compositor-stages-before-draw",
    "--no-pdf-header-footer",
    f"--print-to-pdf={pdf_out.resolve()}",
    html_out.resolve().as_uri(),
]
subprocess.run(cmd, check=True)

reader = pypdf.PdfReader(str(pdf_out))
total_pages = len(reader.pages)
print(f"\n==========================================")
print(f"PDF GENERATED SUCCESSFULLY!")
print(f"Total Pages: {total_pages}")
print(f"==========================================")

empty_pages = []
sparse_pages = []
for i, page in enumerate(reader.pages):
    txt = page.extract_text().strip()
    words = len(txt.split())
    if words == 0:
        empty_pages.append(i + 1)
    elif words < 35:
        sparse_pages.append((i + 1, words, txt[:50]))

print(f"Empty pages (0 words): {empty_pages}")
print(f"Sparse pages (< 35 words): {len(sparse_pages)}")
for p_num, w_cnt, snippet in sparse_pages:
    print(f"  - Page {p_num}: {w_cnt} words | {snippet!r}")

downloads_pdf = pathlib.Path(r"c:\Users\acer\Downloads\ShadowTrace_Internship_Report.pdf")
downloads_pdf.write_bytes(pdf_out.read_bytes())
print(f"\nCopied final PDF to {downloads_pdf} ({downloads_pdf.stat().st_size / 1024:.1f} KB)")
