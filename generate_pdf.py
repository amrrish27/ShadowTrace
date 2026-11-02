import base64
import os
import pathlib
import subprocess
import sys

DOCS_DIR = pathlib.Path(r"c:\Users\acer\Downloads\shadowtrace\ShadowTrace\docs")
TEMPLATE_PATH = DOCS_DIR / "report_template.html"
LOGO_WEBP_PATH = r"C:\Users\acer\.gemini\antigravity\brain\ecdfc198-e8a7-4dc8-879b-21f8dcbf1a2d\.user_uploaded\media_1793626236593_4d4f9678.webp"

with open(LOGO_WEBP_PATH, "rb") as f:
    logo_webp_b64 = base64.b64encode(f.read()).decode("ascii")

template_text = TEMPLATE_PATH.read_text(encoding="utf-8")
html_text = template_text.replace("__LOGO_WEBP__", logo_webp_b64)

html_out = DOCS_DIR / "ShadowTrace_Internship_Report.html"
html_out.write_text(html_text, encoding="utf-8")
print(f"Written HTML report: {html_out} ({len(html_text)} bytes)")

pdf_out = DOCS_DIR / "ShadowTrace_Internship_Report.pdf"
edge_exe = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

print("Compiling PDF with Microsoft Edge...")
cmd = [
    edge_exe,
    "--headless=new",
    "--disable-gpu",
    "--run-all-compositor-stages-before-draw",
    "--no-pdf-header-footer",
    f"--print-to-pdf={pdf_out.resolve()}",
    html_out.resolve().as_uri(),
]

res = subprocess.run(cmd, capture_output=True, text=True)
if pdf_out.exists():
    size_kb = pdf_out.stat().st_size / 1024
    print(f"SUCCESS: Generated PDF at {pdf_out} ({size_kb:.1f} KB)")
else:
    print(f"Edge execution error: {res.returncode}\nstdout: {res.stdout}\nstderr: {res.stderr}")
