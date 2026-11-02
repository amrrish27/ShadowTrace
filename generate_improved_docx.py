# -*- coding: utf-8 -*-
"""
Professional Academic/Industry Project Report Generator for HackHalt Internship.
Produces a clean, publication-grade Word DOCX:
- Pure white background throughout (no black box / inverted blocks)
- Crisp dark typography: Heading 1 (18pt Bold, Deep Navy #1E3A8A), Heading 2 (14pt Bold, Navy #1E40AF), Body (11pt Justified, #111827 / Pure Black #000000)
- Prominent HackHalt Padlock Logo on the Cover Page
- Dynamic Word Page Numbers (PAGE field) centered in the footer
- Professional light-bordered tables with subtle light gray headers (#F1F5F9)
- Academic 1.15 line spacing, 1-inch margins, elegant callout blocks with left accent border
"""
import os
import pathlib
import re
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

DOCS_DIR = pathlib.Path(r"c:\Users\acer\Downloads\shadowtrace\ShadowTrace\docs")
DOCS_DIR.mkdir(parents=True, exist_ok=True)
HTML_PATH = DOCS_DIR / "ShadowTrace_Internship_Report.html"
LOGO_PATH = DOCS_DIR / "hackhalt_logo.png"
OUTPUT_DOCX = DOCS_DIR / "ShadowTrace_Internship_Report.docx"

doc = Document()

# Configure standard A4 layout: 1.0 inch margins all around
section = doc.sections[0]
section.page_width = Inches(8.27)
section.page_height = Inches(11.69)
section.top_margin = Inches(1.0)
section.bottom_margin = Inches(1.0)
section.left_margin = Inches(1.0)
section.right_margin = Inches(1.0)

# Unlink cover page header/footer
section.different_first_page_header_footer = True

# Helper: Add dynamic page number field to a run
def add_page_number_field(run):
    fldChar1 = OxmlElement('w:fldChar')
    fldChar1.set(qn('w:fldCharType'), 'begin')
    instrText = OxmlElement('w:instrText')
    instrText.set(qn('xml:space'), 'preserve')
    instrText.text = "PAGE"
    fldChar2 = OxmlElement('w:fldChar')
    fldChar2.set(qn('w:fldCharType'), 'separate')
    fldChar3 = OxmlElement('w:fldChar')
    fldChar3.set(qn('w:fldCharType'), 'end')
    
    r = run._r
    r.append(fldChar1)
    r.append(instrText)
    r.append(fldChar2)
    r.append(fldChar3)

# Configure Header for subsequent pages
header = section.header
hp = header.paragraphs[0]
hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
hrun = hp.add_run("ShadowTrace — HackHalt Cyber Security Project Report")
hrun.font.name = "Arial"
hrun.font.size = Pt(8.5)
hrun.font.color.rgb = RGBColor(100, 116, 139)

# Configure Footer with centered Page Number
footer = section.footer
fp = footer.paragraphs[0]
fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
frun_left = fp.add_run("Page ")
frun_left.font.name = "Arial"
frun_left.font.size = Pt(9)
frun_left.font.color.rgb = RGBColor(71, 85, 105)

frun_num = fp.add_run()
frun_num.font.name = "Arial"
frun_num.font.size = Pt(9)
frun_num.font.bold = True
frun_num.font.color.rgb = RGBColor(15, 23, 42)
add_page_number_field(frun_num)

frun_mid = fp.add_run("  |  Confidential — HackHalt Cybersecurity Research Labs — 2026")
frun_mid.font.name = "Arial"
frun_mid.font.size = Pt(8.5)
frun_mid.font.color.rgb = RGBColor(148, 163, 184)

# Normal Paragraph style: clean, crisp black typography
style = doc.styles['Normal']
style.font.name = 'Arial'
style.font.size = Pt(11)
style.font.color.rgb = RGBColor(17, 24, 39) # Crisp Dark Slate / Near Black

def set_cell_shading(cell, color_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), color_hex)
    tcPr.append(shd)

def set_cell_borders(cell, top="CCCCCC", bottom="CCCCCC", left="CCCCCC", right="CCCCCC", sz="4"):
    tcPr = cell._tc.get_or_add_tcPr()
    tcBorders = OxmlElement('w:tcBorders')
    for side, col in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        b = OxmlElement(f'w:{side}')
        if col:
            b.set(qn('w:val'), 'single')
            b.set(qn('w:sz'), sz)
            b.set(qn('w:space'), '0')
            b.set(qn('w:color'), col)
        else:
            b.set(qn('w:val'), 'none')
        tcBorders.append(b)
    tcPr.append(tcBorders)

def set_cell_margins(cell, top=100, bottom=100, left=140, right=140):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def clean_html(text):
    text = re.sub(r'<strong[^>]*>(.*?)</strong>', r'__B__\1__EB__', text, flags=re.DOTALL)
    text = re.sub(r'<em[^>]*>(.*?)</em>', r'__I__\1__EI__', text, flags=re.DOTALL)
    text = re.sub(r'<code[^>]*>(.*?)</code>', r'__C__\1__EC__', text, flags=re.DOTALL)
    text = re.sub(r'<span[^>]*>(.*?)</span>', r'\1', text, flags=re.DOTALL)
    text = re.sub(r'<[^>]+>', '', text)
    text = text.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&').replace('&quot;', '"')
    return text.strip()

def add_styled_text(p, text):
    parts = re.split(r'(__B__|__EB__|__I__|__EI__|__C__|__EC__)', text)
    bold = False
    italic = False
    code = False
    for part in parts:
        if part == '__B__':
            bold = True
        elif part == '__EB__':
            bold = False
        elif part == '__I__':
            italic = True
        elif part == '__EI__':
            italic = False
        elif part == '__C__':
            code = True
        elif part == '__EC__':
            code = False
        elif part:
            r = p.add_run(part)
            r.bold = bold
            r.italic = italic
            if code:
                r.font.name = 'Consolas'
                r.font.size = Pt(10)
                r.font.color.rgb = RGBColor(15, 23, 42)
            else:
                r.font.name = 'Arial'
                if not (bold or italic):
                    r.font.color.rgb = RGBColor(17, 24, 39) # Crisp readable black

# Read HTML Content
html_raw = HTML_PATH.read_text(encoding="utf-8")
body_match = re.search(r'<body>(.*?)</body>', html_raw, flags=re.DOTALL)
body_content = body_match.group(1) if body_match else html_raw
pages = re.split(r'<div class=["\']page-break["\']></div>', body_content)

print(f"Generating professional DOCX with {len(pages)} chapters/sections...")

# ==============================================================================
# PAGE 1: COVER PAGE
# ==============================================================================
p_logo = doc.add_paragraph()
p_logo.alignment = WD_ALIGN_PARAGRAPH.CENTER
p_logo.paragraph_format.space_before = Pt(20)
p_logo.paragraph_format.space_after = Pt(10)

if LOGO_PATH.exists():
    r = p_logo.add_run()
    r.add_picture(str(LOGO_PATH), width=Inches(2.5))

p_co = doc.add_paragraph()
p_co.alignment = WD_ALIGN_PARAGRAPH.CENTER
p_co.paragraph_format.space_after = Pt(2)
r = p_co.add_run("HACKHALT CYBER SECURITY")
r.bold = True
r.font.name = "Arial"
r.font.size = Pt(16)
r.font.color.rgb = RGBColor(2, 132, 199) # Crisp HackHalt Blue

p_cos = doc.add_paragraph()
p_cos.alignment = WD_ALIGN_PARAGRAPH.CENTER
p_cos.paragraph_format.space_after = Pt(30)
r = p_cos.add_run("Security Research & Vulnerability Engineering Labs")
r.font.name = "Arial"
r.font.size = Pt(10)
r.font.bold = True
r.font.color.rgb = RGBColor(71, 85, 105)

p_tag = doc.add_paragraph()
p_tag.alignment = WD_ALIGN_PARAGRAPH.CENTER
p_tag.paragraph_format.space_after = Pt(8)
r = p_tag.add_run("INTERNSHIP PROJECT REPORT & ENGINEERING DOCUMENTATION")
r.bold = True
r.font.name = "Arial"
r.font.size = Pt(11)
r.font.color.rgb = RGBColor(100, 116, 139)

p_ti = doc.add_paragraph()
p_ti.alignment = WD_ALIGN_PARAGRAPH.CENTER
p_ti.paragraph_format.space_after = Pt(10)
r = p_ti.add_run("SHADOWTRACE")
r.bold = True
r.font.name = "Arial"
r.font.size = Pt(36)
r.font.color.rgb = RGBColor(30, 58, 138) # BOLD, HIGH-CONTRAST DEEP ROYAL NAVY

p_sub = doc.add_paragraph()
p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
p_sub.paragraph_format.space_after = Pt(30)
r = p_sub.add_run(
    "Automated Discovery, Security Auditing, and Attack Surface Management Platform\n"
    "for Shadow, Zombie, and Orphaned API Endpoints\n"
    "Targeting OWASP API Security Top 10 (API9:2023)"
)
r.font.name = "Arial"
r.font.size = Pt(11.5)
r.font.color.rgb = RGBColor(30, 41, 59) # Crisp readable dark slate

# Professional Clean White/Gray Border Metadata Table (NO BLACK BACKGROUND!)
tbl = doc.add_table(rows=4, cols=2)
tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
meta_items = [
    ("Candidate / Author:", "Amrrish", "Host Organization:", "HackHalt Cyber Security"),
    ("Internship Track:", "Cyber Security Engineering", "Industry Standard:", "OWASP API Top 10 (2023)"),
    ("Codebase Repository:", "amrrish27/ShadowTrace", "Verification Status:", "76 Automated Suites (100% Pass)"),
    ("Live Production URL:", "shadowtrace-1ff5.onrender.com", "Submission Date:", "November 2026")
]
for r_i, (k1, v1, k2, v2) in enumerate(meta_items):
    row = tbl.rows[r_i]
    c1, c2 = row.cells
    for c, k, v in [(c1, k1, v1), (c2, k2, v2)]:
        set_cell_shading(c, "F8FAFC" if r_i % 2 == 1 else "FFFFFF")
        set_cell_borders(c, top="E2E8F0", bottom="E2E8F0", left="E2E8F0", right="E2E8F0", sz="4")
        set_cell_margins(c, top=80, bottom=80, left=120, right=120)
        p = c.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        rk = p.add_run(f"{k} ")
        rk.font.name = "Arial"
        rk.font.size = Pt(9.5)
        rk.font.color.rgb = RGBColor(71, 85, 105)
        rv = p.add_run(v)
        rv.bold = True
        rv.font.name = "Arial"
        rv.font.size = Pt(10)
        rv.font.color.rgb = RGBColor(15, 23, 42) # Solid, crisp black

p_foot = doc.add_paragraph()
p_foot.alignment = WD_ALIGN_PARAGRAPH.CENTER
p_foot.paragraph_format.space_before = Pt(36)
r = p_foot.add_run("Confidential © 2026 HackHalt Cyber Security. Developed during Cyber Security Internship.")
r.font.name = "Arial"
r.font.size = Pt(8.5)
r.font.color.rgb = RGBColor(100, 116, 139)
doc.add_page_break()

# ==============================================================================
# SUBSEQUENT PAGES: CHAPTERS & CONTENT
# ==============================================================================
for page_idx in range(1, len(pages)):
    page = pages[page_idx]
    elements = re.split(
        r'(<h1[^>]*>.*?</h1>|<h2[^>]*>.*?</h2>|<h3[^>]*>.*?</h3>|<p[^>]*>.*?</p>|<pre><code>.*?</code></pre>|<div class="diagram-box">.*?</div>|<div class="callout[^"]*">.*?</div>|<table[^>]*>.*?</table>|<ul[^>]*>.*?</ul>|<ol[^>]*>.*?</ol>)',
        page,
        flags=re.DOTALL
    )
    
    for el in elements:
        el = el.strip()
        if not el:
            continue
            
        # H1: Chapter Heading
        if el.startswith('<h1'):
            m = re.search(r'<h1[^>]*>(.*?)</h1>', el, flags=re.DOTALL)
            if m:
                text = clean_html(m.group(1))
                h = doc.add_heading(text, level=1)
                h.paragraph_format.space_before = Pt(18)
                h.paragraph_format.space_after = Pt(8)
                h.paragraph_format.keep_with_next = True
                h.alignment = WD_ALIGN_PARAGRAPH.LEFT
                for r in h.runs:
                    r.font.name = 'Arial'
                    r.font.size = Pt(17)
                    r.font.bold = True
                    r.font.color.rgb = RGBColor(30, 58, 138) # Dark Navy
                    
        # H2: Section Heading
        elif el.startswith('<h2'):
            m = re.search(r'<h2[^>]*>(.*?)</h2>', el, flags=re.DOTALL)
            if m:
                text = clean_html(m.group(1))
                h = doc.add_heading(text, level=2)
                h.paragraph_format.space_before = Pt(14)
                h.paragraph_format.space_after = Pt(6)
                h.paragraph_format.keep_with_next = True
                h.alignment = WD_ALIGN_PARAGRAPH.LEFT
                for r in h.runs:
                    r.font.name = 'Arial'
                    r.font.size = Pt(13)
                    r.font.bold = True
                    r.font.color.rgb = RGBColor(2, 132, 199) # Bright Blue Section Accent
                    
        # H3: Subsection Heading
        elif el.startswith('<h3'):
            m = re.search(r'<h3[^>]*>(.*?)</h3>', el, flags=re.DOTALL)
            if m:
                text = clean_html(m.group(1))
                h = doc.add_heading(text, level=3)
                h.paragraph_format.space_before = Pt(10)
                h.paragraph_format.space_after = Pt(4)
                h.paragraph_format.keep_with_next = True
                h.alignment = WD_ALIGN_PARAGRAPH.LEFT
                for r in h.runs:
                    r.font.name = 'Arial'
                    r.font.size = Pt(11)
                    r.font.bold = True
                    r.font.color.rgb = RGBColor(30, 41, 59)

        # DIAGRAM BOX / CODE BLOCK: CLEAN LIGHT SHADED BOX (NO BLACK BOX!)
        elif el.startswith('<div class="diagram-box">') or el.startswith('<pre'):
            raw_text = re.sub(r'<[^>]+>', '', el)
            raw_text = raw_text.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&').replace('&quot;', '"').strip()
            
            tbl = doc.add_table(rows=1, cols=1)
            tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
            cell = tbl.cell(0, 0)
            set_cell_shading(cell, "F8FAFC") # Crisp Light Gray/Slate Background
            set_cell_borders(cell, top="CBD5E1", bottom="CBD5E1", left="2563EB", right="CBD5E1", sz="6") # Blue left accent
            set_cell_margins(cell, top=100, bottom=100, left=140, right=140)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(raw_text)
            r.font.name = 'Consolas'
            r.font.size = Pt(8.5)
            r.font.bold = True
            r.font.color.rgb = RGBColor(15, 23, 42) # DARK CRISP TEXT FOR EASY READING!
            doc.add_paragraph().paragraph_format.space_after = Pt(4)

        # CALLOUT BOX: ELEGANT LIGHT BLUE CALLOUT
        elif el.startswith('<div class="callout'):
            raw_text = clean_html(el)
            tbl = doc.add_table(rows=1, cols=1)
            tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
            cell = tbl.cell(0, 0)
            set_cell_shading(cell, "EFF6FF") # Soft Blue Background
            set_cell_borders(cell, top="BFDBFE", bottom="BFDBFE", left="1D4ED8", right="BFDBFE", sz="8") # Strong Blue Border
            set_cell_margins(cell, top=110, bottom=110, left=150, right=150)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            add_styled_text(p, raw_text)
            doc.add_paragraph().paragraph_format.space_after = Pt(4)

        # TABLES: CLEAN, PROFESSIONAL BORDERED TABLE
        elif el.startswith('<table'):
            rows = re.findall(r'<tr[^>]*>(.*?)</tr>', el, flags=re.DOTALL)
            if rows:
                parsed_rows = []
                for row_html in rows:
                    cells = re.findall(r'<(?:td|th)[^>]*>(.*?)</(?:td|th)>', row_html, flags=re.DOTALL)
                    parsed_rows.append([clean_html(c) for c in cells])
                    
                if parsed_rows:
                    num_cols = max(len(r) for r in parsed_rows)
                    tbl = doc.add_table(rows=len(parsed_rows), cols=num_cols)
                    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
                    for r_idx, row_data in enumerate(parsed_rows):
                        for c_idx, cell_value in enumerate(row_data):
                            if c_idx < num_cols:
                                cell = tbl.rows[r_idx].cells[c_idx]
                                is_head = (r_idx == 0 and ('<th' in rows[0]))
                                bg = "F1F5F9" if is_head else ("F8FAFC" if r_idx % 2 == 1 else "FFFFFF")
                                set_cell_shading(cell, bg)
                                set_cell_borders(cell, top="CBD5E1", bottom="CBD5E1", left="CBD5E1", right="CBD5E1", sz="4")
                                set_cell_margins(cell, top=70, bottom=70, left=90, right=90)
                                p = cell.paragraphs[0]
                                p.paragraph_format.space_after = Pt(0)
                                add_styled_text(p, cell_value)
                                if is_head:
                                    for run in p.runs:
                                        run.bold = True
                                        run.font.size = Pt(9)
                                        run.font.color.rgb = RGBColor(15, 23, 42) # DARK BOLD HEADERS
                                else:
                                    for run in p.runs:
                                        run.font.size = Pt(9)
                    doc.add_paragraph().paragraph_format.space_after = Pt(4)

        # BULLET / NUMBERED LISTS: JUSTIFIED ALIGNMENT & CRISP DARK TEXT
        elif el.startswith('<ul') or el.startswith('<ol'):
            items = re.findall(r'<li[^>]*>(.*?)</li>', el, flags=re.DOTALL)
            for item in items:
                p = doc.add_paragraph(style='List Bullet' if el.startswith('<ul') else 'List Number')
                p.paragraph_format.space_after = Pt(3)
                p.paragraph_format.line_spacing = 1.15
                p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
                add_styled_text(p, clean_html(item))

        # STANDARD BODY PARAGRAPHS: JUSTIFIED ALIGNMENT & CRISP DARK TEXT (11pt)
        elif el.startswith('<p'):
            raw_text = clean_html(el)
            if raw_text:
                p = doc.add_paragraph()
                p.paragraph_format.space_after = Pt(6)
                p.paragraph_format.line_spacing = 1.15
                p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
                add_styled_text(p, raw_text)

    # Page break between sections/chapters
    if page_idx < len(pages) - 1:
        doc.add_page_break()

doc.save(str(OUTPUT_DOCX))
print(f"SUCCESS: Generated improved Word document at {OUTPUT_DOCX}")
