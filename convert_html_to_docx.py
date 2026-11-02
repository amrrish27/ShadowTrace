# -*- coding: utf-8 -*-
"""Comprehensive 30+ Page Word DOCX Generator matching HTML report exactly."""
import re
import pathlib
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

DOCS_DIR = pathlib.Path(r"c:\Users\acer\Downloads\shadowtrace\ShadowTrace\docs")
HTML_PATH = DOCS_DIR / "ShadowTrace_Internship_Report.html"
LOGO_PATH = DOCS_DIR / "hackhalt_logo.png"
OUTPUT_DOCX = DOCS_DIR / "ShadowTrace_Internship_Report.docx"

doc = Document()

# Set A4 margins
for sec in doc.sections:
    sec.page_width = Inches(8.27)
    sec.page_height = Inches(11.69)
    sec.top_margin = Inches(0.9)
    sec.bottom_margin = Inches(0.9)
    sec.left_margin = Inches(0.9)
    sec.right_margin = Inches(0.9)
    
    # Running header & footer
    h = sec.header.paragraphs[0]
    h.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    hr = h.add_run("ShadowTrace — HackHalt Cybersecurity Project Report")
    hr.font.name = "Arial"
    hr.font.size = Pt(8)
    hr.font.color.rgb = RGBColor(148, 163, 184)
    
    f = sec.footer.paragraphs[0]
    f.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fr = f.add_run("Confidential — HackHalt Cybersecurity Research Labs — 2026")
    fr.font.name = "Arial"
    fr.font.size = Pt(8)
    fr.font.color.rgb = RGBColor(148, 163, 184)

style = doc.styles['Normal']
style.font.name = 'Arial'
style.font.size = Pt(10)
style.font.color.rgb = RGBColor(30, 41, 59)

def set_cell_shading(cell, color_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), color_hex)
    tcPr.append(shd)

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
                r.font.size = Pt(9)
                r.font.color.rgb = RGBColor(15, 23, 42)
            else:
                r.font.name = 'Arial'

html_raw = HTML_PATH.read_text(encoding="utf-8")
body_match = re.search(r'<body>(.*?)</body>', html_raw, flags=re.DOTALL)
body_content = body_match.group(1) if body_match else html_raw

# Split by page-break
pages = re.split(r'<div class=["\']page-break["\']></div>', body_content)
print(f"Total logical pages from HTML: {len(pages)}")

for page_idx, page in enumerate(pages):
    # PAGE 1: COVER
    if page_idx == 0:
        p_logo = doc.add_paragraph()
        p_logo.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_logo.paragraph_format.space_before = Pt(30)
        p_logo.paragraph_format.space_after = Pt(12)
        if LOGO_PATH.exists():
            r = p_logo.add_run()
            r.add_picture(str(LOGO_PATH), width=Inches(2.4))
            
        p_co = doc.add_paragraph()
        p_co.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_co.paragraph_format.space_after = Pt(2)
        r = p_co.add_run("HACKHALT CYBER SECURITY")
        r.bold = True
        r.font.size = Pt(16)
        r.font.color.rgb = RGBColor(2, 132, 199)
        
        p_cos = doc.add_paragraph()
        p_cos.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_cos.paragraph_format.space_after = Pt(40)
        r = p_cos.add_run("Security Research & Vulnerability Engineering Labs")
        r.font.size = Pt(10)
        r.font.color.rgb = RGBColor(100, 116, 139)
        
        p_tag = doc.add_paragraph()
        p_tag.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_tag.paragraph_format.space_after = Pt(6)
        r = p_tag.add_run("INTERNSHIP PROJECT REPORT & ENGINEERING DOCUMENTATION")
        r.bold = True
        r.font.size = Pt(10)
        r.font.color.rgb = RGBColor(100, 116, 139)
        
        p_ti = doc.add_paragraph()
        p_ti.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_ti.paragraph_format.space_after = Pt(10)
        r = p_ti.add_run("SHADOWTRACE")
        r.bold = True
        r.font.size = Pt(32)
        r.font.color.rgb = RGBColor(15, 23, 42)
        
        p_sub = doc.add_paragraph()
        p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_sub.paragraph_format.space_after = Pt(36)
        r = p_sub.add_run(
            "Automated Discovery, Security Auditing, and Attack Surface Management Platform\n"
            "for Shadow, Zombie, and Orphaned API Endpoints\n"
            "Targeting OWASP API Security Top 10 (API9:2023)"
        )
        r.font.size = Pt(11)
        r.font.color.rgb = RGBColor(51, 65, 85)
        
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
                set_cell_shading(c, "F8FAFC")
                set_cell_margins(c, top=80, bottom=80, left=120, right=120)
                p = c.paragraphs[0]
                p.paragraph_format.space_after = Pt(0)
                rk = p.add_run(f"{k} ")
                rk.font.size = Pt(9)
                rk.font.color.rgb = RGBColor(100, 116, 139)
                rv = p.add_run(v)
                rv.bold = True
                rv.font.size = Pt(9.5)
                rv.font.color.rgb = RGBColor(15, 23, 42)
                
        p_foot = doc.add_paragraph()
        p_foot.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_foot.paragraph_format.space_before = Pt(30)
        r = p_foot.add_run("Confidential © 2026 HackHalt Cyber Security. Developed during Cyber Security Internship.")
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(148, 163, 184)
        doc.add_page_break()
        continue

    # PARSE PAGE ELEMENTS
    elements = re.split(r'(<h1[^>]*>.*?</h1>|<h2[^>]*>.*?</h2>|<h3[^>]*>.*?</h3>|<p[^>]*>.*?</p>|<pre><code>.*?</code></pre>|<div class="diagram-box">.*?</div>|<div class="callout[^"]*">.*?</div>|<table[^>]*>.*?</table>|<ul[^>]*>.*?</ul>|<ol[^>]*>.*?</ol>)', page, flags=re.DOTALL)
    
    for el in elements:
        el = el.strip()
        if not el:
            continue
            
        # H1
        if el.startswith('<h1'):
            m = re.search(r'<h1[^>]*>(.*?)</h1>', el, flags=re.DOTALL)
            if m:
                text = clean_html(m.group(1))
                h = doc.add_heading(text, level=1)
                h.paragraph_format.space_before = Pt(16)
                h.paragraph_format.space_after = Pt(8)
                h.paragraph_format.keep_with_next = True
                for r in h.runs:
                    r.font.name = 'Arial'
                    r.font.size = Pt(16)
                    r.font.bold = True
                    r.font.color.rgb = RGBColor(30, 58, 138)
                    
        # H2
        elif el.startswith('<h2'):
            m = re.search(r'<h2[^>]*>(.*?)</h2>', el, flags=re.DOTALL)
            if m:
                text = clean_html(m.group(1))
                h = doc.add_heading(text, level=2)
                h.paragraph_format.space_before = Pt(13)
                h.paragraph_format.space_after = Pt(5)
                h.paragraph_format.keep_with_next = True
                for r in h.runs:
                    r.font.name = 'Arial'
                    r.font.size = Pt(13)
                    r.font.bold = True
                    r.font.color.rgb = RGBColor(2, 132, 199)
                    
        # H3
        elif el.startswith('<h3'):
            m = re.search(r'<h3[^>]*>(.*?)</h3>', el, flags=re.DOTALL)
            if m:
                text = clean_html(m.group(1))
                h = doc.add_heading(text, level=3)
                h.paragraph_format.space_before = Pt(10)
                h.paragraph_format.space_after = Pt(4)
                h.paragraph_format.keep_with_next = True
                for r in h.runs:
                    r.font.name = 'Arial'
                    r.font.size = Pt(11)
                    r.font.bold = True
                    r.font.color.rgb = RGBColor(51, 65, 85)

        # DIAGRAM / PRE CODE
        elif el.startswith('<div class="diagram-box">') or el.startswith('<pre'):
            raw_text = re.sub(r'<[^>]+>', '', el)
            raw_text = raw_text.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&').replace('&quot;', '"').strip()
            
            tbl = doc.add_table(rows=1, cols=1)
            tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
            cell = tbl.cell(0, 0)
            set_cell_shading(cell, "0F172A")
            set_cell_margins(cell, top=100, bottom=100, left=140, right=140)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(raw_text)
            r.font.name = 'Consolas'
            r.font.size = Pt(8)
            r.font.color.rgb = RGBColor(241, 245, 249)
            doc.add_paragraph().paragraph_format.space_after = Pt(3)

        # CALLOUT
        elif el.startswith('<div class="callout'):
            raw_text = clean_html(el)
            tbl = doc.add_table(rows=1, cols=1)
            tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
            cell = tbl.cell(0, 0)
            set_cell_shading(cell, "EFF6FF")
            set_cell_margins(cell, top=120, bottom=120, left=160, right=160)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            add_styled_text(p, raw_text)
            doc.add_paragraph().paragraph_format.space_after = Pt(3)

        # TABLES
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
                                bg = "0F172A" if is_head else ("F8FAFC" if r_idx % 2 == 1 else "FFFFFF")
                                set_cell_shading(cell, bg)
                                set_cell_margins(cell, top=70, bottom=70, left=90, right=90)
                                p = cell.paragraphs[0]
                                p.paragraph_format.space_after = Pt(0)
                                add_styled_text(p, cell_value)
                                if is_head:
                                    for run in p.runs:
                                        run.bold = True
                                        run.font.size = Pt(8.5)
                                        run.font.color.rgb = RGBColor(255, 255, 255)
                                else:
                                    for run in p.runs:
                                        run.font.size = Pt(8.5)
                    doc.add_paragraph().paragraph_format.space_after = Pt(4)

        # LISTS
        elif el.startswith('<ul') or el.startswith('<ol'):
            items = re.findall(r'<li[^>]*>(.*?)</li>', el, flags=re.DOTALL)
            for idx, item in enumerate(items):
                p = doc.add_paragraph(style='List Bullet' if el.startswith('<ul') else 'List Number')
                p.paragraph_format.space_after = Pt(3)
                p.paragraph_format.line_spacing = 1.15
                add_styled_text(p, clean_html(item))

        # PARAGRAPHS
        elif el.startswith('<p'):
            raw_text = clean_html(el)
            if raw_text:
                p = doc.add_paragraph()
                p.paragraph_format.space_after = Pt(6)
                p.paragraph_format.line_spacing = 1.15
                add_styled_text(p, raw_text)

    # Add page break after each chapter/logical page
    if page_idx < len(pages) - 1:
        doc.add_page_break()

doc.save(str(OUTPUT_DOCX))
print(f"SUCCESS: Saved 30+ page Word document to: {OUTPUT_DOCX}")
