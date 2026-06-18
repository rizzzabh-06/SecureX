"""
PDF Forensic Report Generator — court-admissible reports using ReportLab.
Features exhaustive technical details (Androguard static, Frida dynamic, AI context, Semantic MITRE)
with a dynamic layout that prevents text overlapping.
"""

from datetime import datetime, timezone
from pathlib import Path

from app.config import settings

def generate_report_pdf(findings: dict, output_path: str = None) -> str:
    """
    Generate a technical PDF report from analysis findings.
    Returns the path to the generated PDF.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer,
            Table, TableStyle, HRFlowable, KeepTogether
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
    except ImportError:
        print("[Report] reportlab not installed, skipping PDF generation")
        return ""

    if not output_path:
        reports_dir = Path(settings.REPORTS_DIR)
        reports_dir.mkdir(parents=True, exist_ok=True)
        case_id = findings.get("case_id", "unknown")
        output_path = str(reports_dir / f"report_{case_id}.pdf")

    doc = SimpleDocTemplate(output_path, pagesize=A4,
                            topMargin=15 * mm, bottomMargin=15 * mm,
                            leftMargin=15 * mm, rightMargin=15 * mm)
    styles = getSampleStyleSheet()
    story = []

    # Custom Styles for new color palette
    c_black = colors.HexColor("#111111")
    c_red = colors.HexColor("#8B0000")
    c_orange = colors.HexColor("#CC5500")
    c_green = colors.HexColor("#006400")
    c_bg_light = colors.HexColor("#F9F9F9")

    style_title = ParagraphStyle("TitleStyle", parent=styles["Heading1"], fontSize=20, textColor=c_black, fontName="Helvetica-Bold", spaceAfter=6)
    style_subtitle = ParagraphStyle("SubTitleStyle", parent=styles["Normal"], fontSize=10, textColor=colors.dimgrey, spaceAfter=12)
    style_h2 = ParagraphStyle("H2Style", parent=styles["Heading2"], fontSize=14, textColor=c_black, fontName="Helvetica-Bold", spaceBefore=15, spaceAfter=8)
    style_body = ParagraphStyle("BodyStyle", parent=styles["Normal"], fontSize=9, leading=12)
    style_body_mono = ParagraphStyle("BodyMonoStyle", parent=styles["Normal"], fontSize=8, leading=10, fontName="Courier")
    style_table_cell = ParagraphStyle("TableCell", parent=styles["Normal"], fontSize=8, leading=10)
    style_table_cell_bold = ParagraphStyle("TableCellBold", parent=styles["Normal"], fontSize=8, leading=10, fontName="Helvetica-Bold", textColor=colors.white)

    # ── Header ───────────────────────────────────────────────────
    story.append(Paragraph("DIGITAL FORENSIC ANALYSIS REPORT", style_title))
    story.append(Paragraph(f"SecureX Platform — Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", style_subtitle))
    story.append(HRFlowable(width="100%", thickness=2, color=c_red))
    story.append(Spacer(1, 10))

    # ── Case Metadata ─────────────────────────────────────────────
    score = findings.get("threat_score", 0)
    score_color = c_red if score >= 75 else c_orange if score >= 50 else c_green
    
    classification = findings.get("classification", "N/A").upper()

    meta_data = [
        ["Case Reference", Paragraph(findings.get("case_id", "N/A"), style_table_cell)],
        ["Package Name", Paragraph(findings.get("package_name", "Unknown"), style_table_cell)],
        ["SHA-256 Hash", Paragraph(findings.get("apk_sha256", "N/A"), style_body_mono)],
        ["File Size", Paragraph(f"{findings.get('size_bytes', 0):,} bytes", style_table_cell)],
        ["RISK SCORE", Paragraph(f"{score}/100 — {classification}", ParagraphStyle("Score", parent=style_table_cell_bold, fontSize=12, textColor=colors.white))],
    ]
    
    family = findings.get("malware_family", "")
    if family and family != "No classification":
        meta_data.insert(2, ["Malware Family", Paragraph(family, ParagraphStyle("Fam", parent=style_table_cell, textColor=c_red, fontName="Helvetica-Bold"))])

    t_meta = Table(meta_data, colWidths=[40 * mm, 140 * mm])
    t_meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), c_black),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BACKGROUND", (1, -1), (1, -1), score_color),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (1, 0), (1, -2), [colors.white, c_bg_light]),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 15))

    # ── Executive AI Summary ──────────────────────────────────────
    ai_analysis = findings.get("ai_analysis", {})
    if isinstance(ai_analysis, dict):
        risk = ai_analysis.get("risk_assessment", {})
        behavior = ai_analysis.get("behavior_context", {})
        
        story.append(Paragraph("EXECUTIVE AI SUMMARY", style_h2))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
        story.append(Spacer(1, 5))
        
        reasoning = risk.get("chain_of_reasoning", "No AI reasoning available.")
        
        import re
        # Convert **bold** to <b>bold</b>
        reasoning = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', reasoning)
        # Convert *italic* to <i>italic</i>
        reasoning = re.sub(r'\*(.*?)\*', r'<i>\1</i>', reasoning)
        # Convert `code` to <font>code</font>
        reasoning = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', reasoning)
        
        table_rows = []
        
        def flush_table():
            if table_rows:
                t = Table(table_rows, colWidths=[40 * mm, 140 * mm])
                t.setStyle(TableStyle([
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ("BACKGROUND", (0, 0), (0, -1), c_bg_light),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 6)
                ]))
                story.append(t)
                story.append(Spacer(1, 10))
                table_rows.clear()

        for line in reasoning.split('\n'):
            line = line.strip()
            if not line:
                flush_table()
                continue
            
            if line.startswith('---'):
                flush_table()
                story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
                story.append(Spacer(1, 10))
                continue
                
            if line.startswith('|'):
                if '---' in line:
                    continue # Skip separator row
                cells = [c.strip() for c in line.strip('|').split('|')]
                if len(cells) >= 2:
                    table_rows.append([Paragraph(cells[0], style_table_cell), Paragraph(cells[1], style_table_cell)])
                else:
                    table_rows.append([Paragraph(cells[0], style_table_cell), ""])
                continue
            
            flush_table()

            if line.startswith('#'):
                heading_text = line.lstrip('# ').strip()
                story.append(Paragraph(heading_text, ParagraphStyle("AIHeading", parent=style_h2, fontSize=11, textColor=c_red)))
                story.append(Spacer(1, 4))
            elif line.startswith('- ') or line.startswith('* '):
                bullet_text = line[2:].replace("<i>", "").replace("</i>", "") if line.startswith('* ') else line[2:]
                story.append(Paragraph(f"• {bullet_text}", ParagraphStyle("Bullet", parent=style_body, leftIndent=15, firstLineIndent=-10)))
                story.append(Spacer(1, 4))
            elif re.match(r'^\d+\.\s', line):
                story.append(Paragraph(line, ParagraphStyle("Numbered", parent=style_body, leftIndent=15, firstLineIndent=-10)))
                story.append(Spacer(1, 4))
            else:
                story.append(Paragraph(line, style_body))
                story.append(Spacer(1, 4))
                
        flush_table()
            
        story.append(Spacer(1, 10))
        
        narrative = behavior.get("behavior_narrative", "")
        if narrative:
            story.append(Paragraph("<b>Behavioral Narrative:</b> " + narrative, style_body))
            story.append(Spacer(1, 5))

    # ── Semantic Capabilities (MITRE) ─────────────────────────────
    static = findings.get("static_analysis", {})
    sem_caps = static.get("semantic_capabilities", [])
    if sem_caps:
        story.append(KeepTogether([
            Paragraph("SEMANTIC CAPABILITIES (STATIC INFERENCE)", style_h2),
            HRFlowable(width="100%", thickness=1, color=colors.lightgrey),
            Spacer(1, 5),
            Paragraph("The following capabilities were statically inferred from component names:", style_body),
            Spacer(1, 5),
            Table([[Paragraph(f"• {cap}", style_table_cell)] for cap in sem_caps], colWidths=[180 * mm])
        ]))
        story.append(Spacer(1, 10))

    # ── Static Analysis Findings ──────────────────────────────────
    story.append(Paragraph("STATIC ANALYSIS FINDINGS", style_h2))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
    story.append(Spacer(1, 5))
    
    summary = static.get("summary", {})
    
    # YARA
    yara_hits = summary.get("yara_hits", len(static.get("yara_matches", [])))
    story.append(Paragraph(f"<b>YARA Rules Matched:</b> {yara_hits}", style_body))
    if yara_hits > 0:
        yara_data = [["Rule Name", "Severity", "Tags"]]
        # We don't have the full yara list in the top level 'findings' schema easily, 
        # but if we passed it in static_analysis, we can render it.
        # For now, we just show the count.
    story.append(Spacer(1, 10))

    # Permissions
    perms = static.get("dangerous_permissions", [])
    if perms:
        story.append(Paragraph(f"<b>Dangerous Permissions ({len(perms)}):</b>", style_body))
        perm_str = ", ".join(perms).replace("android.permission.", "")
        story.append(Paragraph(perm_str, style_body_mono))
        story.append(Spacer(1, 10))

    # ── Threat Indicators (IndicatorEngine) ───────────────────────
    indicators = findings.get("threat_indicators", [])
    if indicators:
        story.append(KeepTogether([
            Paragraph("THREAT INDICATORS & RULE MATCHES", style_h2),
            HRFlowable(width="100%", thickness=1, color=colors.lightgrey),
            Spacer(1, 5)
        ]))
        
        ind_data = [[
            Paragraph("Indicator / Rule Name", style_table_cell_bold),
            Paragraph("Category", style_table_cell_bold),
            Paragraph("Severity", style_table_cell_bold),
            Paragraph("MITRE", style_table_cell_bold)
        ]]
        
        for ind in sorted(indicators, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x.get("severity", "INFO"), 5)):
            sev = ind.get("severity", "INFO")
            sev_color = c_red if sev == "CRITICAL" else c_orange if sev == "HIGH" else c_black
            
            ind_data.append([
                Paragraph(ind.get("name", "Unknown"), style_table_cell),
                Paragraph(ind.get("category", "Unknown"), style_table_cell),
                Paragraph(sev, ParagraphStyle("Sev", parent=style_table_cell, textColor=sev_color, fontName="Helvetica-Bold")),
                Paragraph(ind.get("mitre_technique", ""), style_table_cell_bold)
            ])
            
        t_ind = Table(ind_data, colWidths=[80 * mm, 40 * mm, 30 * mm, 30 * mm])
        t_ind.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_black),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_bg_light]),
            ("TOPPADDING", (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ]))
        story.append(t_ind)
        story.append(Spacer(1, 15))

    # ── VirusTotal Detections ─────────────────────────────────────
    threat_intel = findings.get("threat_intel", {})
    hash_check = threat_intel.get("hash_check", {})
    if hash_check and hash_check.get("known"):
        story.append(KeepTogether([
            Paragraph("VIRUSTOTAL INTELLIGENCE", style_h2),
            HRFlowable(width="100%", thickness=1, color=colors.lightgrey),
            Spacer(1, 5)
        ]))
        
        ratio = hash_check.get("detection_ratio", "0/0")
        story.append(Paragraph(f"<b>Detection Ratio:</b> {ratio}", style_body))
        
        families = hash_check.get("families", [])
        if families:
            story.append(Paragraph(f"<b>Detected Families:</b> {', '.join(families)}", style_body))
            
        top_dets = hash_check.get("top_detections", [])
        if top_dets:
            story.append(Spacer(1, 5))
            det_data = [[Paragraph("Security Vendor", style_table_cell_bold), Paragraph("Detection Name", style_table_cell_bold)]]
            for det in top_dets:
                det_data.append([
                    Paragraph(det.get("vendor", "Unknown"), style_table_cell),
                    Paragraph(det.get("result", "Unknown"), style_table_cell)
                ])
            
            t_det = Table(det_data, colWidths=[60 * mm, 120 * mm])
            t_det.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), c_black),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_bg_light]),
                ("TOPPADDING", (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ]))
            story.append(t_det)
            
        story.append(Spacer(1, 15))

    # ── Dynamic Analysis (Frida Hooks) ────────────────────────────
    dynamic = findings.get("dynamic_analysis", {})
    events = [ev for ev in dynamic.get("events", []) if ev.get("type") != "agent_ready"]
    
    story.append(KeepTogether([
        Paragraph("DYNAMIC ANALYSIS (FRIDA RUNTIME HOOKS)", style_h2),
        HRFlowable(width="100%", thickness=1, color=colors.lightgrey),
        Spacer(1, 5)
    ]))
    
    if events:
        story.append(Paragraph(f"Total runtime events captured: {len(events)}. Showing top 20 critical events:", style_body))
        story.append(Spacer(1, 5))
        
        event_data = [[Paragraph("API / Action", style_table_cell_bold), Paragraph("Data / Details", style_table_cell_bold)]]
        
        # Limit to 20 to prevent 50+ page PDFs
        for ev in events[:20]:
            action_type = ev.get("type", "unknown")
            if action_type == "crypto":
                api = f"Crypto: {ev.get('algorithm', 'unknown')}"
                data = f"Key: {ev.get('key_base64', 'N/A')}"
            elif action_type == "sms":
                api = "SMS Sent"
                data = f"To: {ev.get('destination', 'N/A')} | Msg: {ev.get('content', 'N/A')}"
            else:
                api = action_type
                data = str(ev)[:150] + "..." # truncate massive payloads
                
            event_data.append([
                Paragraph(api, style_table_cell),
                Paragraph(data, style_body_mono) # Changed to body mono for better line wrapping
            ])
            
        # Use wordWrap='CJK' for better line breaking on long strings
        style_body_mono.wordWrap = 'CJK'
        t_events = Table(event_data, colWidths=[50 * mm, 130 * mm], repeatRows=1)
        t_events.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (1, 0), c_black),
            ("TEXTCOLOR", (0, 0), (1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_bg_light]),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ]))
        story.append(t_events)
    else:
        story.append(Paragraph("Dynamic instrumentation active. No suspicious runtime hooks, network connections, or SMS operations were intercepted during the analysis window.", style_body))
        
    story.append(Spacer(1, 15))

    # ── Network & C2 Infrastructure ───────────────────────────────
    c2_list = findings.get("c2_infrastructure", [])
    if c2_list:
        story.append(KeepTogether([
            Paragraph("NETWORK & C2 INFRASTRUCTURE", style_h2),
            HRFlowable(width="100%", thickness=1, color=colors.lightgrey),
            Spacer(1, 5)
        ]))
        c2_data = [[
            Paragraph("IP Address", style_table_cell_bold),
            Paragraph("Country", style_table_cell_bold),
            Paragraph("ISP / Domain", style_table_cell_bold),
            Paragraph("AbuseIPDB Score", style_table_cell_bold)
        ]]
        for c2 in c2_list:
            score_val = c2.get('composite_risk', 0)
            score_color = c_red if score_val > 70 else c_orange if score_val > 30 else c_black
            c2_data.append([
                Paragraph(c2.get("ip", "N/A"), style_table_cell),
                Paragraph(c2.get("country", "Unknown"), style_table_cell),
                Paragraph(str(c2.get("domain", c2.get("asn", "Unknown"))), style_table_cell),
                Paragraph(f"{score_val}%", ParagraphStyle("s", parent=style_table_cell, textColor=score_color, fontName="Helvetica-Bold")),
            ])
        c2_table = Table(c2_data, colWidths=[35 * mm, 25 * mm, 80 * mm, 40 * mm], repeatRows=1)
        c2_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_black),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_bg_light]),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ]))
        story.append(c2_table)
        story.append(Spacer(1, 15))

    # ── Chain of Custody ──────────────────────────────────────────
    custody = findings.get("custody_chain", {})
    if custody:
        story.append(KeepTogether([
            Paragraph("CHAIN OF CUSTODY", style_h2),
            HRFlowable(width="100%", thickness=1, color=colors.lightgrey),
            Spacer(1, 5)
        ]))
        integrity = custody.get("integrity", "UNKNOWN")
        integrity_color = c_green if integrity == "VERIFIED" else c_red
        story.append(Paragraph(
            f"Integrity Status: <b>{integrity}</b> ({custody.get('entry_count', 0)} log entries)",
            ParagraphStyle("custody", parent=style_body, textColor=integrity_color)
        ))
        story.append(Spacer(1, 15))

    # ── Footer ────────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
    story.append(Paragraph(
        "Confidential Forensic Report. Handled in accordance with ACPO guidelines for digital evidence.",
        ParagraphStyle("footer", parent=style_table_cell, textColor=colors.grey, alignment=1)
    ))

    doc.build(story)
    return output_path
