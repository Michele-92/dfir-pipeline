"""
report_builder.py
-----------------
Erstellt den DFIR Critical Report als PDF.
Wird von stage14_export.py aufgerufen:

    from report_builder import build_critical_report
    build_critical_report(
        findings     = ctx.forensic_findings,
        ki_texte_map = ki_texte_map,
        ctx          = ctx,
        output_path  = ctx.case_dir / "DFIR_Critical_Report.pdf",
    )
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.lib.colors import HexColor

# ══════════════════════════════════════════════════════════════════════════════
#  FARBEN
# ══════════════════════════════════════════════════════════════════════════════

C_BG        = HexColor("#0d1117")
C_PANEL     = HexColor("#161b22")
C_BORDER    = HexColor("#30363d")
C_RED       = HexColor("#da3633")
C_RED_SOFT  = HexColor("#3d1a1a")
C_ORANGE    = HexColor("#e3972b")
C_BLUE      = HexColor("#1f6feb")
C_GREEN     = HexColor("#238636")
C_YELLOW    = HexColor("#d29922")
C_TEXT      = HexColor("#e6edf3")
C_MUTED     = HexColor("#8b949e")
C_HEAD_BG   = HexColor("#21262d")

# ══════════════════════════════════════════════════════════════════════════════
#  LAYOUT-KONSTANTEN
# ══════════════════════════════════════════════════════════════════════════════

PAGE_W, PAGE_H = A4
MARGIN         = 1.8 * cm
CONTENT_W      = PAGE_W - 2 * MARGIN

# ══════════════════════════════════════════════════════════════════════════════
#  STYLES
# ══════════════════════════════════════════════════════════════════════════════

def _make_styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()

    def s(name: str, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    return {
        "cover_h1":    s("cover_h1",    fontSize=26, textColor=C_TEXT,   fontName="Helvetica-Bold", leading=32),
        "cover_h2":    s("cover_h2",    fontSize=13, textColor=C_RED,    fontName="Helvetica-Bold", leading=18),
        "cover_meta":  s("cover_meta",  fontSize=9,  textColor=C_MUTED,  fontName="Helvetica",      leading=14),
        "cover_warn":  s("cover_warn",  fontSize=10, textColor=C_RED,    fontName="Helvetica-Bold", leading=14),
        "cover_warn2": s("cover_warn2", fontSize=9,  textColor=C_TEXT,   fontName="Helvetica",      leading=13),
        "trans_label": s("trans_label", fontSize=11, textColor=C_RED,    fontName="Helvetica-Bold",
                         leading=16, alignment=TA_CENTER),
        "trans_nr":    s("trans_nr",    fontSize=32, textColor=C_TEXT,   fontName="Helvetica-Bold",
                         leading=40, alignment=TA_CENTER),
        "trans_regel": s("trans_regel", fontSize=13, textColor=C_ORANGE, fontName="Courier",
                         leading=18, alignment=TA_CENTER),
        "trans_datei": s("trans_datei", fontSize=11, textColor=C_MUTED,  fontName="Courier",
                         leading=16, alignment=TA_CENTER),
        "trans_src":   s("trans_src",   fontSize=9,  textColor=C_TEXT,   fontName="Helvetica",
                         leading=13, alignment=TA_CENTER),
        "section":     s("section",     fontSize=13, textColor=C_TEXT,   fontName="Helvetica-Bold",
                         spaceBefore=14, spaceAfter=6),
        "subsection":  s("subsection",  fontSize=11, textColor=C_RED,    fontName="Helvetica-Bold",
                         spaceBefore=8, spaceAfter=4),
        "body":        s("body",        fontSize=9,  textColor=C_TEXT,   fontName="Helvetica",      leading=14),
        "muted":       s("muted",       fontSize=8,  textColor=C_MUTED,  fontName="Helvetica",      leading=12),
        "mono":        s("mono",        fontSize=8,  textColor=HexColor("#79c0ff"), fontName="Courier", leading=12),
        "blk_sev":     s("blk_sev",     fontSize=9,  textColor=C_RED,    fontName="Helvetica-Bold"),
        "blk_regel":   s("blk_regel",   fontSize=9,  textColor=C_TEXT,   fontName="Helvetica-Bold"),
        "blk_icon":    s("blk_icon",    fontSize=11, textColor=C_RED,    fontName="Helvetica-Bold",
                         alignment=TA_CENTER),
        "blk_title":   s("blk_title",   fontSize=9,  textColor=C_TEXT,   fontName="Helvetica-Bold", leading=13),
        "blk_body":    s("blk_body",    fontSize=8.5,textColor=C_TEXT,   fontName="Helvetica",      leading=13),
        "blk_icon_o":  s("blk_icon_o",  fontSize=11, textColor=C_ORANGE, fontName="Helvetica-Bold",
                         alignment=TA_CENTER),
        "blk_icon_g":  s("blk_icon_g",  fontSize=11, textColor=C_GREEN,  fontName="Helvetica-Bold",
                         alignment=TA_CENTER),
        "blk_icon_y":  s("blk_icon_y",  fontSize=11, textColor=C_YELLOW, fontName="Helvetica-Bold",
                         alignment=TA_CENTER),
        "th":          s("th",          fontSize=8,  textColor=C_MUTED,  fontName="Helvetica-Bold"),
        "td":          s("td",          fontSize=8,  textColor=C_TEXT,   fontName="Helvetica",      leading=12),
        "td_mono":     s("td_mono",     fontSize=7.5,textColor=HexColor("#79c0ff"), fontName="Courier", leading=11),
        "td_muted":    s("td_muted",    fontSize=8,  textColor=C_MUTED,  fontName="Helvetica",      leading=12),
        "td_red":      s("td_red",      fontSize=8,  textColor=C_RED,    fontName="Helvetica-Bold"),
        "td_orange":   s("td_orange",   fontSize=8,  textColor=C_ORANGE, fontName="Helvetica-Bold"),
        "td_blue":     s("td_blue",     fontSize=8,  textColor=C_BLUE,   fontName="Helvetica-Bold"),
        "td_yellow":   s("td_yellow",   fontSize=8,  textColor=C_YELLOW, fontName="Helvetica-Bold"),
        "td_green":    s("td_green",    fontSize=8,  textColor=C_GREEN,  fontName="Helvetica-Bold"),
        "kpi_val":     s("kpi_val",     fontSize=22, textColor=C_RED,    fontName="Helvetica-Bold",
                         alignment=TA_CENTER, leading=28),
        "kpi_lbl":     s("kpi_lbl",     fontSize=8,  textColor=C_MUTED,  fontName="Helvetica",
                         alignment=TA_CENTER),
        "tl_ts":       s("tl_ts",       fontSize=8,  textColor=C_MUTED,  fontName="Courier",        leading=12),
        "tl_ev":       s("tl_ev",       fontSize=8.5,textColor=C_TEXT,   fontName="Helvetica",      leading=13),
    }

ST = _make_styles()


def _finding_key(finding) -> str:
    """Eindeutiger Key pro Finding — identisch mit ki_text_generator.py."""
    ts = ""
    if getattr(finding, "anomaly_time", None):
        ts = finding.anomaly_time.strftime("%Y%m%d%H%M%S")
    return f"{finding.file}::{finding.rule}::{ts}"


def _safe_zebra(tbl, color, start: int = 2, step: int = 2):
    n = len(tbl._rowHeights)
    for i in range(start, n, step):
        tbl.setStyle(TableStyle([("BACKGROUND", (0,i), (-1,i), color)]))


# ══════════════════════════════════════════════════════════════════════════════
#  CANVAS-CALLBACK
# ══════════════════════════════════════════════════════════════════════════════

def _add_bg(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(C_BG)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    canvas.setFillColor(C_RED)
    canvas.rect(0, PAGE_H - 4, PAGE_W, 4, fill=1, stroke=0)
    canvas.setFillColor(C_PANEL)
    canvas.rect(0, 0, PAGE_W, 1.1 * cm, fill=1, stroke=0)
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.4)
    canvas.line(0, 1.1 * cm, PAGE_W, 1.1 * cm)
    canvas.setFillColor(C_MUTED)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(MARGIN, 0.4 * cm,
        "DFIR Analyse-Pipeline v3.0  |  CRITICAL Finding Report  |  VERTRAULICH")
    case_id = getattr(doc, "_case_id", "case_unknown")
    canvas.drawRightString(PAGE_W - MARGIN, 0.4 * cm,
        f"Case: {case_id}  |  Seite {doc.page}")
    canvas.restoreState()


# ══════════════════════════════════════════════════════════════════════════════
#  HILFS-FUNKTIONEN
# ══════════════════════════════════════════════════════════════════════════════

def _p(text: str, style: str = "body") -> Paragraph:
    return Paragraph(str(text), ST[style])

def _hr(color=C_BORDER, thickness: float = 0.5, space: float = 6) -> HRFlowable:
    return HRFlowable(width="100%", thickness=thickness,
                      color=color, spaceAfter=space, spaceBefore=space)

def _sp(h: float = 0.3) -> Spacer:
    return Spacer(1, h * cm)

def _section_title(text: str) -> List:
    return [_hr(C_RED, 1.2, 2), _p(text, "section"), _hr(C_BORDER, 0.4, 4)]

def _dark_table(header: List, rows: List, col_widths: List,
                mono_cols: Optional[List[int]] = None) -> Table:
    mono_cols = mono_cols or []
    all_rows = [header] + rows
    tbl = Table(all_rows, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0,0), (-1,0),  C_HEAD_BG),
        ("TEXTCOLOR",  (0,0), (-1,0),  C_MUTED),
        ("FONTNAME",   (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,0),  8),
        ("BACKGROUND", (0,1), (-1,-1), C_PANEL),
        ("TEXTCOLOR",  (0,1), (-1,-1), C_TEXT),
        ("FONTNAME",   (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",   (0,1), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ("RIGHTPADDING",  (0,0), (-1,-1), 6),
        ("LINEBELOW", (0,0), (-1,-1), 0.3, C_BORDER),
        ("BOX",       (0,0), (-1,-1), 0.6, C_BORDER),
        ("VALIGN",    (0,0), (-1,-1), "MIDDLE"),
    ]
    n = len(all_rows)
    for i in range(2, n, 2):
        style.append(("BACKGROUND", (0,i), (-1,i), HexColor("#1a1f27")))
    for col in mono_cols:
        style += [
            ("FONTNAME",  (col,1), (col,-1), "Courier"),
            ("TEXTCOLOR", (col,1), (col,-1), HexColor("#79c0ff")),
        ]
    tbl.setStyle(TableStyle(style))
    return tbl


def _section_box(icon: str, title: str, body: str,
                 icon_style: str = "blk_icon",
                 border_color=None) -> Table:
    border_color = border_color or C_RED
    inner = Table([
        [_p(icon, icon_style), _p(title, "blk_title")],
        [_p("",   icon_style), _p(body,  "blk_body")],
    ], colWidths=[0.9*cm, CONTENT_W - 2.2*cm])
    inner.setStyle(TableStyle([
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 2),
        ("BOTTOMPADDING", (0,0), (-1,-1), 2),
        ("LEFTPADDING",   (0,0), (-1,-1), 0),
        ("RIGHTPADDING",  (0,0), (-1,-1), 0),
    ]))
    outer = Table([[inner]], colWidths=[CONTENT_W - 0.4*cm])
    outer.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_PANEL),
        ("BOX",           (0,0), (-1,-1), 0.5, C_BORDER),
        ("LINEBEFORE",    (0,0), (0,-1),  3,   border_color),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("RIGHTPADDING",  (0,0), (-1,-1), 8),
        ("TOPPADDING",    (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
    ]))
    return outer


def _format_ts(dt) -> str:
    if dt is None:
        return "—"
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d  %H:%M:%S UTC")
    return str(dt)


def _format_evidence(evidence: Optional[List[Dict]]) -> Optional[List]:
    if not evidence:
        return None
    rows = []
    for ev in evidence[:8]:
        src = ev.get("source", "?")
        color_map = {
            "bash_history": "td_orange",
            "auth":         "td_blue",
            "audit":        "td_yellow",
            "mactime":      "td_red",
        }
        src_style = color_map.get(src, "td_muted")
        rows.append([
            Paragraph(ev.get("time", "?"), ST["td_mono"]),
            Paragraph(src,                  ST[src_style]),
            Paragraph(ev.get("message", "")[:110], ST["td"]),
            Paragraph(ev.get("user") or "—", ST["td_muted"]),
        ])
    return rows


# ══════════════════════════════════════════════════════════════════════════════
#  SEITE 1 — DECKBLATT
# ══════════════════════════════════════════════════════════════════════════════

def _build_cover(ctx) -> List:
    story = []
    story.append(_sp(1.2))
    story.append(_p("DFIR ANALYSE-PIPELINE v3.0", "cover_h2"))
    story.append(_p("CRITICAL FINDING REPORT", "cover_h1"))
    story.append(_sp(0.3))
    story.append(_hr(C_RED, 1.5))
    story.append(_sp(0.3))

    hostname  = getattr(ctx, "hostname",     "—")
    os_name   = getattr(ctx, "os_name",      "—")
    timezone  = getattr(ctx, "timezone",     "—")
    sha256    = getattr(ctx, "sha256",       "—")
    case_id   = ctx.case_dir.name if getattr(ctx, "case_dir", None) else "—"
    file_size = getattr(ctx, "file_size_gb", "—")

    meta = [
        ["Case-ID",      case_id],
        ["Hostname",     hostname],
        ["OS",           os_name],
        ["Zeitzone",     timezone],
        ["Image-SHA256", f"{sha256[:48]}..." if len(str(sha256)) > 48 else sha256],
        ["Image-Größe",  f"{file_size} GB"],
        ["Erstellt",     datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
    ]
    meta_tbl = Table(meta, colWidths=[3.5*cm, CONTENT_W - 3.5*cm])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (0,-1),  C_HEAD_BG),
        ("BACKGROUND",    (1,0), (1,-1),  C_PANEL),
        ("TEXTCOLOR",     (0,0), (0,-1),  C_MUTED),
        ("TEXTCOLOR",     (1,0), (1,-1),  C_TEXT),
        ("FONTNAME",      (0,0), (0,-1),  "Helvetica-Bold"),
        ("FONTNAME",      (1,0), (1,-1),  "Courier"),
        ("FONTSIZE",      (0,0), (-1,-1), 8.5),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("LINEBELOW",     (0,0), (-1,-1), 0.3, C_BORDER),
        ("BOX",           (0,0), (-1,-1), 0.8, C_BORDER),
        ("LINEBEFORE",    (0,0), (0,-1),  3,   C_RED),
    ]))
    story.append(meta_tbl)
    story.append(_sp(0.5))

    findings   = getattr(ctx, "forensic_findings", [])
    n_critical = sum(1 for f in findings if f.severity == "CRITICAL")
    n_high     = sum(1 for f in findings if f.severity == "HIGH")
    n_medium   = sum(1 for f in findings if f.severity == "MEDIUM")

    warn_inner = Table([
        [_p("SOFORTMASSNAHME ERFORDERLICH", "cover_warn")],
        [_p(
            f"CRITICAL: {n_critical}  ·  HIGH: {n_high}  ·  MEDIUM: {n_medium}  —  "
            "Anti-Forensics erkannt. Beweise sichern bevor weitere Analyse fortgesetzt wird.",
            "cover_warn2"
        )],
    ], colWidths=[CONTENT_W - 0.8*cm])
    warn_inner.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_RED_SOFT),
        ("BOX",           (0,0), (-1,-1), 1.5, C_RED),
        ("LINEBEFORE",    (0,0), (0,-1),  4,   C_RED),
        ("LEFTPADDING",   (0,0), (-1,-1), 12),
        ("RIGHTPADDING",  (0,0), (-1,-1), 12),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(warn_inner)
    story.append(_sp(0.6))
    story.append(_p("VERTRAULICH — Nicht für die Öffentlichkeit", "cover_meta"))
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SEITE 2 — EXECUTIVE SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

def _build_executive_summary(ctx) -> List:
    story = []
    story += _section_title("Executive Summary")

    findings   = getattr(ctx, "forensic_findings", [])
    iocs       = getattr(ctx, "iocs",              [])
    af_hits    = getattr(ctx, "antiforensics_hits", [])
    n_critical = sum(1 for f in findings if f.severity == "CRITICAL")
    n_high     = sum(1 for f in findings if f.severity == "HIGH")
    n_medium   = sum(1 for f in findings if f.severity == "MEDIUM")
    n_iocs     = len(iocs)
    n_af       = len(af_hits)

    def kpi_cell(val: str, label: str, color) -> Table:
        val_s = ParagraphStyle("kv", fontSize=20, textColor=color,
                               fontName="Helvetica-Bold", alignment=TA_CENTER, leading=26)
        lbl_s = ParagraphStyle("kl", fontSize=8, textColor=C_MUTED,
                               fontName="Helvetica", alignment=TA_CENTER)
        t = Table([[Paragraph(val, val_s)], [Paragraph(label, lbl_s)]],
                  colWidths=[CONTENT_W / 3 - 0.3*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), C_PANEL),
            ("BOX",        (0,0), (-1,-1), 0.6, C_BORDER),
            ("LINEBEFORE", (0,0), (0,-1),  3,   color),
            ("TOPPADDING",    (0,0), (-1,-1), 10),
            ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ]))
        return t

    col_w = [CONTENT_W / 3] * 3
    gap_style = TableStyle([
        ("LEFTPADDING",  (0,0), (-1,-1), 3),
        ("RIGHTPADDING", (0,0), (-1,-1), 3),
    ])

    row1 = Table([[
        kpi_cell(str(n_critical), "CRITICAL",      C_RED),
        kpi_cell(str(n_high),     "HIGH",          C_ORANGE),
        kpi_cell(str(n_medium),   "MEDIUM",        C_YELLOW),
    ]], colWidths=col_w)
    row1.setStyle(gap_style)

    row2 = Table([[
        kpi_cell(str(n_iocs),    "IOCs",           C_ORANGE),
        kpi_cell(str(n_af),      "Anti-Forensics", C_RED),
        kpi_cell("SEHR GUT",     "Qualität",       C_GREEN),
    ]], colWidths=col_w)
    row2.setStyle(gap_style)

    story += [row1, _sp(0.15), row2, _sp(0.5)]

    story.append(_p("Sofortmaßnahmen", "subsection"))
    story.append(_p(
        "1.  Beweise sichern — Anti-Forensics-Techniken wurden erkannt "
        "(Timestomping, Log-Deletion). Image nicht booten.", "body"))
    story.append(_p(
        "2.  IOC-Qualität MITTEL — manuelle Nachprüfung der extrahierten IOCs empfohlen.",
        "body"))
    story.append(_p(
        f"3.  {n_critical} CRITICAL-Befunde — alle auf den folgenden Seiten einzeln "
        "dokumentiert mit forensischer Begründung und empfohlenen Maßnahmen.", "body"))
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SEITE 3 — ALGORITHMUS-ÜBERSICHT
# ══════════════════════════════════════════════════════════════════════════════

def _build_algorithm_overview() -> List:
    story = []
    story += _section_title("Analyse-Methodik — Stage 8.5")
    story.append(_p(
        "Die CRITICAL-Einstufung basiert auf dem Prinzip der forensischen Korroboration: "
        "Ein Befund wird erst dann als CRITICAL markiert, wenn mindestens zwei "
        "unabhängige Analyse-Methoden denselben Verdacht bestätigen.", "body"))
    story.append(_sp(0.3))

    steps = [
        ("1", "MACB-Anomalien",        "MACtime-Zeitstempel",
         "Modified vor Born (physikalisch unmöglich), ctime-Sprünge, Timestamps vor 2000."),
        ("2", "Aktivitätsmuster",      "MACtime + bash_history",
         "Burst (>10 Systemdateien in 5 Min), Nachtaktivität, Staging in /tmp oder /dev/shm."),
        ("3", "Stage-9-Kreuzreferenz", "Anti-Forensics-Hits",
         "Hochstufung auf CRITICAL wenn Stage 9 (YARA + Keyword) denselben Befund bestätigt."),
        ("4", "CVE-Zeitfenster",       "IOCs + MACtime",
         "Systemdatei-Modifikationen ±30 Minuten nach CVE-Download = Exploit-Ausführung."),
        ("5", "Stage-6-Kontext",       "bash_history, auth, audit",
         "±10 Minuten um jeden Befund: wer hat was getan? Ergänzt Befunde mit Chronologie."),
    ]
    nr_s   = ParagraphStyle("nr_s",  fontSize=14, textColor=C_RED,   fontName="Helvetica-Bold",
                            alignment=TA_CENTER, leading=18)
    grp_s  = ParagraphStyle("grp_s", fontSize=9,  textColor=C_TEXT,  fontName="Helvetica-Bold", leading=13)
    src_s  = ParagraphStyle("src_s", fontSize=8,  textColor=C_BLUE,  fontName="Helvetica",      leading=12)
    desc_s = ParagraphStyle("desc_s",fontSize=8,  textColor=C_MUTED, fontName="Helvetica",      leading=12)

    step_rows = []
    for nr, gruppe, quelle, desc in steps:
        step_rows.append([
            Paragraph(nr, nr_s),
            Table([
                [Paragraph(gruppe, grp_s)],
                [Paragraph(quelle, src_s)],
                [Paragraph(desc,   desc_s)],
            ], colWidths=[CONTENT_W - 2.8*cm], style=[
                ("TOPPADDING",    (0,0), (-1,-1), 1),
                ("BOTTOMPADDING", (0,0), (-1,-1), 1),
                ("LEFTPADDING",   (0,0), (-1,-1), 0),
            ]),
        ])
    steps_tbl = Table(step_rows, colWidths=[1.2*cm, CONTENT_W - 1.2*cm])
    steps_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_PANEL),
        ("LINEBELOW",     (0,0), (-1,-1), 0.3, C_BORDER),
        ("LINEBEFORE",    (0,0), (0,-1),  3,   C_RED),
        ("BOX",           (0,0), (-1,-1), 0.5, C_BORDER),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,1), (-1,-1), 8),
    ]))
    _safe_zebra(steps_tbl, HexColor('#1a1f27'), start=1)
    story.append(steps_tbl)
    story.append(_sp(0.3))
    story.append(_p(
        "Jeder Befund auf den folgenden Seiten enthält: den Zeitstempel-Vergleich, "
        "eine KI-generierte forensische Begründung (Ollama, lokal), den Log-Kontext "
        "aus Stage 6 sowie priorisierte Maßnahmen.", "muted"))
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  SEITENÜBERLEITUNG
# ══════════════════════════════════════════════════════════════════════════════

def _transition_page(number: int, total: int, regel: str,
                     datei: str, bestaetigt_durch: str) -> Table:
    inner = Table([
        [Paragraph("CRITICAL-BEFUND", ST["trans_label"])],
        [Paragraph(f"#{number:02d} / {total}", ST["trans_nr"])],
        [Spacer(1, 0.4*cm)],
        [Paragraph(regel, ST["trans_regel"])],
        [Paragraph(datei, ST["trans_datei"])],
        [Spacer(1, 0.4*cm)],
        [Paragraph(f"Bestätigt durch: {bestaetigt_durch}", ST["trans_src"])],
    ], colWidths=[CONTENT_W - 2.0*cm])
    inner.setStyle(TableStyle([
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 0),
        ("RIGHTPADDING",  (0,0), (-1,-1), 0),
    ]))
    outer = Table([[inner]], colWidths=[CONTENT_W])
    outer.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_RED_SOFT),
        ("BOX",           (0,0), (-1,-1), 2.5, C_RED),
        ("TOPPADDING",    (0,0), (-1,-1), 60),
        ("BOTTOMPADDING", (0,0), (-1,-1), 60),
        ("LEFTPADDING",   (0,0), (-1,-1), 20),
        ("RIGHTPADDING",  (0,0), (-1,-1), 20),
    ]))
    return outer


# ══════════════════════════════════════════════════════════════════════════════
#  CRITICAL-BEFUND-BLOCK
# ══════════════════════════════════════════════════════════════════════════════

def _critical_block(number: int, regel: str, datei: str,
                    mod_ts: str, born_ts: str,
                    warum: str, was_bedeutet: str, naechste_schritte: str,
                    kontext_rows: Optional[List] = None,
                    cve: Optional[Dict] = None) -> List:
    story = []

    nr_box = Table([[Paragraph(f"#{number:02d}", ParagraphStyle(
        "nr_b", fontSize=18, textColor=C_RED, fontName="Helvetica-Bold",
        alignment=TA_CENTER, leading=22,
    ))]], colWidths=[1.3*cm])
    nr_box.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_RED_SOFT),
        ("BOX",           (0,0), (-1,-1), 0.8, C_RED),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING",   (0,0), (-1,-1), 4),
        ("RIGHTPADDING",  (0,0), (-1,-1), 4),
    ]))

    detail = Table([
        [_p("CRITICAL", "blk_sev"), _p(f"Regel: <b>{regel}</b>", "td")],
        [_p("Datei:", "td_muted"),  Paragraph(datei, ST["td_mono"])],
    ], colWidths=[2.1*cm, CONTENT_W - 3.6*cm])
    detail.setStyle(TableStyle([
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ("TOPPADDING",    (0,0), (-1,-1), 2),
        ("BOTTOMPADDING", (0,0), (-1,-1), 2),
        ("LEFTPADDING",   (0,0), (-1,-1), 0),
    ]))

    header = Table([[nr_box, detail]], colWidths=[1.5*cm, CONTENT_W - 1.5*cm])
    header.setStyle(TableStyle([
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("LEFTPADDING",  (0,0), (-1,-1), 0),
        ("RIGHTPADDING", (1,0), (1,-1),  0),
    ]))
    story.append(KeepTogether([header, _sp(0.2)]))

    ts_label_s = ParagraphStyle("tsl", fontSize=8,  textColor=C_MUTED, fontName="Helvetica-Bold")
    ts_val_s   = ParagraphStyle("tsv", fontSize=9,  textColor=C_TEXT,  fontName="Courier")
    ts_sub_s   = ParagraphStyle("tss", fontSize=7.5,textColor=C_MUTED, fontName="Helvetica")
    ts_arrow_s = ParagraphStyle("tsa", fontSize=18, textColor=C_RED,   fontName="Helvetica-Bold",
                                alignment=TA_CENTER, leading=22)

    half = (CONTENT_W - 2.5*cm) / 2
    ts_tbl = Table([
        [Paragraph("Modified (M)", ts_label_s), Paragraph("", ts_label_s),  Paragraph("Born (B)", ts_label_s)],
        [Paragraph(mod_ts, ts_val_s),           Paragraph("&lt;", ts_arrow_s), Paragraph(born_ts, ts_val_s)],
        [Paragraph("Inhalt zuletzt geändert", ts_sub_s), Paragraph("", ts_sub_s), Paragraph("Datei erstellt", ts_sub_s)],
    ], colWidths=[half, 2.5*cm, half])
    ts_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_BG),
        ("BACKGROUND",    (0,0), (0,-1),  HexColor("#1a1f27")),
        ("BACKGROUND",    (2,0), (2,-1),  HexColor("#1a1f27")),
        ("BOX",           (0,0), (0,-1),  0.6, C_MUTED),
        ("BOX",           (2,0), (2,-1),  0.6, C_MUTED),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN",         (1,0), (1,-1),  "CENTER"),
    ]))
    story += [ts_tbl, _sp(0.2)]

    story.append(_section_box("!", "Warum ist das CRITICAL?", warum,
                              icon_style="blk_icon", border_color=C_RED))
    story.append(_sp(0.15))
    story.append(_section_box("i", "Was bedeutet das konkret?", was_bedeutet,
                              icon_style="blk_icon_o", border_color=C_ORANGE))
    story.append(_sp(0.15))

    if kontext_rows:
        ctx_lbl_s = ParagraphStyle("ctl", fontSize=8, textColor=C_BLUE,
                                    fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=3)
        story.append(Paragraph("Kontext (Stage 6) — ±10 Minuten um den Befund:", ctx_lbl_s))
        ctx_header = [_p("Uhrzeit","th"), _p("Quelle","th"),
                      _p("Ereignis","th"), _p("Benutzer","th")]
        ctx_tbl = _dark_table(ctx_header, kontext_rows, [2.2*cm, 2.8*cm, 9.0*cm, 2.2*cm])
        ctx_outer = Table([[ctx_tbl]], colWidths=[CONTENT_W - 0.2*cm])
        ctx_outer.setStyle(TableStyle([
            ("BOX",          (0,0), (-1,-1), 0.5, C_BORDER),
            ("LINEBEFORE",   (0,0), (0,-1),  3,   C_BLUE),
            ("LEFTPADDING",  (0,0), (-1,-1), 0),
            ("RIGHTPADDING", (0,0), (-1,-1), 0),
            ("TOPPADDING",   (0,0), (-1,-1), 0),
            ("BOTTOMPADDING",(0,0), (-1,-1), 0),
        ]))
        story += [ctx_outer, _sp(0.15)]

    if cve:
        story.append(_section_box(
            "CVE", f"CVE-Zusammenhang: {cve.get('id','?')}",
            cve.get("text", "—"),
            icon_style="blk_icon_y", border_color=C_YELLOW,
        ))
        story.append(_sp(0.15))

    story.append(_section_box(
        "->", "Empfohlene nächste Schritte", naechste_schritte,
        icon_style="blk_icon_g", border_color=C_GREEN,
    ))
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  ZUSAMMENFASSUNG
# ══════════════════════════════════════════════════════════════════════════════

def _build_summary(findings: List, ctx) -> List:
    story = []
    story += _section_title("Zusammenfassung & Angriffsreihenfolge")

    critical = [f for f in findings if f.severity == "CRITICAL"]
    hdr = [_p("Nr.","th"), _p("Datei","th"), _p("Regel","th"), _p("Schwere","th")]
    rows = []
    for i, f in enumerate(critical[:20]):
        rows.append([
            _p(f"#{i+1:02d}", "td_mono"),
            Paragraph(f.file[:55], ST["td_mono"]),
            _p(f.rule[:30], "td"),
            _p("CRITICAL", "td_red"),
        ])
    if len(critical) > 20:
        rows.append([
            _p("...", "td_muted"),
            _p(f"+ {len(critical)-20} weitere in forensic_findings.json", "td_muted"),
            _p("—", "td_muted"), _p("CRITICAL", "td_red"),
        ])
    story.append(_dark_table(hdr, rows, [1.5*cm, 7.0*cm, 5.5*cm, 2.2*cm]))
    story.append(_sp(0.4))

    story.append(_p("Rekonstruierte Angriffsreihenfolge", "subsection"))
    tl_events = []
    for f in sorted(findings, key=lambda x: x.anomaly_time or datetime.min):
        if f.severity in ("CRITICAL", "HIGH") and f.anomaly_time:
            tl_events.append((
                f.anomaly_time.strftime("%Y-%m-%d %H:%M"),
                f.description[:80] if f.description else f.rule,
            ))

    if tl_events:
        tl_tbl = Table(tl_events[:20], colWidths=[4.0*cm, CONTENT_W - 4.0*cm])
        tl_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (0,-1),  C_HEAD_BG),
            ("BACKGROUND",    (1,0), (1,-1),  C_PANEL),
            ("TEXTCOLOR",     (0,0), (0,-1),  C_MUTED),
            ("TEXTCOLOR",     (1,0), (1,-1),  C_TEXT),
            ("FONTNAME",      (0,0), (0,-1),  "Courier"),
            ("FONTNAME",      (1,0), (1,-1),  "Helvetica"),
            ("FONTSIZE",      (0,0), (-1,-1), 8.5),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("LINEBELOW",     (0,0), (-1,-1), 0.3, C_BORDER),
            ("BOX",           (0,0), (-1,-1), 0.8, C_BORDER),
            ("LINEBEFORE",    (0,0), (0,-1),  3,   C_RED),
        ]))
        _safe_zebra(tl_tbl, HexColor('#1a1f27'), start=1)
        story.append(tl_tbl)

    story.append(_sp(0.4))
    story.append(_p(
        "Vollständige Befundliste: <b>forensic_findings.json</b>  |  "
        "Interaktive Timeline: http://localhost:5000/sketch/1/explore", "muted"))
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  CHAIN OF CUSTODY
# ══════════════════════════════════════════════════════════════════════════════

def _build_chain_of_custody(ctx) -> List:
    story = []
    story += _section_title("Chain of Custody")

    sha256    = getattr(ctx, "sha256",       "—")
    md5       = getattr(ctx, "md5",          "—")
    file_size = getattr(ctx, "file_size_gb", "—")
    case_id   = ctx.case_dir.name if getattr(ctx, "case_dir", None) else "—"
    hostname  = getattr(ctx, "hostname",     "—")

    cod_data = [
        ["Dateiname",  f"{hostname}.E01"],
        ["SHA256",     str(sha256)],
        ["MD5",        str(md5)],
        ["Größe",      f"{file_size} GB"],
        ["Case-ID",    case_id],
        ["Analyse",    datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
    ]
    tbl = Table(cod_data, colWidths=[3.0*cm, CONTENT_W - 3.0*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (0,-1),  C_HEAD_BG),
        ("BACKGROUND",    (1,0), (1,-1),  C_PANEL),
        ("TEXTCOLOR",     (0,0), (0,-1),  C_MUTED),
        ("TEXTCOLOR",     (1,0), (1,-1),  C_TEXT),
        ("FONTNAME",      (0,0), (0,-1),  "Helvetica-Bold"),
        ("FONTNAME",      (1,0), (1,-1),  "Courier"),
        ("FONTSIZE",      (0,0), (-1,-1), 8.5),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("LINEBELOW",     (0,0), (-1,-1), 0.3, C_BORDER),
        ("BOX",           (0,0), (-1,-1), 0.8, C_BORDER),
        ("LINEBEFORE",    (0,0), (0,-1),  3,   C_GREEN),
    ]))
    story.append(tbl)
    story.append(_sp(0.4))
    story.append(_p(
        "Rechtlicher Hinweis: Dieses Dokument wurde automatisch generiert. "
        "Die Integrität des Beweismittels wurde durch SHA256- und MD5-Hashwerte gesichert. "
        "KI-generierte Texte wurden durch lokales Ollama-Modell erstellt — "
        "keine Daten wurden an externe Server übermittelt.", "muted"))
    return story


# ══════════════════════════════════════════════════════════════════════════════
#  HAUPT-FUNKTION
# ══════════════════════════════════════════════════════════════════════════════

def build_critical_report(findings: List,
                           ki_texte_map: Dict[str, Dict],
                           ctx,
                           output_path: Path) -> None:
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN,  bottomMargin=1.6*cm,
        title="DFIR Critical Finding Report",
        author="DFIR Analyse-Pipeline v3.0",
    )
    doc._case_id = ctx.case_dir.name if getattr(ctx, "case_dir", None) else "—"

    story = []
    critical = [f for f in findings if f.severity == "CRITICAL"]

    story += _build_cover(ctx)
    story.append(PageBreak())

    story += _build_executive_summary(ctx)
    story.append(PageBreak())

    story += _build_algorithm_overview()
    story.append(PageBreak())

    for i, finding in enumerate(critical):
        bestaetigt = "MACtime"
        if finding.description and "Stage 9" in finding.description:
            bestaetigt += " + Stage 9"
        if finding.rule == "cve_time_window":
            bestaetigt += " + CVE-Zeitfenster"

        story.append(_transition_page(
            number=i + 1, total=len(critical),
            regel=finding.rule, datei=finding.file,
            bestaetigt_durch=bestaetigt,
        ))
        story.append(PageBreak())

        ki = ki_texte_map.get(_finding_key(finding), {})

        born_ts = "—"
        if finding.description and "Born (" in finding.description:
            m = re.search(r"Born \(([^)]+)\)", finding.description)
            if m:
                born_ts = m.group(1)

        cve_info = None
        if finding.rule == "cve_time_window" and finding.description:
            m = re.search(r"(CVE-\d{4}-\d+)", finding.description)
            cve_id = m.group(1) if m else ""
            cve_info = {"id": cve_id, "text": finding.description[:300]}

        story += _critical_block(
            number=i + 1,
            regel=finding.rule,
            datei=finding.file,
            mod_ts=_format_ts(finding.anomaly_time),
            born_ts=born_ts,
            warum=ki.get("warum_critical",    finding.description or "—"),
            was_bedeutet=ki.get("was_bedeutet",      "Manuelle Analyse erforderlich."),
            naechste_schritte=ki.get("naechste_schritte", "1. Befund manuell prüfen."),
            kontext_rows=_format_evidence(getattr(finding, "evidence", None)),
            cve=cve_info,
        )
        story.append(PageBreak())

    story += _build_summary(findings, ctx)
    story.append(PageBreak())

    story += _build_chain_of_custody(ctx)

    doc.build(story, onFirstPage=_add_bg, onLaterPages=_add_bg)
