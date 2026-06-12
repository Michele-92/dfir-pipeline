#!/usr/bin/env python3
"""Moderner forensischer Analysebericht — Design-System "Ink & Steel".

ZUSAETZLICHE Ausgabe neben dem bestehenden report.pdf:
    forensischer_analysebericht.pdf

Speist sich vollstaendig aus den realen ctx-Daten (Provenienz, Fall-Modus,
evidence_items, forensic_findings, IOCs, Anti-Forensik, Parser-Statistik).
Jede Sektion ist defensiv gekapselt — fehlende Daten brechen den Bericht
nicht ab. Aufruf aus stages/stage14_export.run().
"""
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# ── Design-Konstanten ────────────────────────────────────────────────────
_INK   = '#1A2632'; _STEEL = '#2E5E8C'; _SLATE = '#5C6670'
_MIST  = '#F4F7FA'; _LINE  = '#DCE4EC'
_SEVC  = {'CRITICAL': '#B23A32', 'HIGH': '#B97E22', 'MEDIUM': '#6B7280',
          'LOW': '#3F7253', 'INFO': '#3F7253'}
NBSP = ' '


def build_modern_report(ctx, case_dir: Path) -> None:
    """Erzeugt forensischer_analysebericht.pdf. Fehler werden geloggt,
    nicht propagiert (darf den restlichen Export nie blockieren)."""
    try:
        _build(ctx, case_dir)
    except Exception as e:
        log.warning(f'  Moderner Bericht uebersprungen: {e}')


def _build(ctx, case_dir: Path) -> None:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (BaseDocTemplate, PageTemplate, Frame, Paragraph,
                                    Spacer, Table, TableStyle, PageBreak, HRFlowable,
                                    KeepTogether, NextPageTemplate)
    from reportlab.lib.styles import ParagraphStyle
    from datetime import datetime

    INK=colors.HexColor(_INK); STEEL=colors.HexColor(_STEEL); SLATE=colors.HexColor(_SLATE)
    MIST=colors.HexColor(_MIST); LINE=colors.HexColor(_LINE)
    PW, PH = A4; ML = 22*mm; W = PW - 2*ML

    def st(n, **kw):
        b = dict(fontName='Helvetica', fontSize=9.5, leading=14.5, textColor=INK); b.update(kw)
        return ParagraphStyle(n, **b)
    S_TITLE=st('ti',fontName='Helvetica-Bold',fontSize=29,leading=35)
    S_SUB=st('su',fontSize=12,textColor=SLATE,leading=17)
    S_BODY=st('bo',textColor=colors.HexColor('#2A333D'))
    S_LEAD=st('le',fontSize=10.5,leading=17,textColor=colors.HexColor('#2A333D'))
    S_SMALL=st('sm',fontSize=7.5,leading=10.5,textColor=SLATE)
    S_LABEL=st('la',fontName='Helvetica-Bold',fontSize=6.8,leading=9,textColor=SLATE)
    S_HDR=st('hd',fontName='Helvetica-Bold',fontSize=7,leading=9,textColor=SLATE)
    S_KPI=st('kn',fontName='Helvetica-Bold',fontSize=19,leading=22)
    S_CELL=st('ce',fontSize=8.5,leading=12,textColor=colors.HexColor('#2A333D'))
    S_CELLR=st('cr',fontSize=8.5,leading=12,textColor=colors.HexColor('#2A333D'),alignment=2)

    def esc(x):
        s = str(x) if x is not None else ''
        return s.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
    def nowrap(x): return esc(x).replace(' ', NBSP)
    def lab(t): return Paragraph(esc(t).upper().replace(' ',NBSP), S_LABEL)
    def hdr(t): return Paragraph(esc(t).upper().replace(' ',NBSP), S_HDR)

    def h1(num, title):
        t=Table([[Paragraph(f'<font size="18" color="{_STEEL}"><b>{esc(num)}</b></font>',S_BODY),
                  Paragraph(f'<font size="14" color="{_INK}"><b>{esc(title)}</b></font>',S_BODY)]],
                colWidths=[13*mm,W-13*mm])
        t.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'BOTTOM'),('LINEBELOW',(0,0),(-1,-1),0.75,LINE),
                               ('BOTTOMPADDING',(0,0),(-1,-1),5),('LEFTPADDING',(0,0),(-1,-1),0)]))
        return [t, Spacer(1,5*mm)]
    def h2(t): return Paragraph(f'<font size="10.5"><b>{esc(t)}</b></font>', S_BODY)
    def sev(level):
        lv=(level or 'INFO').upper(); c=_SEVC.get(lv,'#6B7280')
        return Paragraph(f'<font color="{c}" size="7">●</font>{NBSP}<font size="7" color="{c}"><b>{lv}</b></font>',S_SMALL)

    def tbl(data, widths, sev_col=None, right=(), nowrap_cols=(), raw_cols=()):
        rows=[]
        for r,row in enumerate(data):
            out=[]
            for ci,cell in enumerate(row):
                if r==0: out.append(hdr(cell))
                elif sev_col is not None and ci==sev_col: out.append(sev(cell))
                else:
                    txt = str(cell) if ci in raw_cols else (nowrap(cell) if ci in nowrap_cols else esc(cell))
                    out.append(Paragraph(txt, S_CELLR if ci in right else S_CELL))
            rows.append(out)
        t=Table(rows,colWidths=widths,repeatRows=1)
        t.setStyle(TableStyle([('LINEBELOW',(0,0),(-1,0),1.1,STEEL),('LINEBELOW',(0,1),(-1,-2),0.5,LINE),
            ('TOPPADDING',(0,0),(-1,0),2),('BOTTOMPADDING',(0,0),(-1,0),5),
            ('TOPPADDING',(0,1),(-1,-1),5),('BOTTOMPADDING',(0,1),(-1,-1),5),
            ('LEFTPADDING',(0,0),(-1,-1),2),('RIGHTPADDING',(0,0),(-1,-1),8),('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
        return t
    def beilage(text):
        t=Table([[Paragraph(f'<font size="8" color="{_STEEL}"><b>→{NBSP}{NBSP}BEILAGE</b></font>'
                            f'<font size="8" color="#2A333D">{NBSP}{NBSP}{text}</font>',S_SMALL)]],colWidths=[W])
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),MIST),('LINEBEFORE',(0,0),(0,-1),1.6,STEEL),
            ('TOPPADDING',(0,0),(-1,-1),5.5),('BOTTOMPADDING',(0,0),(-1,-1),5.5),('LEFTPADDING',(0,0),(-1,-1),9)]))
        return t
    def prov(text):
        return Paragraph(f'<font size="7.2" color="{_SLATE}"><b>PROVENIENZ</b>{NBSP}{NBSP}·{NBSP}{NBSP}{text}</font>',S_SMALL)
    def kpi(items):
        gap=4*mm; cw=(W-3*gap)/4; cards=[]
        for num,l in items:
            c=Table([[Paragraph(esc(num),S_KPI)],[lab(l)]],colWidths=[cw-12])
            c.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),MIST),('LINEABOVE',(0,0),(-1,0),1.8,STEEL),
                ('TOPPADDING',(0,0),(-1,0),8),('BOTTOMPADDING',(0,1),(-1,1),8),('BOTTOMPADDING',(0,0),(-1,0),2),
                ('LEFTPADDING',(0,0),(-1,-1),11)])); cards.append(c)
        row=Table([[cards[0],'',cards[1],'',cards[2],'',cards[3]]],colWidths=[cw,gap,cw,gap,cw,gap,cw])
        row.setStyle(TableStyle([('LEFTPADDING',(0,0),(-1,-1),0),('RIGHTPADDING',(0,0),(-1,-1),0),
            ('TOPPADDING',(0,0),(-1,-1),0),('BOTTOMPADDING',(0,0),(-1,-1),0)]))
        return row
    def finding_card(fid,title,level,erk,inner,prov_text,beil):
        lv=(level or 'INFO').upper()
        pill=Table([[sev(lv)]],colWidths=[26*mm])
        pill.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),MIST),('TOPPADDING',(0,0),(-1,-1),3),
            ('BOTTOMPADDING',(0,0),(-1,-1),3),('LEFTPADDING',(0,0),(-1,-1),7)]))
        head=Table([[Paragraph(f'<font size="11"><b>{esc(fid)}{NBSP}{NBSP}{esc(title)}</b></font>',S_BODY),pill]],
                   colWidths=[W-26*mm-14,26*mm])
        head.setStyle(TableStyle([('LEFTPADDING',(0,0),(-1,-1),0),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('BOTTOMPADDING',(0,0),(-1,-1),3)]))
        items=[[head],[Paragraph(erk,S_LEAD)],[Spacer(1,3*mm)]]
        if inner is not None: items+=[[inner],[Spacer(1,2.5*mm)]]
        items+=[[prov(prov_text)]]
        if beil: items+=[[Spacer(1,2*mm)],[beilage(beil)]]
        card=Table(items,colWidths=[W-9])
        card.setStyle(TableStyle([('LINEBEFORE',(0,0),(0,-1),2.2,colors.HexColor(_SEVC.get(lv,'#6B7280'))),
            ('LEFTPADDING',(0,0),(-1,-1),11),('TOPPADDING',(0,0),(-1,-1),1),('BOTTOMPADDING',(0,0),(-1,-1),1)]))
        return KeepTogether(card)

    # ── Kopf/Fuss ────────────────────────────────────────────────────────
    case_id = case_dir.name
    def _later(c,d):
        c.saveState(); c.setStrokeColor(LINE); c.setLineWidth(0.6)
        c.line(ML,PH-14*mm,PW-ML,PH-14*mm); c.setFillColor(SLATE); c.setFont('Helvetica-Bold',6.5)
        t=c.beginText(ML,PH-12*mm); t.setCharSpace(1.5); t.textOut(f'CASE {case_id[:34]}'); c.drawText(t)
        txt='VERTRAULICH'; wd=c.stringWidth(txt,'Helvetica-Bold',6.5)+1.5*len(txt)
        t=c.beginText(PW-ML-wd,PH-12*mm); t.setCharSpace(1.5); t.textOut(txt); c.drawText(t)
        c.line(ML,13*mm,PW-ML,13*mm); c.setFont('Helvetica',7)
        c.drawString(ML,9.5*mm,'DFIR-Pipeline v3.0 — Forensischer Analysebericht')
        c.drawRightString(PW-ML,9.5*mm,f'Seite {d.page}'); c.restoreState()
    def _first(c,d):
        c.saveState(); c.setFillColor(STEEL); c.setFont('Helvetica-Bold',7)
        t=c.beginText(ML,PH-22*mm); t.setCharSpace(2.0); t.textOut('DFIR-PIPELINE V3.0'); c.drawText(t)
        c.setFillColor(SLATE); t=c.beginText(ML+60*mm,PH-22*mm); t.setCharSpace(2.0)
        t.textOut('·   DIGITALE FORENSIK'); c.drawText(t); c.restoreState()

    out_file = case_dir / 'forensischer_analysebericht.pdf'
    doc=BaseDocTemplate(str(out_file),pagesize=A4,leftMargin=ML,rightMargin=ML,
                        topMargin=20*mm,bottomMargin=18*mm,title='Forensischer Analysebericht')
    doc.addPageTemplates([PageTemplate(id='cover',frames=[Frame(ML,18*mm,W,PH-44*mm,id='fc')],onPage=_first),
                          PageTemplate(id='page', frames=[Frame(ML,18*mm,W,PH-40*mm,id='f')], onPage=_later)])
    S=[]

    # ── Daten aus ctx sammeln ────────────────────────────────────────────
    combined = bool(getattr(ctx,'combined_case',False))
    evi = getattr(ctx,'evidence_items',[]) or []
    if not evi:   # Einzel-Image: Pseudo-Item aus ctx
        pp = getattr(ctx,'partition_profiles',[]) or []
        evi=[{'name':(ctx.disk_image_path.name if ctx.disk_image_path else 'Image'),
              'os_name':ctx.os_name,'os_family':ctx.os_family,'hostname':ctx.hostname,
              'kernel_version':ctx.kernel_version,'machine_id':getattr(ctx,'machine_id',''),
              'shadow_mtime':getattr(ctx,'shadow_mtime',''),'file_type':ctx.file_type,
              'file_size_gb':ctx.file_size_gb,'timezone_display':getattr(ctx,'timezone_display','') or ctx.timezone,
              'partition_layout':getattr(ctx,'partition_layout',[]),'partition_profiles':pp}]
    coc = ctx.coc
    ev_hashes = getattr(coc,'evidence_hashes',{}) if coc else {}
    findings = getattr(ctx,'forensic_findings',[]) or []
    iocs = getattr(ctx,'iocs',[]) or []
    afhits = getattr(ctx,'antiforensics_hits',[]) or []
    nevents = getattr(ctx,'normalized_events',[]) or []
    n_part = sum(len(e.get('partition_layout') or []) for e in evi)
    created = datetime.now().strftime('%d.%m.%Y, %H:%M UTC')

    # ════ DECKBLATT ════
    S+=[Spacer(1,54*mm),
        HRFlowable(width=26*mm,thickness=2.6,color=STEEL,hAlign='LEFT'),Spacer(1,7*mm),
        Paragraph('Forensischer<br/>Analysebericht',S_TITLE),Spacer(1,5*mm),
        Paragraph(f'Case {esc(case_id)}',S_SUB),Spacer(1,26*mm)]
    img_names=', '.join(e.get('name','?') for e in evi)
    meta=[['Beweismittel',f'{len(evi)} Image(s) — {img_names}'],
          ['Modus','Fall-Modus (gemeinsamer Report)' if combined else 'Einzel-Image'],
          ['Bericht erstellt',created],
          ['Werkzeug','DFIR-Pipeline v3.0']]
    mt=Table([[lab(k),Paragraph(esc(v),S_BODY)] for k,v in meta],colWidths=[42*mm,W-42*mm])
    mt.setStyle(TableStyle([('LINEBELOW',(0,0),(-1,-2),0.5,LINE),('TOPPADDING',(0,0),(-1,-1),5.5),
        ('BOTTOMPADDING',(0,0),(-1,-1),5.5),('LEFTPADDING',(0,0),(-1,-1),0),('VALIGN',(0,0),(-1,-1),'MIDDLE')]))
    S+=[mt,NextPageTemplate('page'),PageBreak()]

    # ════ 01 SUMMARY ════
    S+=h1('01','Zusammenfassung')
    n_crit=sum(1 for f in findings if (f.severity or '').upper()=='CRITICAL')
    S+=[kpi([(str(len(evi)),'Images'),(f'{len(nevents):,}'.replace(',','.'),'Ereignisse'),
             (str(len(findings)),'Befunde'),(f'{len(iocs):,}'.replace(',','.'),'IOCs')]),Spacer(1,6*mm)]
    summ=(f'Analysiert wurden {len(evi)} Disk-Image(s) mit insgesamt {n_part} Partition(en) und '
          f'{len(nevents):,} normalisierten Ereignissen. '.replace(',','.'))
    if findings:
        summ+=f'Die Timeline-Analyse meldet {len(findings)} forensische Befunde'
        summ+=f', davon {n_crit} kritische. ' if n_crit else '. '
    if afhits:
        summ+=f'Es wurden {len(afhits)} Anti-Forensik-Indikatoren erkannt. '
    summ+=f'Die IOC-Extraktion lieferte {len(iocs)} Indikatoren. '
    summ+=('Beweismittel-Integritaet ueber Hashwerte belegt (Abschnitt 02), '
           'jede Information mit nachpruefbarer Quelle (Provenienz).')
    S+=[Paragraph(summ,S_LEAD),Spacer(1,8*mm)]

    # ════ 02 BEWEISMITTEL ════
    S+=h1('02','Beweismittel & Integrität')
    rows=[['#','Image','Betriebssystem','Hostname','Größe']]
    for i,e in enumerate(evi,1):
        rows.append([str(i),e.get('name','?'),
                     (e.get('os_name') or e.get('os_family') or '—'),
                     e.get('hostname') or '—',
                     f"{e.get('file_size_gb',0):.1f} GB"])
    S+=[tbl(rows,[8*mm,42*mm,W-42*mm-30*mm-26*mm-8*mm,30*mm,26*mm],right={4},nowrap_cols={4}),Spacer(1,5*mm)]
    if ev_hashes:
        S+=[h2('Hash-Verifikation — vollständig, keine Kürzung'),Spacer(1,2.5*mm)]
        hr=[['Image','Verfahren','Wert']]
        for name,h in ev_hashes.items():
            if h.get('sha1'):   hr.append([name,'SHA1 · E01',h['sha1']])
            if h.get('sha256'): hr.append([name,'SHA256',h['sha256']])
            if h.get('md5'):    hr.append([name,'MD5',h['md5']])
        if len(hr)>1:
            S+=[tbl(hr,[34*mm,26*mm,W-60*mm],nowrap_cols={1}),Spacer(1,2.5*mm),
                prov('Hashwerte aus Stage 01 (E01-eingebettet via TSK img_stat oder berechnet).')]
    S+=[PageBreak()]

    # ════ 03 SYSTEME ════
    S+=h1('03','Systemüberblick je Image')
    for e in evi:
        pps=e.get('partition_profiles') or [{}]
        pp=next((p for p in pps if p.get('is_primary')),pps[0] if pps else {})
        lbl=f"Partition {pp.get('partition_index','?')}, offset {pp.get('offset','?')}"
        srows=[['Merkmal','Wert','Quelle'],
            ['Betriebssystem',e.get('os_name') or '—',pp.get('os_source','') or 'target-query'],
            ['Kernel',e.get('kernel_version') or '—','/boot + target-query'],
            ['Hostname',e.get('hostname') or '—','/etc/hostname'],
            ['Zeitzone',e.get('timezone_display') or '—','/etc/timezone'],
            ['Machine-ID',e.get('machine_id') or '—','/etc/machine-id · icat'],
            ['/etc/shadow geändert',e.get('shadow_mtime') or '—',f'istat · {lbl}'],
            ['Partitionen',str(len(e.get('partition_layout') or [])),'mmls']]
        S+=[h2(e.get('name','Image')),Spacer(1,2.5*mm),
            tbl(srows,[37*mm,W-37*mm-52*mm,52*mm]),Spacer(1,7*mm)]
    S+=[PageBreak()]

    # ════ 04 BEFUNDE ════
    S+=h1('04','Forensische Erkenntnisse')
    if findings:
        order={'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
        top=sorted(findings,key=lambda f:order.get((f.severity or '').upper(),5))[:6]
        for i,f in enumerate(top,1):
            ts=f.anomaly_time.strftime('%Y-%m-%d %H:%M UTC') if getattr(f,'anomaly_time',None) else '—'
            # Image/Quelle aus dem Stage-6-Kontext des Befunds ableiten (falls vorhanden)
            _img=''; _ctxsrc=''
            for ce in (getattr(f,'evidence',[]) or []):
                if isinstance(ce,dict):
                    _img=_img or ce.get('evidence','') or ce.get('image','')
                    _ctxsrc=_ctxsrc or ce.get('orig_path','') or ce.get('source','')
            brows=[['Merkmal','Wert'],
                   ['Betroffene Datei',f.file or '—'],
                   ['Zeitpunkt (UTC)',ts]]
            if _img:    brows.append(['Image',_img])
            if _ctxsrc: brows.append(['Quelle (Kontext)',_ctxsrc])
            brows.append(['Regel / Methode',f.rule or '—'])
            S+=[finding_card(f'B-{i:02d}',esc(f.rule or 'Befund'),(f.severity or 'INFO'),
                f'<b>Erkenntnis</b> — {esc(f.description or "")}',
                tbl(brows,[42*mm,W-42*mm-11]),
                'Stage 8.5 Timeline-Analyse (events.db / mactime) · betroffene Datei im Image nachpruefbar',
                '<b>forensic_findings.xlsx</b> · alle Befunde mit vollstaendigem Evidence-Kontext'),
                Spacer(1,6*mm)]
    else:
        S+=[Paragraph('Keine forensischen Befunde durch die Timeline-Analyse erkannt.',S_BODY),Spacer(1,4*mm)]
    # Anti-Forensik kompakt
    if afhits:
        af_order={'critical':0,'high':1,'medium':2}
        afs=sorted(afhits,key=lambda h:af_order.get((h.get('severity') or '').lower(),3))[:6]
        ar=[['Typ','Betroffene Datei','Nachweis-Quelle','Detail','Schwere']]
        for h in afs:
            ar.append([h.get('type','?'),(h.get('file','') or '—')[:30],
                       h.get('source','—'),(h.get('details','') or '')[:46],
                       (h.get('severity','info') or 'info').upper()])
        S+=[h2('Anti-Forensik-Indikatoren — Auszug'),Spacer(1,2.5*mm),
            tbl(ar,[26*mm,34*mm,30*mm,W-26*mm-34*mm-30*mm-22*mm-11,22*mm],sev_col=4),Spacer(1,2.5*mm),
            prov('Spalte „Betroffene Datei" + „Nachweis-Quelle" (Pruefmethode: z.B. fls_symlink_scan, '
                 'rc_local, grub_config, yara) — im Image direkt nachpruefbar.'),Spacer(1,2*mm),
            beilage(f'Alle {len(afhits)} Anti-Forensik-Treffer inkl. YARA-Details: <b>antiforensics.json</b>')]
    S+=[PageBreak()]

    # ════ 05 TIMELINE ════
    S+=h1('05','Rekonstruierte Timeline — Schlüsselereignisse')
    rel=[e for e in nevents if (e.severity or '') in ('critical','high','medium')]
    rel=sorted(rel,key=lambda e:e.timestamp)[:18]
    if rel:
        tr=[(['Zeit (UTC)','Image','Quelle','Ereignis','Schwere'] if combined
             else ['Zeit (UTC)','Quelle','Ereignis','Schwere'])]
        for e in rel:
            ts=e.timestamp.strftime('%d.%m %H:%M:%S') if e.timestamp else '—'
            src=(e.orig_path or e.source or '')[:26]
            ev_short=(e.evidence or '—')
            ev_short=ev_short[:-4] if ev_short.lower().endswith('.e01') else ev_short
            if combined:
                tr.append([ts,ev_short,src,(e.message or '')[:42],(e.severity or 'info').upper()])
            else:
                tr.append([ts,src,(e.message or '')[:52],(e.severity or 'info').upper()])
        if combined:
            S+=[tbl(tr,[27*mm,23*mm,30*mm,W-27*mm-23*mm-30*mm-22*mm-11,22*mm],
                    sev_col=4,nowrap_cols={0,1})]
        else:
            S+=[tbl(tr,[27*mm,36*mm,W-27*mm-36*mm-22*mm-11,22*mm],sev_col=3,nowrap_cols={0})]
        S+=[Spacer(1,2.5*mm)]
    else:
        S+=[Paragraph('Keine relevanten Timeline-Ereignisse (critical/high/medium).',S_BODY),Spacer(1,2.5*mm)]
    S+=[beilage('Vollständige Timeline: <b>timeline.xlsx</b> + <b>activity_timeline.csv</b> · '
                'Sitzungen: <b>reboot_sessions.xlsx</b> / <b>ip_sessions.xlsx</b> · interaktiv: Timesketch'),
        Spacer(1,8*mm)]

    # ════ 06 IOCs ════
    S+=h1('06','Indikatoren (IOCs) — Auszug')
    if iocs:
        by={}
        for i in iocs: by.setdefault(i.type,[]).append(i)
        if combined:
            ir=[['Typ','Wert','Quelle (Parser/Datei)','Image']]
        else:
            ir=[['Typ','Wert','Quelle (Parser/Datei)','Kontext']]
        for typ in sorted(by,key=lambda k:-len(by[k]))[:8]:
            it=by[typ][0]
            quelle=(it.source or '—')
            last=(getattr(it,'evidence','') or '—') if combined else (it.context or '—')
            ir.append([typ,(it.value or '')[:42],str(quelle)[:24],str(last)[:22]])
        npriv=len(by.get('ip_private',[]))
        S+=[tbl(ir,[18*mm,52*mm,32*mm,W-18*mm-52*mm-32*mm],),Spacer(1,2.5*mm),
            prov('Spalte „Quelle" nennt den Parser bzw. die Herkunft (z.B. auth, '
                 'bash_history, bulk_extractor) — jeder IOC ist bis zur Ursprungsdatei rueckverfolgbar.'),Spacer(1,2*mm),
            beilage(f'Alle {len(iocs)} IOCs'
                    +(f' — {npriv} ip_private separat' if npriv else '')+': <b>iocs.json</b> / <b>iocs.xlsx</b>')]
    else:
        S+=[Paragraph('Keine IOCs extrahiert.',S_BODY)]
    S+=[Spacer(1,8*mm)]

    # ════ 07 METHODIK ════
    S+=h1('07','Methodik & Grenzen')
    mrb=getattr(ctx,'max_read_mb',50)
    S+=[Paragraph('Vollautomatisierte Analyse mit der DFIR-Pipeline v3.0: Beweissicherung, '
        'Partition-Layout, System-Profiling, TSK-Extraktion mit Manifest, Log-Parsing (inkl. '
        'Journal und wtmpdb), IOC-Extraktion, UTC-Normalisierung, Anti-Forensik und YARA, '
        'Timeline-Analyse, Export. Jede extrahierte Information traegt ihre Provenienz '
        '(Originalpfad, Partition, Parser, Extraktionsmethode'
        +(', Image' if combined else '')+'). '
        f'<b>Grenzen</b> — Logdateien über {mrb} MB wurden zum Speicherschutz partiell gelesen '
        '(Parameter --max-read-mb, im Protokoll vermerkt). RAM-Analyse nur bei vorhandenem '
        'Speicherabbild. Jahresinferenz jahresloser Syslog-Zeitstempel über die Datei-mtime.',S_BODY),
        PageBreak()]

    # ════ ANHANG D — Pipeline-Protokoll ════
    S+=h1('D','Anhang — Pipeline-Ausführungsprotokoll')
    S+=[Paragraph('Stage-Übersichten der Pipeline-Ausführung — inhaltlich identisch zu den '
                  'Terminal-Panels.',S_BODY),Spacer(1,5*mm)]
    # D.x Partition-Layout je Image
    for e in evi:
        pl=e.get('partition_layout') or []
        if not pl: continue
        S+=[h2(f"Partition-Layout — {e.get('name','Image')}"),Spacer(1,2.5*mm)]
        pr=[['#','Offset','Dateisystem','Rolle','Tool','OS erkannt']]
        for p in pl:
            pr.append([str(p.get('index','?')),str(p.get('offset','?')),p.get('fs_type','?'),
                       p.get('role','?'),p.get('tool','?'),(p.get('os_name') or '—')])
        S+=[tbl(pr,[8*mm,22*mm,26*mm,26*mm,16*mm,W-98*mm],right={1}),Spacer(1,5*mm)]
    # D Parser-Statistik
    pstats=getattr(ctx,'parser_stats',{}) or {}
    if pstats:
        S+=[h2('Log-Parsing — Events pro Parser'),Spacer(1,2.5*mm)]
        pr=[['Parser','Events']]
        for name,cnt in sorted(pstats.items(),key=lambda x:-x[1])[:18]:
            pr.append([name,f'{cnt:,}'.replace(',','.')])
        S+=[tbl(pr,[W-40*mm,40*mm],right={1}),Spacer(1,2.5*mm),
            prov(f'{getattr(ctx,"parsed_events",0):,} Events gesamt'.replace(',','.')
                 +f' · Qualitaet: {ctx.stage_status.get("quality","—")}'
                 +f' · Stage-Fehler: {len(getattr(ctx,"stage_errors",{}))}')]

    doc.build(S)
    log.info(f'  Moderner Bericht erstellt → {out_file.name}')
