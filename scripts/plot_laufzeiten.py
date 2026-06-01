"""
plot_laufzeiten.py
------------------
Erzeugt ein Tortendiagramm der Stage-Laufzeiten aus dem DFIR-Pipeline-Testdurchlauf.
Ausgabe: laufzeiten_diagramm.png (300 DPI, weißer Hintergrund)

Verwendung:
    python scripts/plot_laufzeiten.py
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# ── Laufzeiten in Sekunden (Testdurchlauf 2026-05-31) ──────────────────────────
LAUFZEITEN = {
    'Stage 06\nProtokollanayse (38 Parser)': 4885,   # 81:25
    'Stage 07\nIOC-Extraktion':              1831,   # 30:31
    'Stage 03\nSystem-Profiling':            1031,   # 17:11
    'Stage 14\nExport & Archivierung':        277,   # 04:37
    'Stage 05\nDisk-Forensik':                255,   # 04:15
    'Stage 08\nDatennormalisierung':          198,   # 03:18
    'Übrige Stages\n(01, 02, 03.5, 09, 8.5, 13)': 138,  # Rest
}

# ── Farben ─────────────────────────────────────────────────────────────────────
FARBEN = [
    '#1B3A5C',   # Stage 06 — dunkelblau (dominiert)
    '#2E6DA4',   # Stage 07 — mittelblau
    '#4A90C4',   # Stage 03 — hellblau
    '#6BAED6',   # Stage 14 — blau-grau
    '#9ECAE1',   # Stage 05 — hellblau
    '#C6DBEF',   # Stage 08 — sehr hell
    '#CCCCCC',   # Übrige   — grau
]

# ── Diagramm ───────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(9, 6), facecolor='white')

labels  = list(LAUFZEITEN.keys())
values  = list(LAUFZEITEN.values())
gesamt  = sum(values)

# Explode für Stage 06 (leicht herausziehen)
explode = [0.04 if i == 0 else 0 for i in range(len(values))]

wedges, texts, autotexts = ax.pie(
    values,
    labels=None,
    autopct=lambda p: f'{p:.1f} %' if p > 2 else '',
    startangle=140,
    colors=FARBEN,
    explode=explode,
    pctdistance=0.75,
    wedgeprops={'linewidth': 1.2, 'edgecolor': 'white'},
)

# Prozentbeschriftung formatieren
for at in autotexts:
    at.set_fontsize(10)
    at.set_fontweight('bold')
    at.set_color('white')

# ── Legende ────────────────────────────────────────────────────────────────────
def sek_zu_mmss(sekunden):
    m, s = divmod(int(sekunden), 60)
    return f'{m:02d}:{s:02d} min'

legende_labels = [
    f'{lbl.replace(chr(10), " ")}  —  {sek_zu_mmss(val)}  ({val/gesamt*100:.1f} %)'
    for lbl, val in zip(labels, values)
]

patches = [
    mpatches.Patch(color=FARBEN[i], label=legende_labels[i])
    for i in range(len(labels))
]

ax.legend(
    handles=patches,
    loc='center left',
    bbox_to_anchor=(1.02, 0.5),
    fontsize=9,
    frameon=True,
    framealpha=0.95,
    edgecolor='#CCCCCC',
)

# ── Titel & Untertitel ─────────────────────────────────────────────────────────
ax.set_title(
    'Laufzeitverteilung der DFIR-Pipeline',
    fontsize=14,
    fontweight='bold',
    pad=18,
    color='#0D1B2A',
)
fig.text(
    0.5, 0.01,
    f'Gesamtlaufzeit: 143 Min 35 Sek  |  Testimage: starkskunk5.E01  |  40 GB Alpine Linux v3.15',
    ha='center',
    fontsize=8,
    color='#555555',
)

plt.tight_layout()

# ── Speichern ─────────────────────────────────────────────────────────────────
ausgabe = 'laufzeiten_diagramm.png'
plt.savefig(ausgabe, dpi=300, bbox_inches='tight', facecolor='white')
print(f'✅ Gespeichert: {ausgabe}')
plt.show()
