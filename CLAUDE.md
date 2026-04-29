# CLAUDE.md – Bachelorarbeit Projektordner

## Wichtige Pfade
- Dieses Projekt: Aktueller Ordner
- Obsidian Vault: `C:\Users\miche\Desktop\Obsidian-SB`
- Tageslog Ziel: `C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\bachelorarbeit\tageslog\`
- Overview Datei: `C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\bachelorarbeit\overview.md`
- Skill Vorlage: `C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\skills\bachelor-log.md`

---

## Session-Start – automatisch beim Start

Beim Start liest du folgende Dateien in dieser Reihenfolge:

1. Lies `C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\bachelorarbeit\overview.md`
   → Verstehe das Thema, den aktuellen Status und den nächsten Meilenstein
2. Suche den neuesten Eintrag in `C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\bachelorarbeit\tageslog\`
   → Lies ihn komplett durch
3. Begrüße mich mit:
   - Thema der Bachelorarbeit in einem Satz
   - Was wir zuletzt gemacht haben
   - Wo wir aufgehört haben
   - Was als nächstes ansteht
   - Offene Probleme vom letzten Mal

Beispiel Begrüßung:
> "Willkommen zurück! Zuletzt haben wir [X] implementiert.
> Offen ist noch [Y]. Weitermachen?"

---

## Während der Session – laufend im Hintergrund

Während wir arbeiten merkst du dir automatisch:

- Jede Python Datei die erstellt oder verändert wurde
- Jeden Fehler der aufgetaucht ist und wie er gelöst wurde
- Jede wichtige Entscheidung die getroffen wurde
- Jeden Ansatz der nicht funktioniert hat
- Jeden neuen Gedanken oder jede neue Idee
- Den aktuellen Stand des Codes am Ende

Du musst das nicht zeigen – nur intern merken für die Session-Summary.

---

## Session speichern – wenn ich "Session speichern" sage

### Schritt 1 – Lies die Skill-Vorlage
Öffne: `C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\skills\bachelor-log.md`
Verwende exakt dieses Format für die Summary.

### Schritt 2 – Erstelle die Tages-Summary
Speichere die fertige Summary unter:
`C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\bachelorarbeit\tageslog\YYYY-MM-DD.md`

Wobei YYYY-MM-DD das heutige Datum ist – z.B. `2025-04-21.md`

Fülle jeden Abschnitt präzise aus:
- Nur konkrete Fakten – keine vagen Aussagen
- Jede veränderte Python Datei mit genauem Namen
- Jeden Fehler mit der exakten Fehlermeldung
- Jeden gelösten Bug mit der genauen Lösung
- Offene Punkte klar markieren

### Schritt 3 – Aktualisiere die Overview
Öffne: `C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\bachelorarbeit\overview.md`
Aktualisiere folgende Felder:
- Letzte Session: DATUM
- Gesamtfortschritt: [aktueller Stand in 1-2 Sätzen]
- Nächster Meilenstein: [was kommt als nächstes]

### Schritt 4 – Bestätigung
Sage mir exakt:
> "✅ Session gespeichert:
> → bachelorarbeit/tageslog/DATUM.md erstellt
> → overview.md aktualisiert
> Morgen einfach Claude starten und weitermachen!"

---

## Wie Claude mit mir kommuniziert

- Direkt und technisch präzise – kein Smalltalk
- Bei Python Fehlern: immer die genaue Fehlermeldung zeigen
- Bei Entscheidungen: kurz zwei Optionen nennen und auf meine Wahl warten
- Sprache: Deutsch

---

## Wichtige Regeln

- Niemals Code löschen ohne meine ausdrückliche Erlaubnis
- Vor großen Änderungen kurz fragen: "Soll ich X machen?"
- Immer den vollständigen Code zeigen – keine Auslassungen mit "..."
- Wenn etwas unklar ist: fragen statt raten

## Wichtige Regel bei mehreren Sessions pro Tag

Wenn ich "Session speichern" sage, prüfe zuerst:

- Schritt 1 – Prüfe ob heute bereits eine Datei existiert:
C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\bachelorarbeit\tageslog\YYYY-MM-DD.md

- Schritt 2 – Entscheide:

- FALL A – Datei existiert NICHT:
→ Erstelle neue Datei unter:
   C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\bachelorarbeit\tageslog\YYYY-MM-DD.md
→ Verwende das komplette Format aus:
   C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\skills\bachelor-log.md

- FALL B – Datei existiert BEREITS:
→ Öffne die bestehende Datei unter:  C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\bachelorarbeit\tageslog\YYYY-MM-DD.md
→ Schreibe NIEMALS den bestehenden Inhalt um oder auch nicht überschreiben
→ Zähle wie viele Sessions bereits drin sind
→ Füge am Ende einen neuen Abschnitt hinzu:
### Session [Nummer] – HH:MM Uhr
→ Verwende dasselbe Format wie in bachelor-log.md
   aber nur für diese Session – nicht den ganzen Tag nochmal
  am Ende hinzu. Niemals überschreiben.

---
 
## Rückblick auf Anfrage
 
Wenn ich eine der folgenden Fragen stelle:
- "Was haben wir gestern gemacht?"
- "Was haben wir heute gemacht?"
- "Was haben wir zuletzt gemacht?"
- "Wo haben wir aufgehört?"
- "Was haben wir letzte Woche gemacht?"
- "Was haben wir am [DATUM] gemacht?"
- "Zeig mir was wir am [DATUM] gemacht haben"
### Schritt 1 – Bestimme welche Datei gesucht wird
- "gestern" → suche Datei mit gestriger Datum z.B. `2025-04-20.md`
- "zuletzt" / "aufgehört" → suche die neueste Datei im Ordner
- "letzte Woche" → suche alle Dateien der letzten 7 Tage
- "am [DATUM]" → suche exakt diese Datei z.B. `2025-04-15.md`
### Schritt 2 – Suche im Tageslog Ordner
Alle Dateien liegen unter:
`C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\bachelorarbeit\tageslog\`
 
Dateiformat ist immer: `YYYY-MM-DD.md`
Beispiele: `2025-04-21.md`, `2025-04-20.md`, `2025-04-14.md`
 
Falls die gesuchte Datei nicht existiert sage mir:
> "Für [DATUM] gibt es keinen Eintrag. Der nächste verfügbare Eintrag ist [DATUM]."
 
### Schritt 3 – Lies die gefundene Datei komplett durch
 
### Schritt 4 – Antworte mit exakt dieser Struktur:
 
─────────────────────────────────────
📋 Rückblick: [DATUM]
─────────────────────────────────────
 
✅ ERLEDIGT:
• [Was konkret fertig wurde]
• [Was konkret fertig wurde]
 
🐍 VERÄNDERTE PYTHON DATEIEN:
• [Dateiname.py] → [Was wurde geändert]
• [Dateiname.py] → [Was wurde geändert]
 
🐛 PROBLEME & LÖSUNGEN:
• Problem: [Fehlermeldung]
  Lösung: [Was hat geholfen]
• Problem: [Fehlermeldung]
  Lösung: [Was hat geholfen]
 
🔄 NOCH OFFEN:
• [Was nicht fertig wurde]
• [Was noch aussteht]
 
🔜 NÄCHSTER GEPLANTER SCHRITT:
• [Genau womit wir weitermachen sollten]
 
⚠️ WICHTIGER KONTEXT:
• [Was ich unbedingt wissen muss]
 
─────────────────────────────────────
 
### Sonderfall – "letzte Woche"
Falls ich nach der letzten Woche frage:
- Lies alle vorhandenen Dateien der letzten 7 Tage
- Fasse sie zusammen in einer Gesamtübersicht
- Zeige pro Tag eine Kurzzeile was gemacht wurde
- Hebe das Wichtigste der ganzen Woche hervor

---

## Zwischenspeichern – wenn ich "Zwischenspeichern" sage

Das ist KEIN neuer Session-Abschnitt.
Das ist eine Aktualisierung der laufenden Session.

Schritt 1 – Prüfe ob heute bereits eine Datei existiert:
C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\bachelorarbeit\tageslog\YYYY-MM-DD.md

FALL A – Datei existiert NICHT:
→ Erstelle sie neu mit dem kompletten Format aus:
   C:\Users\miche\Desktop\Obsidian-SB\Second-Brain-OS\skills\bachelor-log.md

FALL B – Datei existiert BEREITS:
→ Öffne die letzte vorhandene Session in der Datei
→ Erstelle KEINEN neuen Abschnitt
→ Aktualisiere NUR die folgenden Felder
   der laufenden Session mit neuen Informationen:
   - ✅ Heute erledigt
   - 🐍 Python Änderungen
   - 🐛 Probleme & Lösungen
   - 🔜 Nächste Schritte
   - ⚠️ Wichtiger Kontext
→ Niemals löschen was bereits drin steht
→ Nur neue Informationen ergänzen die seit
   dem letzten Speichern dazugekommen sind

Bestätigung danach:
"💾 Zwischengespeichert – Session läuft weiter"