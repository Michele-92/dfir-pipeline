#!/usr/bin/env bash
# Lädt alle externen Daten herunter — einmalig auf Ubuntu 22.04 ausführen
# Verwendung: cd dfir_pipeline && bash data/setup_data.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== DFIR Pipeline — Daten-Setup ==="

# 1. MITRE ATT&CK v15 (~80 MB)
if [ ! -f "enterprise-attack-v15.json" ]; then
    echo "[1/4] Lade MITRE ATT&CK v15..."
    wget -q --show-progress \
        -O enterprise-attack-v15.json \
        https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
    echo "  MITRE ATT&CK v15 gespeichert."
else
    echo "[1/4] MITRE ATT&CK v15 bereits vorhanden — übersprungen."
fi

# 2. YARA Community-Regeln
if [ ! -d "yara-rules/community/.git" ]; then
    echo "[2/4] Klone YARA Community-Regeln..."
    rm -rf yara-rules/community
    git clone --depth=1 \
        https://github.com/Yara-Rules/rules \
        yara-rules/community
    echo "  YARA Community-Regeln gespeichert."
else
    echo "[2/4] YARA Community-Regeln bereits vorhanden — übersprungen."
fi

# 3. Signature-Base (Florian Roth)
if [ ! -d "yara-rules/signature-base/.git" ]; then
    echo "[3/4] Klone Signature-Base..."
    rm -rf yara-rules/signature-base
    git clone --depth=1 \
        https://github.com/Neo23x0/signature-base \
        yara-rules/signature-base
    echo "  Signature-Base gespeichert."
else
    echo "[3/4] Signature-Base bereits vorhanden — übersprungen."
fi

# 4. Sigma-Regeln (SigmaHQ)
if [ ! -d "sigma-rules/.git" ]; then
    echo "[4/4] Klone Sigma-Regeln..."
    rm -rf sigma-rules
    git clone --depth=1 \
        https://github.com/SigmaHQ/sigma \
        sigma-rules
    echo "  Sigma-Regeln gespeichert."
else
    echo "[4/4] Sigma-Regeln bereits vorhanden — übersprungen."
fi

echo ""
echo "=== Setup abgeschlossen ==="
echo "Inhalt von data/:"
ls -lh .
