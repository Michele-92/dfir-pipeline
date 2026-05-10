"""
ki_text_generator.py  —  Multi-Provider
----------------------------------------
Unterstützt drei LLM-Provider:
  - Anthropic  (Claude)
  - Mistral    (Mistral API)
  - Ollama     (lokales Modell)

Konfiguration über Umgebungsvariablen:
  LLM_PROVIDER=ollama          # Default für VM-Betrieb
  ANTHROPIC_API_KEY=sk-ant-...
  MISTRAL_API_KEY=...
  OLLAMA_BASE_URL=http://localhost:11434   # optional, Default
  OLLAMA_MODEL=llama3.1:8b                # optional, Default
"""

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Optional

log = logging.getLogger(__name__)

def _finding_key(finding) -> str:
    """
    Eindeutiger Key pro Finding — verhindert Key-Kollision wenn zwei
    CRITICAL-Befunde dieselbe Datei betreffen (z.B. /etc/passwd).
    Identisch in report_builder.py um konsistente Zuordnung zu garantieren.
    """
    ts = ""
    if getattr(finding, "anomaly_time", None):
        ts = finding.anomaly_time.strftime("%Y%m%d%H%M%S")
    return f"{finding.file}::{finding.rule}::{ts}"


# ══════════════════════════════════════════════════════════════════════════════
#  PROVIDER-ABSTRAKTION
# ══════════════════════════════════════════════════════════════════════════════

class LLMProvider(ABC):
    SYSTEM_PROMPT = (
        "Du bist ein erfahrener DFIR-Analyst (Digital Forensics and Incident Response). "
        "Erklaere forensische Befunde praezise fuer Analysten und nicht-technische Empfaenger. "
        "Antworte ausschliesslich mit validem JSON, ohne Markdown-Backticks, ohne Praeambel."
    )

    @abstractmethod
    def complete(self, prompt: str) -> str: ...

    def name(self) -> str:
        return self.__class__.__name__


# ── Provider 1: Anthropic ─────────────────────────────────────────────────────

class AnthropicProvider(LLMProvider):
    """
    pip install anthropic
    Umgebungsvariable: ANTHROPIC_API_KEY
    """
    def __init__(self, model: str = "claude-sonnet-4-5"):
        import anthropic
        self.client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self.model = model

    def complete(self, prompt: str) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=self.SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text.strip()

    def name(self) -> str:
        return f"Anthropic ({self.model})"


# ── Provider 2: Mistral ───────────────────────────────────────────────────────

class MistralProvider(LLMProvider):
    """
    pip install mistralai
    Umgebungsvariable: MISTRAL_API_KEY
    """
    def __init__(self, model: str = "mistral-large-latest"):
        from mistralai import Mistral
        self.client = Mistral(api_key=os.environ["MISTRAL_API_KEY"])
        self.model = model

    def complete(self, prompt: str) -> str:
        response = self.client.chat.complete(
            model=self.model,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
        )
        return response.choices[0].message.content.strip()

    def name(self) -> str:
        return f"Mistral ({self.model})"


# ── Provider 3: Ollama (lokal) ────────────────────────────────────────────────

class OllamaProvider(LLMProvider):
    """
    Kein pip-Paket noetig — nutzt nur requests.

    Ollama starten:  ollama serve
    Modell laden:    ollama pull llama3.1:8b

    Umgebungsvariablen (optional):
      OLLAMA_BASE_URL=http://localhost:11434
      OLLAMA_MODEL=llama3.1:8b
    """
    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None):
        import requests
        self._requests = requests
        self.model    = model    or os.environ.get("OLLAMA_MODEL",    "llama3.1:8b")  # Fix: war "llama3"
        self.base_url = base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        self.url      = f"{self.base_url}/api/chat"

    def complete(self, prompt: str) -> str:
        payload = {
            "model":   self.model,
            "stream":  False,
            "options": {"temperature": 0.2},
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
        }
        response = self._requests.post(self.url, json=payload, timeout=120)
        response.raise_for_status()
        return response.json()["message"]["content"].strip()

    def name(self) -> str:
        return f"Ollama ({self.model} @ {self.base_url})"


# ══════════════════════════════════════════════════════════════════════════════
#  FACTORY — liest LLM_PROVIDER aus der Umgebung
# ══════════════════════════════════════════════════════════════════════════════

def get_provider() -> LLMProvider:
    """
    export LLM_PROVIDER=ollama     →  OllamaProvider  (Default für VM)
    export LLM_PROVIDER=anthropic  →  AnthropicProvider
    export LLM_PROVIDER=mistral    →  MistralProvider
    """
    name = os.environ.get("LLM_PROVIDER", "ollama").lower()  # Fix: war "anthropic"

    if name == "anthropic":
        return AnthropicProvider(
            model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")
        )
    elif name == "mistral":
        return MistralProvider(
            model=os.environ.get("MISTRAL_MODEL", "mistral-large-latest")
        )
    elif name == "ollama":
        return OllamaProvider()
    else:
        raise ValueError(f"Unbekannter Provider: '{name}'. Erlaubt: anthropic, mistral, ollama")


# ══════════════════════════════════════════════════════════════════════════════
#  KERN-LOGIK
# ══════════════════════════════════════════════════════════════════════════════

def generate_finding_texts(finding, provider: Optional[LLMProvider] = None) -> dict:
    if provider is None:
        provider = get_provider()
    try:
        raw = provider.complete(_build_prompt(finding))
        raw = raw.replace("```json", "").replace("```", "").strip()
        result = json.loads(raw)
        for key in ("warum_critical", "was_bedeutet", "naechste_schritte"):
            if key not in result or not result[key]:
                raise ValueError(f"Fehlendes Feld: {key}")
        log.info(f"  [{provider.name()}] OK: {finding.file[:50]}")
        return result
    except Exception as e:
        log.warning(f"  [{provider.name()}] Fehler: {e} — Fallback")
        return _fallback_texts(finding)


def generate_all_critical_texts(findings: list,
                                 provider: Optional[LLMProvider] = None,
                                 delay_seconds: float = 0.5) -> dict:
    if provider is None:
        provider = get_provider()
    critical = [f for f in findings if f.severity == "CRITICAL"]
    log.info(f"  [{provider.name()}] {len(critical)} CRITICAL-Befunde")
    result = {}
    for i, finding in enumerate(critical):
        result[_finding_key(finding)] = generate_finding_texts(finding, provider)
        if i < len(critical) - 1 and delay_seconds > 0:
            time.sleep(delay_seconds)
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  PROMPT & FALLBACK
# ══════════════════════════════════════════════════════════════════════════════

def _build_prompt(finding) -> str:
    kontext_str = "Kein Kontext verfuegbar."
    if getattr(finding, "evidence", None):
        zeilen = [
            f"  {ev.get('time','?')}  [{ev.get('source','?')}]  "
            f"{ev.get('message','')[:100]}  {ev.get('user') or ''}".rstrip()
            for ev in finding.evidence[:5]
        ]
        kontext_str = "\n".join(zeilen)

    ts_info = ""
    if getattr(finding, "anomaly_time", None):
        ts_info = f"Anomalie-Zeitpunkt: {finding.anomaly_time.strftime('%Y-%m-%d %H:%M:%S UTC')}"

    return f"""Analysiere diesen CRITICAL-Befund:

BEFUND
  Schwere:      {finding.severity}
  Regel:        {finding.rule}
  Datei:        {finding.file}
  {ts_info}
  Beschreibung: {finding.description}

KONTEXT (plus/minus 10 Minuten):
{kontext_str}

Antworte NUR mit diesem JSON:
{{
  "warum_critical": "2-3 Saetze: forensische Begruendung, warum CRITICAL.",
  "was_bedeutet":   "2-3 Saetze: Bedeutung im Angriffs-Kontext.",
  "naechste_schritte": "3-4 nummerierte Massnahmen, priorisiert."
}}""".strip()


def _fallback_texts(finding) -> dict:
    return {
        "warum_critical": (
            f"Regel '{finding.rule}' wurde auf '{finding.file}' ausgeloest. "
            f"{finding.description[:200]} "
            "Zwei unabhaengige Methoden bestaetigen diesen Befund (CRITICAL)."
        ),
        "was_bedeutet": (
            f"'{finding.file}' zeigt Anzeichen einer Manipulation. "
            "Deutet auf Anti-Forensics-Aktivitaeten hin. Details in forensic_findings.json."
        ),
        "naechste_schritte": (
            f"1. '{finding.file}' sichern und hashen. "
            "2. Zeitstempel mit Originaldaten vergleichen. "
            "3. Kontext in forensic_findings.json pruefen. "
            "4. Manuelle Analyse durchfuehren."
        ),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  TESTLAUF
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    from datetime import datetime
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    class MockFinding:
        severity     = "CRITICAL"
        rule         = "timestomping_M_lt_B"
        file         = "/EFI/BOOT"
        description  = "Modified (2022-12-13 05:42:44) liegt VOR Born (2022-12-13 05:42:45)"
        anomaly_time = datetime(2022, 12, 13, 5, 42, 44)
        evidence     = [{"time": "05:42:44", "source": "mactime",
                         "message": "[m..b] /EFI/BOOT", "user": None}]

    provider = get_provider()
    print(f"\nProvider: {provider.name()}\n{'─'*50}")
    texte = generate_finding_texts(MockFinding(), provider)
    print("\n=== Warum CRITICAL? ===\n", texte["warum_critical"])
    print("\n=== Was bedeutet das? ===\n", texte["was_bedeutet"])
    print("\n=== Naechste Schritte ===\n", texte["naechste_schritte"])
