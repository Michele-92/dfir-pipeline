"""Tests fuer den gebuendelten YARA-Compile (Stage 9, Punkt 4).

Verifiziert:
  - Bundle-Compile liefert dieselben Treffer wie der alte Einzel-Compile
  - Robustheit: eine fehlerhafte Regeldatei wird uebersprungen, der Rest wirkt
  - Scan-Scope: nur case_dir/raw/ wird gescannt (nicht die eigenen Ausgaben)

Wird uebersprungen, wenn yara-python nicht installiert ist.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

yara = pytest.importorskip("yara")

from models.pipeline_context import PipelineContext
from stages import stage09_antiforensics as s9


GOOD_RULE = 'rule FindEvil {{ strings: $a = "{kw}" condition: $a }}'


def _write_rules(rules_dir: Path, broken: bool = False):
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / 'a.yar').write_text(GOOD_RULE.format(kw='EVIL_MARKER'))
    (rules_dir / 'b.yar').write_text(
        'rule FindMal {{ strings: $b = "MAL_MARKER" condition: $b }}'.replace('{{','{').replace('}}','}'))
    if broken:
        # Syntaktisch kaputte Regel — darf den Rest NICHT lahmlegen
        (rules_dir / 'broken.yar').write_text('rule Broken { this is not valid yara')


def _make_case(tmp_path: Path):
    raw = tmp_path / 'case' / 'raw' / 'log_artefakte'
    raw.mkdir(parents=True, exist_ok=True)
    (raw / 'evil.log').write_text('hello EVIL_MARKER world')
    (raw / 'mal.log').write_text('contains MAL_MARKER here')
    (raw / 'clean.log').write_text('nichts auffaelliges')
    # eigene Pipeline-Ausgabe ausserhalb raw/ — darf NICHT gescannt werden
    (tmp_path / 'case' / 'report_EVIL_MARKER.txt').write_text('EVIL_MARKER im Report')
    return tmp_path / 'case'


def _ctx(tmp_path, broken=False):
    rules_dir = tmp_path / 'data' / 'yara-rules'
    _write_rules(rules_dir, broken=broken)
    ctx = PipelineContext()
    ctx.case_dir = _make_case(tmp_path)
    ctx.yara_mode = 'full'   # -> rules_dir == base
    # _get_yara_rules_dir zeigt auf das Projekt; hier patchen wir direkt:
    s9._get_yara_rules_dir = lambda mode: rules_dir
    return ctx


def test_bundle_findet_treffer(tmp_path):
    ctx = _ctx(tmp_path)
    hits = s9._check_yara(ctx)
    rules = sorted({h['rule'] for h in hits})
    assert rules == ['FindEvil', 'FindMal']
    files = {Path(h['file']).name for h in hits}
    assert 'evil.log' in files and 'mal.log' in files


def test_scope_nur_raw(tmp_path):
    ctx = _ctx(tmp_path)
    hits = s9._check_yara(ctx)
    # report_EVIL_MARKER.txt liegt ausserhalb raw/ -> darf nicht auftauchen
    assert all('report_EVIL_MARKER' not in h['file'] for h in hits)


def test_robust_gegen_kaputte_regel(tmp_path):
    ctx = _ctx(tmp_path, broken=True)
    hits = s9._check_yara(ctx)
    # Trotz broken.yar muessen die guten Regeln weiter matchen
    rules = sorted({h['rule'] for h in hits})
    assert 'FindEvil' in rules and 'FindMal' in rules


def test_compile_helper_skipped_count(tmp_path):
    rules_dir = tmp_path / 'r'
    _write_rules(rules_dir, broken=True)
    rule_files = sorted(rules_dir.rglob('*.yar'))
    compiled, skipped = s9._compile_yara_rules(rule_files)
    assert compiled is not None
    assert skipped == 1          # genau broken.yar
