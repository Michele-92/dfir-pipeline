"""Tests fuer die Multi-Image-Erkennung (Ordner-Eingabe, Baustein 0 + Option 2).

Logik: Datei direkt / Ordner mit 1 Image (auch EWF-segmentiert) -> laeuft
ohne Rueckfrage. Nur Ordner mit MEHREREN Images loest die Auswahl aus.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline import _scan_image_folder, _resolve_folder_input


def _folder(dateien):
    d = Path(tempfile.mkdtemp())
    for name, size in dateien:
        (d / name).write_bytes(b'\x00' * size)
    return d


def test_ewf_segmente_zaehlen_als_ein_image():
    d = _folder([('server.E01', 1000), ('server.E02', 1000),
                 ('server.E03', 500), ('notizen.txt', 10)])
    imgs = _scan_image_folder(d)
    assert len(imgs) == 1
    assert imgs[0]['segments'] == 3
    assert imgs[0]['path'].name == 'server.E01'


def test_mehrere_formate_erkannt():
    d = _folder([('jumpbox.E01', 100), ('webserver.E01', 200),
                 ('desktop.dd', 300), ('vm.vmdk', 400), ('readme.md', 5)])
    namen = [e['path'].name for e in _scan_image_folder(d)]
    assert len(namen) == 4
    assert 'readme.md' not in namen


def test_exe_ist_kein_ewf_segment():
    d = _folder([('tool.exe', 100), ('disk.E01', 100), ('disk.E02', 100)])
    imgs = _scan_image_folder(d)
    assert len(imgs) == 1 and imgs[0]['segments'] == 2


def test_verwaistes_segment_ohne_e01_ignoriert():
    d = _folder([('orphan.E02', 100), ('echt.dd', 100)])
    imgs = _scan_image_folder(d)
    assert len(imgs) == 1 and imgs[0]['path'].name == 'echt.dd'


def test_ordner_mit_einem_image_laeuft_direkt():
    d = _folder([('einzeln.E01', 100)])
    r = _resolve_folder_input(d, 'ask')
    assert isinstance(r, Path) and r.name == 'einzeln.E01'


def test_case_mode_batch_liefert_liste():
    d = _folder([('a.E01', 100), ('b.E01', 100), ('c.dd', 100)])
    r = _resolve_folder_input(d, 'batch')
    assert isinstance(r, list) and len(r) == 3


def test_interaktive_auswahl(monkeypatch):
    d = _folder([('a.E01', 100), ('b.E01', 100), ('c.dd', 100)])
    eingaben = iter(['x', '2'])
    monkeypatch.setattr('builtins.input', lambda prompt='': next(eingaben))
    r = _resolve_folder_input(d, 'ask')
    assert isinstance(r, Path) and r.name == 'b.E01'


def test_interaktiv_a_ergibt_batch(monkeypatch):
    d = _folder([('a.E01', 100), ('b.E01', 100)])
    monkeypatch.setattr('builtins.input', lambda prompt='': 'a')
    r = _resolve_folder_input(d, 'ask')
    assert isinstance(r, list) and len(r) == 2


# ── Fall-Modus (Option 1): mehrere Images, ein gemeinsamer Report ────────

def test_case_mode_combined_liefert_dict():
    d = _folder([('jumpbox.E01', 100), ('webserver.E01', 200)])
    r = _resolve_folder_input(d, 'combined')
    assert isinstance(r, dict) and r['combined'] is True
    assert len(r['images']) == 2


def test_interaktiv_j_ergibt_fall_modus(monkeypatch):
    d = _folder([('jumpbox.E01', 100), ('webserver.E01', 200)])
    monkeypatch.setattr('builtins.input', lambda prompt='': 'j')
    r = _resolve_folder_input(d, 'ask')
    assert isinstance(r, dict) and r['combined'] is True


def test_stage01_teilt_casedir_und_coc_im_fallmodus(monkeypatch, tmp_path):
    import stages.stage01_detection as s1
    from models.pipeline_context import PipelineContext
    monkeypatch.setattr(s1, 'read_e01_hashes', lambda p: ('', ''))
    monkeypatch.setattr(s1, 'read_e01_media_size', lambda p: 0)
    monkeypatch.setattr(s1, 'detect_format', lambda m: 'DD')
    monkeypatch.setattr(s1, 'detect_format_by_extension', lambda p: 'DD')
    monkeypatch.setattr(s1, 'compute_both', lambda p: ('sha_' + p.name, 'md5_' + p.name))

    img1 = tmp_path / 'jumpbox.E01';   img1.write_bytes(b'A' * 50)
    img2 = tmp_path / 'webserver.E01'; img2.write_bytes(b'B' * 50)
    ctx = PipelineContext(output_dir=tmp_path / 'out', combined_case=True)

    ctx.disk_image_path = img1; ctx.evidence_label = 'jumpbox.E01'
    ctx = s1.run(ctx)
    cd, coc = ctx.case_dir, ctx.coc
    ctx.disk_image_path = img2; ctx.evidence_label = 'webserver.E01'
    ctx = s1.run(ctx)

    assert ctx.case_dir is cd      # geteilter Case-Ordner
    assert ctx.coc is coc          # eine gemeinsame CoC
    assert set(ctx.coc.evidence_hashes) == {'jumpbox.E01', 'webserver.E01'}
    assert ctx.coc.evidence_hashes['jumpbox.E01']['md5'] == 'md5_jumpbox.E01'
