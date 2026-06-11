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
