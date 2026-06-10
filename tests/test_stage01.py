import sys
import tempfile
import hashlib
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.hashing import compute_sha256, compute_md5, compute_both
from utils.file_detection import detect_format, detect_format_by_extension
from utils.timestamp import to_utc
from stages.stage01_detection import _create_case_dir


def test_sha256():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b'DFIR test data')
        path = Path(f.name)
    expected = hashlib.sha256(b'DFIR test data').hexdigest()
    assert compute_sha256(path) == expected
    path.unlink()


def test_md5():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b'DFIR test data')
        path = Path(f.name)
    expected = hashlib.md5(b'DFIR test data').hexdigest()
    assert compute_md5(path) == expected
    path.unlink()


def test_compute_both_consistency():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b'consistency check')
        path = Path(f.name)
    sha, md = compute_both(path)
    assert sha == compute_sha256(path)
    assert md  == compute_md5(path)
    path.unlink()


def test_detect_format_e01():
    assert detect_format('EWF Expert Witness Format') == 'E01'


def test_detect_format_vmdk():
    assert detect_format('VMware VMDK disk image') == 'VMDK'


def test_detect_format_fallback():
    assert detect_format('unknown binary data') == 'DD'


def test_detect_format_by_extension():
    assert detect_format_by_extension(Path('disk.e01'))  == 'E01'
    assert detect_format_by_extension(Path('mem.raw'))   == 'DD'
    assert detect_format_by_extension(Path('vm.vmdk'))   == 'VMDK'
    assert detect_format_by_extension(Path('vhd.vhdx'))  == 'VHDX'


def test_to_utc_iso():
    from datetime import timezone
    dt = to_utc('2026-04-22T09:15:33+02:00')
    assert dt.tzinfo == timezone.utc
    assert dt.hour == 7


def test_to_utc_invalid():
    from datetime import datetime, timezone
    result = to_utc('not-a-date')
    assert result == datetime.min.replace(tzinfo=timezone.utc)


def test_create_case_dir():
    # Erwartete Struktur entspricht stage01_detection._create_case_dir:
    # es werden nur raw/disk_artefakte und raw/log_artefakte angelegt
    # (memory_artefakte/autopsy_artefakte entfielen mit Deaktivierung
    #  von Stage 02_mem und Stage 04.1).
    with tempfile.TemporaryDirectory() as tmp:
        case_dir = _create_case_dir(Path(tmp))
        assert case_dir.exists()
        assert (case_dir / 'raw' / 'disk_artefakte').exists()
        assert (case_dir / 'raw' / 'log_artefakte').exists()
