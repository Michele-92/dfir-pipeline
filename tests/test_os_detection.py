"""Tests fuer das OS-Prioritaetsmodell (Review-Fix HIGH #11).

Kaskade: os-release -> usr/lib/os-release -> Distro-Releasedateien
-> /etc/issue -> Paketmanager-Heuristik. Quelle wird dokumentiert.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from stages.stage03_profiling import detect_os_from_partition

IMG = Path('fake.E01')


def _reader(inhalte):
    return lambda img, off, inode: inhalte.get(inode, '')


def test_os_release_hat_hoechste_prioritaet():
    index = {'etc/os-release': 'i1', 'etc/debian_version': 'i2',
             'etc/issue': 'i3', 'var/lib/dpkg/status': 'i4'}
    r = detect_os_from_partition(IMG, 0, index, _reader({
        'i1': 'NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 22.04.3 LTS"\nID=ubuntu',
        'i2': '12.5', 'i3': 'Debian GNU/Linux'}))
    assert r['os_name'] == 'Ubuntu 22.04.3 LTS'
    assert r['os_family'] == 'debian'
    assert r['source'] == '/etc/os-release'


def test_usr_lib_os_release_backup():
    r = detect_os_from_partition(IMG, 0, {'usr/lib/os-release': 'i1'},
        _reader({'i1': 'NAME="CentOS Linux"\nPRETTY_NAME="CentOS Linux 7 (Core)"'}))
    assert r['os_family'] == 'rhel'
    assert r['source'] == '/usr/lib/os-release'


def test_distro_releasedateien():
    r = detect_os_from_partition(IMG, 0, {'etc/debian_version': 'i1'},
                                 _reader({'i1': '11.7\n'}))
    assert r == {'os_name': 'Debian 11.7', 'os_family': 'debian',
                 'source': '/etc/debian_version'}
    r2 = detect_os_from_partition(IMG, 0, {'etc/redhat-release': 'i1'},
        _reader({'i1': 'CentOS Linux release 7.9.2009 (Core)\n'}))
    assert r2['os_name'].startswith('CentOS') and r2['os_family'] == 'rhel'
    r3 = detect_os_from_partition(IMG, 0, {'etc/alpine-release': 'i1'},
                                  _reader({'i1': '3.18.4'}))
    assert r3['os_name'] == 'Alpine Linux 3.18.4'


def test_issue_banner_mit_getty_escapes():
    r = detect_os_from_partition(IMG, 0, {'etc/issue': 'i1'},
        _reader({'i1': 'Ubuntu 20.04.6 LTS \\n \\l\n\n'}))
    assert r['os_family'] == 'debian'
    assert r['source'] == '/etc/issue'
    assert '\\' not in r['os_name']


def test_paketmanager_heuristik():
    r = detect_os_from_partition(IMG, 0, {'var/lib/rpm/Packages': 'i1'},
                                 _reader({}))
    assert r['os_family'] == 'rhel' and 'Heuristik' in r['source']
    r2 = detect_os_from_partition(IMG, 0, {'var/lib/dpkg/status': 'i1'},
                                  _reader({}))
    assert r2['os_family'] == 'debian'


def test_suse_erkennung():
    r = detect_os_from_partition(IMG, 0, {'etc/os-release': 'i1'},
        _reader({'i1': 'NAME="openSUSE Leap"\nPRETTY_NAME="openSUSE Leap 15.5"'}))
    assert r['os_family'] == 'suse'


def test_nichts_gefunden_bleibt_leer():
    r = detect_os_from_partition(IMG, 0, {'home/u/x.txt': 'i1'}, _reader({}))
    assert r == {'os_name': '', 'os_family': '', 'source': ''}
    assert detect_os_from_partition(IMG, 0, {}, _reader({}))['os_name'] == ''


def test_multi_os_pro_partition_unterscheidbar():
    fam1 = detect_os_from_partition(IMG, 2048, {'etc/os-release': 'i1'},
        _reader({'i1': 'NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 22.04"'}))['os_family']
    fam2 = detect_os_from_partition(IMG, 999999, {'etc/redhat-release': 'i1'},
        _reader({'i1': 'Rocky Linux release 9.2'}))['os_family']
    assert {fam1, fam2} == {'debian', 'rhel'}


# ── istat-mtime-Parsing (Shadow-Nachfix) ─────────────────────────────────

from stages.stage03_profiling import _parse_istat_mtime


def test_istat_mtime_tsk4_file_modified():
    out = ("Inode Times:\n"
           "Accessed:               2020-03-13 11:02:00.000000000 (UTC)\n"
           "File Modified:          2020-03-12 00:17:01.123456789 (UTC)\n"
           "Inode Modified:         2020-03-12 00:17:02.000000000 (UTC)\n")
    assert _parse_istat_mtime(out) == '2020-03-12 00:17:01.123456789 (UTC)'


def test_istat_mtime_altformat_gleiche_zeile():
    assert _parse_istat_mtime('Modified:  Thu Mar 12 00:17:01 2020\n') == \
        'Thu Mar 12 00:17:01 2020'


def test_istat_mtime_naechste_zeile():
    assert _parse_istat_mtime('Modified:\n2020-03-12 00:17:01 (UTC)\n') == \
        '2020-03-12 00:17:01 (UTC)'


def test_istat_ctime_wird_ignoriert():
    assert _parse_istat_mtime('Inode Modified: 2020-03-12 00:17:02 (UTC)\n') == ''
