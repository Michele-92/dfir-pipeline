"""Korrektes Parsing des Linux utmp/wtmp/btmp-Binaerformats.

Linux glibc utmp-Record (x86_64): 384 Bytes, Felder per Byte-Offset:
  ut_type    short   @ 0      ut_id     char[4]   @ 40
  (padding)          @ 2      ut_user   char[32]  @ 44
  ut_pid     int32   @ 4      ut_host   char[256] @ 76
  ut_line    char[32]@ 8      ut_exit   4 Bytes   @ 332
  ut_session int32   @ 336    ut_tv.tv_sec  int32 @ 340
  ut_addr_v6 16 B    @ 348    ut_tv.tv_usec int32 @ 344
Manche Architekturen nutzen 392 Bytes Stride — wird automatisch erkannt.

Einzige Implementierung im Projekt — verwendet von parsers/wtmp_parser.py
(Review-Fix: vorher eigener, falscher 96-Byte-Struct) und perspektivisch
stages/stage03_profiling.
"""
import struct
from typing import Dict, List

UT_TYPES = {
    0: 'empty', 1: 'run_level', 2: 'boot_time',
    3: 'new_time', 4: 'old_time', 5: 'init_process',
    6: 'login_process', 7: 'user_process', 8: 'dead_process',
}

USER_PROCESS = 7
DEAD_PROCESS = 8
BOOT_TIME    = 2


def detect_stride(data: bytes) -> int:
    for stride in (384, 392):
        if len(data) >= stride and len(data) % stride == 0:
            return stride
    return 384


def _cstr(raw: bytes) -> str:
    return raw.split(b'\x00', 1)[0].decode('utf-8', errors='replace').strip()


def parse_utmp_records(data: bytes) -> List[Dict]:
    """Parst rohe utmp/wtmp/btmp-Bytes in eine Liste von Record-Dicts."""
    records: List[Dict] = []
    if not data:
        return records
    stride = detect_stride(data)
    for i in range(len(data) // stride):
        chunk = data[i * stride:(i + 1) * stride]
        if len(chunk) < 384:
            break
        try:
            ut_type = struct.unpack_from('<h', chunk, 0)[0]
            ut_pid  = struct.unpack_from('<i', chunk, 4)[0]
            ts_sec  = struct.unpack_from('<i', chunk, 340)[0]
            ts_usec = struct.unpack_from('<i', chunk, 344)[0]
        except struct.error:
            continue
        records.append({
            'type':      ut_type,
            'type_name': UT_TYPES.get(ut_type, 'unknown'),
            'pid':       ut_pid,
            'line':      _cstr(chunk[8:40]),
            'id':        _cstr(chunk[40:44]),
            'user':      _cstr(chunk[44:76]),
            'host':      _cstr(chunk[76:332]),
            'ts_sec':    ts_sec,
            'ts_usec':   ts_usec,
        })
    return records
