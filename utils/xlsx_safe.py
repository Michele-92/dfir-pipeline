"""Schutz vor openpyxl IllegalCharacterError.

Manche extrahierten Werte (z.B. IOCs, die per Regex aus BINAEREN Dateien
gematcht wurden) enthalten Steuerzeichen (\\x00-\\x1f), die Excel/openpyxl in
Zellen grundsaetzlich verbietet. Ohne Schutz bricht der gesamte Stage-14-Export
mit IllegalCharacterError ab.

Import dieses Moduls aktiviert global (einmalig) einen Schutz: Beim Binden
eines Strings an eine Zelle werden unerlaubte Steuerzeichen still entfernt —
der Report wird erzeugt statt abzustuerzen. Sichtbarer Inhalt bleibt erhalten.
"""
from openpyxl.cell import cell as _opx_cell

_ILLEGAL = _opx_cell.ILLEGAL_CHARACTERS_RE
_orig_check_string = _opx_cell.Cell.check_string


def _check_string_safe(self, value):
    if isinstance(value, str):
        value = _ILLEGAL.sub('', value)
    return _orig_check_string(self, value)


# Idempotent: nur einmal patchen
if getattr(_opx_cell.Cell.check_string, '__name__', '') != '_check_string_safe':
    _opx_cell.Cell.check_string = _check_string_safe
