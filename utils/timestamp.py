from datetime import datetime, timezone
from typing import Optional
from dateutil import parser as dateparser
import pytz

_MONTHS = {'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
           'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12}


def to_utc(raw_timestamp, system_tz: str = 'UTC') -> Optional[datetime]:
    """Normalisiert einen Timestamp nach UTC.

    - datetime aware  -> nach UTC konvertiert
    - datetime naiv   -> als system_tz interpretiert, dann UTC
    - String          -> geparst (dateutil), naiv als system_tz
    - unparsebar      -> None  (Review-Fix T2: frueher datetime.min,
                        wodurch 'Erste Aktivitaet' auf Jahr 0001 fiel)
    """
    if isinstance(raw_timestamp, datetime):
        if raw_timestamp.tzinfo is None:
            try:
                return pytz.timezone(system_tz).localize(raw_timestamp)\
                           .astimezone(timezone.utc)
            except Exception:
                return raw_timestamp.replace(tzinfo=timezone.utc)
        return raw_timestamp.astimezone(timezone.utc)
    s = ' '.join(str(raw_timestamp).split())
    # Fast-Paths fuer die haeufigsten Formate — dateutil kostet ~10x mehr
    # und dominiert bei Millionen Syslog-Zeilen die Stage-6-Laufzeit
    dt = None
    try:
        dt = datetime.fromisoformat(s)            # ISO (dpkg, dnf, ...)
    except ValueError:
        try:
            dt = datetime.strptime(s, '%Y %b %d %H:%M:%S')   # Syslog-Familie
        except ValueError:
            pass
    if dt is None:
        try:
            dt = dateparser.parse(s)
        except Exception:
            return None
        if dt is None:
            return None
    try:
        if dt.tzinfo is None:
            tz = pytz.timezone(system_tz)
            dt = tz.localize(dt)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def infer_syslog_year(ref: datetime, month_abbr: str, day: int = 1) -> int:
    """Jahr fuer jahreslose Syslog-Timestamps (Review-Fix CRITICAL #7).

    Referenz: Datei-mtime, sofern sie 'alt' ist (Original-Logverzeichnis);
    bei frisch extrahierten Dateien (mtime = Extraktionszeit) ist die
    Referenz 'jetzt'. Liegt der Log-Monat NACH dem Referenz-Monat, war es
    das Vorjahr (Jahreswechsel-Logik) — Timestamps liegen nie in der Zukunft.

    Limitation (dokumentieren): Logs aelter als ~1 Jahr koennen ohne
    istat-Originalzeiten nicht exakt datiert werden.
    """
    m = _MONTHS.get(month_abbr[:3].lower())
    if m is None:
        return ref.year
    if (m, day) > (ref.month, ref.day):
        return ref.year - 1
    return ref.year


def year_reference(path) -> datetime:
    """Referenzzeit fuer infer_syslog_year: mtime wenn plausibel alt,
    sonst 'jetzt' (frisch extrahierte Dateien tragen die Extraktionszeit)."""
    now = datetime.now(tz=timezone.utc)
    try:
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        if (now - mtime).days >= 2:
            return mtime
    except OSError:
        pass
    return now
