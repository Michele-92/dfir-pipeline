from datetime import datetime, timezone
from dateutil import parser as dateparser
import pytz


def to_utc(raw_timestamp: str, system_tz: str = 'UTC') -> datetime:
    if isinstance(raw_timestamp, datetime):
        if raw_timestamp.tzinfo is None:
            return raw_timestamp.replace(tzinfo=timezone.utc)
        return raw_timestamp.astimezone(timezone.utc)
    try:
        dt = dateparser.parse(str(raw_timestamp))
        if dt is None:
            return datetime.min.replace(tzinfo=timezone.utc)
        if dt.tzinfo is None:
            tz = pytz.timezone(system_tz)
            dt = tz.localize(dt)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)
