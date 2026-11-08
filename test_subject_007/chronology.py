"""Timestamp semantics: preserve source values; never substitute analysis time."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
import re

PHT = timezone(timedelta(hours=8), 'PHT')
EMPTY = {'', '-', "'-", 'N/A', 'None', 'NotApplicable', 'Unreadable'}


def timestamp(value, *, assume_utc=False, capture=None):
    raw = str(value or '').strip()
    result = {'time_raw': raw, 'time_utc': '', 'time_pht': '', 'time_status': 'Unavailable'}
    if raw in EMPTY:
        return result
    text = raw.replace(' UTC', '+00:00').replace('Z', '+00:00')
    # Preserve the complete original timestamp, even if datetime uses microseconds.
    text = re.sub(r'(\.\d{6})\d+', r'\1', text)
    try:
        date = datetime.fromisoformat(text)
    except ValueError:
        result['time_status'] = 'Unparseable source value'
        return result
    if date.tzinfo is None:
        if not assume_utc:
            result['time_status'] = 'Timezone not supplied'
            return result
        date = date.replace(tzinfo=timezone.utc)
        result['time_status'] = 'UTC assumed from plugin convention'
    else:
        result['time_status'] = 'Source timezone supplied'
    date = date.astimezone(timezone.utc)
    if date.year < 2000:
        result['time_status'] = 'Implausible date; not placed on timeline'
        return result
    if capture and date > capture + timedelta(minutes=1):
        result['time_status'] = 'Later than snapshot; validate acquisition/structure'
    result.update(time_utc=date.isoformat(), time_pht=date.astimezone(PHT).isoformat())
    return result


def as_datetime(value):
    # Validation needs the date even when implausibly old; display filtering is
    # deliberately separate from parsing.
    try:
        text=str(value).strip().replace(' UTC','+00:00').replace('Z','+00:00')
        text=re.sub(r'(\.\d{6})\d+',r'\1',text)
        date=datetime.fromisoformat(text)
        if date.tzinfo is None:date=date.replace(tzinfo=timezone.utc)
        return date.astimezone(timezone.utc)
    except (TypeError,ValueError):return None


def memory_timeline(processes, network):
    """Deduplicate identical observations while retaining every reference."""
    events = {}
    for pid, records in processes.items():
        for ref, row in records:
            for field, label in (('CreateTime', 'Process created'), ('ExitTime', 'Process exited')):
                times = timestamp(row.get(field), assume_utc=True)
                if not times['time_utc']:
                    continue
                name = str(row.get('ImageFileName', row.get('Process', row.get('COMM', ''))))
                identity = row.get('Offset(V)', row.get('Offset', ''))
                key = (label, pid, name, identity, times['time_utc'])
                event = events.setdefault(key, {**times, 'kind': label, 'timestamp_field': field,
                    'pid': pid, 'subject': name, 'host': '', 'identity': identity,
                    'interpretation': 'Process lifetime timestamp, not an authentication/logon event.',
                    'references': []})
                event['references'].append(ref)
    for item in network:
        if not item.get('time_utc'):
            continue
        subject = f"{item['local_address']}:{item['local_port']} -> {item['remote_address']}:{item['remote_port']}"
        key = ('Network object created', item['pid'], subject, item.get('protocol'), item.get('state'), item['time_utc'])
        event = events.setdefault(key, {k: item[k] for k in ('time_raw','time_utc','time_pht','time_status')})
        event.update(kind='Network object created', timestamp_field=item['timestamp_field'], pid=item['pid'],
                     subject=subject, host='', identity='', interpretation='Network-object creation, not an RDP authentication or session start.')
        event.setdefault('references', []).append({k:item[k] for k in ('plugin','run_id','row_id')})
    return sorted(events.values(), key=lambda r: (r['time_utc'], r['kind'], str(r['pid'])))
