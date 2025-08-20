from __future__ import annotations
import re, time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+\"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>\S+)\"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+\"(?P<referrer>[^\"]*)\"\s+\"(?P<agent>[^\"]*)\"'
)

GENERIC_RE = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+).+?\"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(?P<path>\S+)\s+(?P<proto>HTTP/\d\.\d)\"\s+(?P<status>\d{3}).*?\"(?P<agent>[^\"]*)\"')

def _parse_time(ts: str) -> float:
    try:
        dt = datetime.strptime(ts.split()[0], "%d/%b/%Y:%H:%M:%S")
        return dt.timestamp()
    except Exception:
        return time.time()

@dataclass
class Event:
    ts: float
    ip: str
    method: str
    path: str
    status: int
    agent: str
    raw: str

def parse_line(line: str) -> Optional[Event]:
    m = COMBINED_RE.search(line)
    if not m:
        m = GENERIC_RE.search(line)
        if not m:
            return None
        ts = time.time()
    else:
        ts = _parse_time(m.group("time"))
    try:
        status = int(m.group("status"))
    except Exception:
        status = 0
    return Event(ts, m.group("ip"), m.group("method"), m.group("path"), status, m.group("agent"), line.strip())
