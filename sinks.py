from __future__ import annotations
import json, time, threading
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
try:
    import requests
except Exception:
    requests = None

@dataclass
class Finding:
    ts: float
    ip: str
    site: str
    env: str
    rules: list
    mitre: list
    anomaly: float
    severity: int
    sample: str

    def to_dict(self):
        from datetime import datetime
        return {
            "ts": datetime.utcfromtimestamp(self.ts).isoformat() + "Z",
            "ip": self.ip,
            "site": self.site,
            "environment": self.env,
            "rules": self.rules,
            "mitre": sorted(set(self.mitre)),
            "anomaly": round(self.anomaly, 2),
            "severity": self.severity,
            "sample": self.sample,
        }

class AlertSink:
    def __init__(self, min_severity=3, webhook: Optional[str]=None, jsonl_path: Optional[str]=None):
        self.min = min_severity
        self.webhook = webhook
        self.jsonl_path = jsonl_path
        self._dedupe: Dict[Tuple[str, int], float] = {}
        self._lock = threading.Lock()

    def _should_send(self, ip: str, severity: int) -> bool:
        key = (ip, severity)
        now = time.time()
        with self._lock:
            last = self._dedupe.get(key, 0)
            if now - last < 60:
                return False
            self._dedupe[key] = now
        return True

    def send(self, f: Finding):
        if f.severity < self.min:
            return
        if not self._should_send(f.ip, f.severity):
            return
        payload = f.to_dict()
        line = json.dumps(payload, ensure_ascii=False)
        print(line, flush=True)
        if self.jsonl_path:
            try:
                with open(self.jsonl_path, "a") as w:
                    w.write(line + "\n")
            except Exception as e:
                print(f"[warn] failed to write jsonl: {e}")
        if self.webhook and requests:
            try:
                requests.post(self.webhook, json={"text": f"ThreatHawk alert:\n```{json.dumps(payload, indent=2)}```"}, timeout=5)
            except Exception as e:
                print(f"[warn] webhook failed: {e}")
