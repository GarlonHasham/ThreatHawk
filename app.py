# app.py — Single-file ThreatHawk (FastAPI) voor Render
# Geen externe "threathawk" package nodig. Alles zit in dit bestand.
# Endpoints: /health, /findings (GET), /ban (POST), /ingest (POST?source=cloudflare&minutes=5)

import os, json, re, time, math
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Optional, List, Dict, Deque
import requests
from fastapi import FastAPI, Header, HTTPException

# ---------------------------
# Config via environment vars
# ---------------------------
API_KEY = os.environ.get("THREATHAWK_API_KEY", "change-me")
FINDINGS_PATH = os.environ.get("THREATHAWK_FINDINGS_PATH", "/tmp/findings.jsonl")
BANLIST_PATH = os.environ.get("THREATHAWK_BANLIST_PATH", "/tmp/banlist.txt")
BAN_ENABLED = os.environ.get("THREATHAWK_BAN_ENABLED", "false").lower() == "true"

SITE = os.environ.get("THREATHAWK_SITE", "codeniacs.ai")
ENVIRONMENT = os.environ.get("THREATHAWK_ENV", "prod")
MIN_SEVERITY = int(os.environ.get("THREATHAWK_MIN_SEVERITY", "3"))
EMA_ALPHA = float(os.environ.get("THREATHAWK_EMA_ALPHA", "0.2"))
WINDOW_SECONDS = int(os.environ.get("THREATHAWK_WINDOW_SECONDS", "60"))

CF_API_TOKEN = os.environ.get("CF_API_TOKEN")        # optioneel voor /ingest
CF_ZONE_ID   = os.environ.get("CF_ZONE_ID")          # optioneel voor /ingest

# ---------------------------
# Utilities
# ---------------------------
def _auth(x_api_key: Optional[str]):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="invalid api key")

def _jsonl_append(path: str, obj: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    with open(path, "a") as w:
        w.write(json.dumps(obj, ensure_ascii=False) + "\n")

# ---------------------------
# Log parser (combined-ish)
# ---------------------------
COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>\S+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)"'
)
GENERIC_RE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).+?"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(?P<path>\S+)\s+(?P<proto>HTTP/\d\.\d)"\s+(?P<status>\d{3}).+?"(?P<agent>[^"]*)"'
)

def _parse_time(ts: str) -> float:
    # "20/Aug/2025:10:15:30 +0000"
    try:
        return datetime.strptime(ts.split()[0], "%d/%b/%Y:%H:%M:%S").timestamp()
    except Exception:
        return time.time()

def parse_line(line: str):
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
    return {
        "ts": ts,
        "ip": m.group("ip"),
        "method": m.group("method"),
        "path": m.group("path"),
        "status": status,
        "agent": m.group("agent"),
        "raw": line.strip(),
    }

# ---------------------------
# Simple anomaly model
# ---------------------------
class AnomalyModel:
    def __init__(self, window_seconds=60, ema_alpha=0.2):
        self.window_seconds = window_seconds
        self.ema_alpha = ema_alpha
        self.by_ip: Dict[str, Deque[dict]] = defaultdict(lambda: deque(maxlen=5000))
        self.baseline = defaultdict(lambda: {
            "ema_rate": 0.0, "var_rate": 1.0,
            "ema_err": 0.0,  "var_err": 1.0,
            "ema_up": 0.0,   "var_up": 1.0,
            "ema_ql": 0.0,   "var_ql": 1.0,
            "ema_ent": 0.0,  "var_ent": 1.0,
        })

    @staticmethod
    def _agent_entropy(agent: str) -> float:
        if not agent:
            return 0.0
        counts = {}
        for ch in agent:
            counts[ch] = counts.get(ch, 0) + 1
        total = len(agent)
        return -sum((c/total)*math.log2(c/total) for c in counts.values())

    @staticmethod
    def _query_len(path: str) -> int:
        if "?" not in path:
            return 0
        return len(path.split("?", 1)[1])

    def update_and_score(self, ev: dict) -> float:
        q = self.by_ip[ev["ip"]]
        q.append(ev)
        now = ev["ts"]
        # trim window
        while q and now - q[0]["ts"] > self.window_seconds:
            q.popleft()

        total = len(q)
        errors = sum(1 for e in q if e["status"] >= 400)
        upaths = len({e["path"] for e in q})
        qlen = sum(self._query_len(e["path"]) for e in q) / max(1, total)
        ent = sum(self._agent_entropy(e["agent"]) for e in q) / max(1, total)

        b = self.baseline[ev["ip"]]
        a = self.ema_alpha

        def ema(cur, new): return (1-a)*cur + a*new
        def upd_var(cur_var, mean, new):
            diff = new - mean
            return (1-a)*cur_var + a*(diff*diff)

        b["var_rate"] = upd_var(b["var_rate"], b["ema_rate"], total); b["ema_rate"] = ema(b["ema_rate"], total)
        b["var_err"]  = upd_var(b["var_err"],  b["ema_err"],  errors); b["ema_err"]  = ema(b["ema_err"],  errors)
        b["var_up"]   = upd_var(b["var_up"],   b["ema_up"],   upaths); b["ema_up"]   = ema(b["ema_up"],   upaths)
        b["var_ql"]   = upd_var(b["var_ql"],   b["ema_ql"],   qlen);   b["ema_ql"]   = ema(b["ema_ql"],   qlen)
        b["var_ent"]  = upd_var(b["var_ent"],  b["ema_ent"],  ent);    b["ema_ent"]  = ema(b["ema_ent"],  ent)

        def z(new, mean, var):
            std = max(1e-3, var ** 0.5)
            return max(0.0, (new - mean) / std)

        return z(total, b["ema_rate"], b["var_rate"]) + \
               z(errors, b["ema_err"], b["var_err"]) + \
               z(upaths, b["ema_up"], b["var_up"]) + \
               z(qlen,   b["ema_ql"], b["var_ql"]) + \
               z(ent,    b["ema_ent"], b["var_ent"])

MODEL = AnomalyModel(window_seconds=WINDOW_SECONDS, ema_alpha=EMA_ALPHA)

# ---------------------------
# Simple rules (regex)
# ---------------------------
RULES = [
    ("SQLi.union_select", r"union\s+select|information_schema|sleep\s*\(|benchmark\s*\(", 5, "T1190"),
    ("SQLi.boolean", r"(?:'|%27)\s*or\s*1=1|--|/\*|\*/", 4, "T1190"),
    ("XSS.script_tag", r"<\s*script|javascript:|onerror\s*=|onload\s*=", 4, "T1190"),
    ("LFI.path_traversal", r"\.\./|\.%2e%2e/|%2e%2e%2f|/etc/passwd|/proc/self", 5, "T1190"),
    ("RCE.shell", r"(?:cmd|exec|system|passthru)\s*\(|bash\s+-c|;\s*\$?\(\w+\)", 5, "T1059"),
    ("Scanner.user_agent", r"sqlmap|acunetix|nessus|nikto|burp|dirbuster", 3, "T1190"),
    ("WP.attack_surface", r"/wp-login\.php|/wp-admin|/xmlrpc\.php", 3, "T1190"),
    ("Auth.bruteforce", r"/login|/admin|/account/login", 3, "T1110"),
]
RULES = [(n, re.compile(rx, re.IGNORECASE), sev, mitre) for (n, rx, sev, mitre) in RULES]

def evaluate_event(ev: dict):
    anomaly = MODEL.update_and_score(ev)
    text = f'{ev["path"]}\n{ev["raw"]}\n{ev["agent"]}'
    hits = [name for (name, rx, _, _) in RULES if rx.search(text)]
    mitre = [m for (name, rx, _, m) in RULES if name in hits]
    rule_sev = max([sev for (name, rx, sev, m) in RULES if name in hits], default=0)
    anomaly_sev = min(5, int(1 + anomaly / 3))
    combined = int(round(0.6 * anomaly_sev + 0.4 * rule_sev))
    return anomaly, hits, sorted(set(mitre)), combined

def write_finding(ev: dict, anomaly: float, hits: List[str], mitre: List[str], combined: int):
    if combined < MIN_SEVERITY and not hits:
        return False
    payload = {
        "ts": datetime.utcfromtimestamp(ev["ts"]).isoformat() + "Z",
        "ip": ev["ip"],
        "site": SITE,
        "environment": ENVIRONMENT,
        "rules": hits,
        "mitre": mitre,
        "anomaly": round(anomaly, 2),
        "severity": combined,
        "sample": ev["raw"][:800],
    }
    print(json.dumps(payload, ensure_ascii=False), flush=True)
    _jsonl_append(FINDINGS_PATH, payload)
    return True

# ---------------------------
# Cloudflare Logpull
# ---------------------------
def cloudflare_fetch_last_minutes(api_token: str, zone_id: str, minutes: int = 5) -> List[str]:
    end = datetime.utcnow()
    start = end - timedelta(minutes=minutes)
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/logs/received"
    params = {
        "start": start.isoformat() + "Z",
        "end": end.isoformat() + "Z",
        "fields": "ClientIP,EdgeStartTimestamp,ClientRequestMethod,ClientRequestURI,EdgeResponseStatus,ClientRequestUserAgent,ClientRequestProtocol",
        "sample": 1
    }
    headers = {"Authorization": f"Bearer {api_token}"}
    r = requests.get(url, headers=headers, params=params, timeout=30)
    r.raise_for_status()
    lines = []
    for line in r.iter_lines(decode_unicode=True):
        if not line:
            continue
        try:
            rec = json.loads(line)
            ip = rec.get("ClientIP", "-")
            ts = datetime.utcfromtimestamp(rec.get("EdgeStartTimestamp", 0)).strftime("%d/%b/%Y:%H:%M:%S +0000")
            method = rec.get("ClientRequestMethod", "GET")
            path = rec.get("ClientRequestURI", "/")
            proto = f'HTTP/{rec.get("ClientRequestProtocol", "1.1")}'
            status = rec.get("EdgeResponseStatus", 200)
            agent = rec.get("ClientRequestUserAgent", "")
            combined = f'{ip} - - [{ts}] "{method} {path} {proto}" {status} 0 "-" "{agent}"'
            lines.append(combined)
        except Exception:
            continue
    return lines

# ---------------------------
# FastAPI app
# ---------------------------
app = FastAPI(title="ThreatHawk API (single-file)", version="0.2.0")

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/findings")
def findings(limit: int = 50, min_severity: int = MIN_SEVERITY, site: Optional[str] = None, x_api_key: Optional[str] = Header(None)):
    _auth(x_api_key)
    items = []
    try:
        with open(FINDINGS_PATH, "r") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if obj.get("severity", 0) < min_severity:
                        continue
                    if site and obj.get("site") != site:
                        continue
                    items.append(obj)
                except Exception:
                    continue
    except FileNotFoundError:
        items = []
    return {"items": items[-limit:], "count": min(len(items), limit)}

@app.post("/ban")
def ban(ip: str, reason: str = "manual", x_api_key: Optional[str] = Header(None)):
    _auth(x_api_key)
    if not BAN_ENABLED:
        return {"accepted": False, "reason": "banlist disabled"}
    with open(BANLIST_PATH, "a") as w:
        w.write(f"{ip} # {reason}\n")
    return {"accepted": True, "ip": ip}

@app.post("/ingest")
def ingest(source: str, minutes: int = 5, x_api_key: Optional[str] = Header(None)):
    _auth(x_api_key)
    if source != "cloudflare":
        raise HTTPException(status_code=400, detail="unsupported source")
    if not (CF_API_TOKEN and CF_ZONE_ID):
        raise HTTPException(status_code=400, detail="Cloudflare credentials missing")
    lines = cloudflare_fetch_last_minutes(CF_API_TOKEN, CF_ZONE_ID, minutes=minutes)
    count = 0
    for line in lines:
        ev = parse_line(line)
        if not ev:
            continue
        anomaly, hits, mitre, combined = evaluate_event(ev)
        if write_finding(ev, anomaly, hits, mitre, combined):
            count += 1
    return {"ingested": count, "minutes": minutes}

