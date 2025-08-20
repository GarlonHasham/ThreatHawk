from __future__ import annotations
from fastapi import FastAPI, Header, HTTPException
from typing import Optional
import os, json, time

from threathawk.rules import load_rules
from threathawk.parsers import parse_line, Event
from threathawk.anomaly import AnomalyModel
from threathawk.sinks import AlertSink, Finding
from threathawk.config import load as load_cfg

app = FastAPI(title="ThreatHawk API", version="0.2.0")

API_KEY = os.environ.get("THREATHAWK_API_KEY", "change-me")
FINDINGS_PATH = os.environ.get("THREATHAWK_FINDINGS_PATH", "./findings.jsonl")
BANLIST_PATH = os.environ.get("THREATHAWK_BANLIST_PATH", "./banlist.txt")
BAN_ENABLED = os.environ.get("THREATHAWK_BAN_ENABLED", "false").lower() == "true"

CF_API_TOKEN = os.environ.get("CF_API_TOKEN")
CF_ZONE_ID = os.environ.get("CF_ZONE_ID")

# load config (optional)
CFG_PATH = os.environ.get("THREATHAWK_CONFIG", "./config.cloudrun.yaml")
try:
    CFG = load_cfg(CFG_PATH)
except Exception:
    class _Tmp: site="site"; environment="prod"; alerts=type("a",(object,),{"min_severity":3,"webhook":None,"jsonl_path":None})(); anomaly=type("b",(object,),{"window_seconds":60,"ema_alpha":0.2})()
    CFG = _Tmp()

RULES = load_rules(getattr(CFG, "rules", {}).get("file") if hasattr(CFG, "rules") else None)
MODEL = AnomalyModel(window_seconds=CFG.anomaly.window_seconds, ema_alpha=CFG.anomaly.ema_alpha)
ALERTS = AlertSink(min_severity=CFG.alerts.min_severity, webhook=CFG.alerts.webhook, jsonl_path=FINDINGS_PATH)

def _auth(x_api_key: Optional[str]):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="invalid api key")

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/findings")
def findings(limit: int = 50, min_severity: int = 3, site: Optional[str] = None, x_api_key: Optional[str] = Header(None)):
    _auth(x_api_key)
    items = []
    try:
        with open(FINDINGS_PATH, "r") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if obj.get("severity",0) < min_severity: 
                        continue
                    if site and obj.get("site") != site:
                        continue
                    items.append(obj)
                except Exception:
                    continue
    except FileNotFoundError:
        items = []
    items = items[-limit:]
    return {"items": items, "count": len(items)}

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
    # Pull logs
    from threathawk.integrations.cloudflare_logpull import fetch_last_minutes
    lines = fetch_last_minutes(CF_API_TOKEN, CF_ZONE_ID, minutes=minutes)
    # Process
    count = 0
    for line in lines:
        ev = parse_line(line)
        if not ev: 
            continue
        anomaly = MODEL.update_and_score(ev)
        text = f"{ev.path}\n{ev.raw}\n{ev.agent}"
        hits = [r for r in RULES if r.pattern.search(text)]
        anomaly_sev = min(5, int(1 + anomaly / 3))
        rule_sev = max([r.severity for r in hits], default=0)
        combined = int(round(0.6 * anomaly_sev + 0.4 * rule_sev))
        if combined >= CFG.alerts.min_severity or hits:
            f = Finding(ts=ev.ts, ip=ev.ip, site=CFG.site, env=CFG.environment,
                        rules=[r.name for r in hits], mitre=[r.mitre for r in hits],
                        anomaly=anomaly, severity=combined, sample=ev.raw[:800])
            ALERTS.send(f)
            count += 1
    return {"ingested": count, "minutes": minutes}
