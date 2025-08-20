from __future__ import annotations
import yaml, dataclasses
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

@dataclass
class AnomalyCfg:
    ema_alpha: float = 0.2
    window_seconds: int = 60

@dataclass
class Alerts:
    min_severity: int = 3
    stdout: bool = True
    jsonl_path: Optional[str] = None
    webhook: Optional[str] = None

@dataclass
class Config:
    site: str = "codeniacs.ai"
    environment: str = "prod"
    rules: Dict[str, Any] = dataclasses.field(default_factory=dict)
    anomaly: AnomalyCfg = dataclasses.field(default_factory=AnomalyCfg)
    alerts: Alerts = dataclasses.field(default_factory=Alerts)

def load(path: str) -> Config:
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    cfg = Config()
    cfg.site = data.get("site", cfg.site)
    cfg.environment = data.get("environment", cfg.environment)
    cfg.rules = data.get("rules", {})
    a = data.get("anomaly", {})
    cfg.anomaly = AnomalyCfg(a.get("ema_alpha", cfg.anomaly.ema_alpha), a.get("window_seconds", cfg.anomaly.window_seconds))
    al = data.get("alerts", {})
    cfg.alerts = Alerts(al.get("min_severity",3), al.get("stdout",True), al.get("jsonl_path"), al.get("webhook"))
    return cfg
