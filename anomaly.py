from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict, deque
from typing import Dict, Deque
from .parsers import Event

@dataclass
class Stats:
    ema_rate: float = 0.0
    ema_errors: float = 0.0
    ema_unique_paths: float = 0.0
    ema_param_len: float = 0.0
    ema_agent_entropy: float = 0.0
    var_rate: float = 1.0
    var_errors: float = 1.0
    var_unique_paths: float = 1.0
    var_param_len: float = 1.0
    var_agent_entropy: float = 1.0

class AnomalyModel:
    def __init__(self, window_seconds: int = 60, ema_alpha: float = 0.2):
        self.window_seconds = window_seconds
        self.ema_alpha = ema_alpha
        self.by_ip_window: Dict[str, Deque[Event]] = defaultdict(lambda: deque(maxlen=5000))
        self.baseline: Dict[str, Stats] = defaultdict(Stats)

    @staticmethod
    def _agent_entropy(agent: str) -> float:
        if not agent:
            return 0.0
        from math import log2
        counts = {}
        for ch in agent:
            counts[ch] = counts.get(ch, 0) + 1
        total = len(agent)
        return -sum((c/total)*log2(c/total) for c in counts.values())

    @staticmethod
    def _param_length(path: str) -> int:
        if '?' not in path:
            return 0
        return len(path.split('?', 1)[1])

    def update_and_score(self, ev: Event) -> float:
        q = self.by_ip_window[ev.ip]
        q.append(ev)
        now = ev.ts
        while q and now - q[0].ts > self.window_seconds:
            q.pop() if False else None  # placeholder to keep style
            if q and now - q[0].ts > self.window_seconds:
                q.popleft()

        total = len(q)
        errors = sum(1 for e in q if e.status >= 400)
        unique_paths = len({e.path for e in q})
        avg_param_len = sum(self._param_length(e.path) for e in q) / max(1, total)
        avg_agent_entropy = sum(self._agent_entropy(e.agent) for e in q) / max(1, total)

        b = self.baseline[ev.ip]
        a = self.ema_alpha
        def ema(cur, new): return (1-a)*cur + a*new
        def update_var(cur_var, cur_mean, new):
            diff = new - cur_mean
            return (1-a)*cur_var + a*(diff*diff)

        b.var_rate = update_var(b.var_rate, b.ema_rate, total); b.ema_rate = ema(b.ema_rate, total)
        b.var_errors = update_var(b.var_errors, b.ema_errors, errors); b.ema_errors = ema(b.ema_errors, errors)
        b.var_unique_paths = update_var(b.var_unique_paths, b.ema_unique_paths, unique_paths); b.ema_unique_paths = ema(b.ema_unique_paths, unique_paths)
        b.var_param_len = update_var(b.var_param_len, b.ema_param_len, avg_param_len); b.ema_param_len = ema(b.ema_param_len, avg_param_len)
        b.var_agent_entropy = update_var(b.var_agent_entropy, b.ema_agent_entropy, avg_agent_entropy); b.ema_agent_entropy = ema(b.ema_agent_entropy, avg_agent_entropy)

        def z(new, mean, var):
            std = max(1e-3, var ** 0.5)
            return (new - mean) / std

        z_rate = max(0.0, z(total, b.ema_rate, b.var_rate))
        z_err = max(0.0, z(errors, b.ema_errors, b.var_errors))
        z_upath = max(0.0, z(unique_paths, b.ema_unique_paths, b.var_unique_paths))
        z_param = max(0.0, z(avg_param_len, b.ema_param_len, b.var_param_len))
        z_agent = max(0.0, z(avg_agent_entropy, b.ema_agent_entropy, b.var_agent_entropy))
        return z_rate + z_err + z_upath + z_param + z_agent
