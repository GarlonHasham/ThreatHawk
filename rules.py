from __future__ import annotations
import re, yaml
from dataclasses import dataclass
from typing import List, Optional

@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    severity: int
    mitre: str
    desc: str = ""

DEFAULTS = [
    ("SQLi.union_select", r"union\s+select|information_schema|sleep\s*\(|benchmark\s*\(", 5, "T1190", "SQL injection payloads"),
    ("SQLi.boolean", r"(?:'|%27)\s*or\s*1=1|--|/\*|\*/", 4, "T1190", "Boolean SQLi markers"),
    ("XSS.script_tag", r"<\s*script|javascript:|onerror\s*=|onload\s*=", 4, "T1190", "XSS indicators"),
    ("LFI.path_traversal", r"\.\./|\.%2e%2e/|%2e%2e%2f|/etc/passwd|/proc/self", 5, "T1190", "LFI/traversal"),
    ("RCE.shell", r"(?:cmd|exec|system|passthru)\s*\(|bash\s+-c|;\s*\$?\(\w+\)", 5, "T1059", "Command exec"),
    ("Scanner.user_agent", r"sqlmap|acunetix|nessus|nikto|burp|dirbuster", 3, "T1190", "Scanner UA"),
    ("WP.attack_surface", r"/wp-login\.php|/wp-admin|/xmlrpc\.php", 3, "T1190", "WordPress surface"),
    ("Auth.bruteforce", r"/login|/admin|/account/login", 3, "T1110", "Bruteforce/login surface"),
]

def load_rules(yaml_path: Optional[str]) -> List[Rule]:
    rules: List[Rule] = []
    if yaml_path:
        try:
            data = yaml.safe_load(open(yaml_path, "r")) or {}
            for r in data.get("rules", []):
                rules.append(Rule(
                    name=r.get("name", "rule"),
                    pattern=re.compile(r.get("regex",""), re.IGNORECASE),
                    severity=int(r.get("severity",3)),
                    mitre=r.get("mitre","T1190"),
                    desc=r.get("desc",""),
                ))
        except FileNotFoundError:
            pass
    for name, rx, sev, mitre, desc in DEFAULTS:
        rules.append(Rule(name, re.compile(rx, re.IGNORECASE), sev, mitre, desc))
    return rules
