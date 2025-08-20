import requests, datetime

# Fetch last N minutes of logs from Cloudflare Logpull v1 (HTTP requests)
# Note: Cloudflare returns JSON lines with fields; we convert to a combined-like line for our parser.
# This is a simplified mapper sufficient for the MVP.

def fetch_last_minutes(api_token: str, zone_id: str, minutes: int = 5):
    end = datetime.datetime.utcnow()
    start = end - datetime.timedelta(minutes=minutes)
    # Build request
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
    for obj in r.iter_lines(decode_unicode=True):
        if not obj:
            continue
        try:
            import json
            rec = json.loads(obj)
            ip = rec.get("ClientIP","-")
            ts = datetime.datetime.utcfromtimestamp(rec.get("EdgeStartTimestamp",0)).strftime("%d/%b/%Y:%H:%M:%S +0000")
            method = rec.get("ClientRequestMethod","GET")
            path = rec.get("ClientRequestURI","/")
            proto = f"HTTP/{rec.get('ClientRequestProtocol','1.1')}"
            status = rec.get("EdgeResponseStatus",200)
            agent = rec.get("ClientRequestUserAgent","")
            # Compose a combined-like log line for our parser
            line = f'{ip} - - [{ts}] "{method} {path} {proto}" {status} 0 "-" "{agent}"'
            lines.append(line)
        except Exception:
            continue
    return lines
