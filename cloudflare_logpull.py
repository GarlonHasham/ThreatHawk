import requests, datetime, json

def fetch_last_minutes(api_token: str, zone_id: str, minutes: int = 5):
    end = datetime.datetime.utcnow()
    start = end - datetime.timedelta(minutes=minutes)
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
        if not line: continue
        try:
            rec = json.loads(line)
            ip = rec.get("ClientIP","-")
            ts = datetime.datetime.utcfromtimestamp(rec.get("EdgeStartTimestamp",0)).strftime("%d/%b/%Y:%H:%M:%S +0000")
            method = rec.get("ClientRequestMethod","GET")
            path = rec.get("ClientRequestURI","/")
            proto = f"HTTP/{rec.get('ClientRequestProtocol','1.1')}"
            status = rec.get("EdgeResponseStatus",200)
            agent = rec.get("ClientRequestUserAgent","")
            combined = f'{ip} - - [{ts}] "{method} {path} {proto}" {status} 0 "-" "{agent}"'
            lines.append(combined)
        except Exception:
            continue
    return lines
