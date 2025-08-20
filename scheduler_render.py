import os, time, requests

API_BASE = os.environ.get("API_BASE", "https://threathawk.onrender.com").rstrip("/")
API_KEY  = os.environ.get("X_API_KEY", "thk_live_CHANGE_ME")

def run_once():
    url = f"{API_BASE}/ingest?source=cloudflare&minutes=5"
    print(f"[scheduler] POST {url}")
    r = requests.post(url, headers={"X-API-Key": API_KEY}, timeout=30)
    print("[scheduler] status:", r.status_code, r.text[:200])

if __name__ == "__main__":
    while True:
        try:
            run_once()
        except Exception as e:
            print("[scheduler] error:", e)
        time.sleep(300)  # 5 min
