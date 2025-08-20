# ThreatHawk — Render Deployment Pack (Free-tier friendly)

This pack lets you deploy the ThreatHawk API on **Render.com** with a free plan.
It provides:
- A **Web Service** (FastAPI) to serve `/health`, `/findings`, `/ban`, `/ingest`.
- Two ways to automate ingestion of logs from **Cloudflare Logpull**:
  1) **Render Cron Job** (recommended) that calls `POST /ingest` every 5 minutes.
  2) An optional **Background Worker** (`scheduler_render.py`) which self-schedules.

> You only need **one** of the two ingestion options. The Cron job is simpler.

## 0) What you need
- A free account on https://render.com
- Your **Cloudflare** API Token (with Zone Logs Read) and **Zone ID** if you want automatic ingest.
- Your own API Key for the agent, e.g. `thk_live_CHANGE_ME`

## 1) Deploy the Web Service (API)
1. Create a new **Web Service** on Render and connect this folder as a repo or upload it.
2. When prompted, set:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn threathawk.server:app --host 0.0.0.0 --port $PORT`
3. Set **Environment Variables** in the service:
   - `THREATHAWK_API_KEY=thk_live_CHANGE_ME`  (choose your own secure key)
   - `THREATHAWK_FINDINGS_PATH=/tmp/findings.jsonl`  (ephemeral on free tier)
   - `THREATHAWK_BAN_ENABLED=false`
   - If using Cloudflare:
     - `CF_API_TOKEN=cf_live_YOURTOKEN`
     - `CF_ZONE_ID=YOUR_ZONE_ID`
4. Click **Create Web Service**. After a few minutes, Render gives you a URL like:
   `https://threathawk.onrender.com`

### Verify
```
curl -H "X-API-Key: thk_live_CHANGE_ME" https://threathawk.onrender.com/health
# -> {"ok": true}
```

## 2) Automate ingestion (choose ONE)

### Option A — Render Cron Job (recommended)
1. In Render dashboard: **New** → **Cron Job**.
2. Schedule: `*/5 * * * *` (every 5 minutes), Region same as service.
3. Request:
   - **Method**: `POST`
   - **URL**: `https://YOUR_SERVICE.onrender.com/ingest?source=cloudflare&minutes=5`
   - **Headers**: `X-API-Key: thk_live_CHANGE_ME`
4. Save. The job will keep the findings up to date.

### Option B — Background Worker (alternative)
1. Create a **Background Worker** from this repo.
2. Build Command: `pip install -r requirements.txt`
3. Start Command: `python scheduler_render.py`
4. Env vars: same as the Web Service (needs the API key & Cloudflare vars).

> On the free tier, worker or web service may sleep when idle; Cron is more reliable.

## 3) Connect to your ChatGPT GPT (Action)
- Use **Server URL** = `https://YOUR_SERVICE.onrender.com`
- Auth: **API Key**, header `X-API-Key`, value = your `THREATHAWK_API_KEY`
- Import `openapi.render.threathawk.yaml` when creating the Action.

## 4) Notes about free tier
- Storage is **ephemeral** (`/tmp`), so findings reset on redeploy. To persist, add a free external sink (Slack webhook for alerts, or a cheap database). For simplicity we keep JSONL on disk and rely on Cron for fresh data.
- Do **not** enable auto-ban in production without review.

