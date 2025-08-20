# ThreatHawk — Ultimate Pack (Cloud Run + Scheduler + Cloudflare + GCS persistence)

This pack makes your AI Agent truly hands‑off:
- **Cloud Run API** (serverless)
- **Cloud Scheduler** triggers **/ingest** every 5 minutes
- **Cloudflare Logpull** (no servers needed) — pull logs for your sites
- **GCS persistent storage** via **gcsfuse** (findings.jsonl survives restarts)
- **OpenAPI** ready for ChatGPT Action
- **Privacy page template** and GPT Configure snippet

## What you'll get
- `deploy-cloudrun-gcsfuse.sh` — deploys Cloud Run with GCS Fuse
- `scheduler-create.sh` — creates a Cloud Scheduler job to call `/ingest`
- `set_secrets.sh` — stores API keys/tokens safely
- `config.cloudrun.yaml` — server on, auto_run on
- `openapi.ultimate.threathawk.yaml` — includes `/health`, `/findings`, `/ban`, `/ingest`
- `privacy-template.md` — copy to your website
- Updated code:
  - `server.py` — adds `/ingest` endpoint
  - `integrations/cloudflare_logpull.py` — pulls last N minutes of logs
  - uses same detection engine (rules + anomaly)

> You do NOT need to manage VMs or Docker hosts. Cloud Run + Scheduler handle it.

---

## 0) Prereqs
```bash
gcloud config set project YOUR_PROJECT_ID
gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com   cloudscheduler.googleapis.com secretmanager.googleapis.com iam.googleapis.com
```

## 1) Secrets (one‑time)
```bash
# AI Agent API key (for GPT Action and internal auth)
API_KEY="thk_live_CHANGE_ME"

# Cloudflare (for logpull)
CF_API_TOKEN="cf_live_CHANGE_ME"   # needs Zone Logs Read permission
CF_ZONE_ID="your_zone_id_here"

# Create or update secrets
bash set_secrets.sh
```

## 2) Build image & deploy Cloud Run with GCS Fuse
```bash
# Create a bucket for persistence (once)
REGION=europe-west4
BUCKET=threathawk-findings-$RANDOM
gsutil mb -l $REGION gs://$BUCKET

# Deploy (builds image + mounts GCS via gcsfuse at /data)
BUCKET=$BUCKET REGION=$REGION bash deploy-cloudrun-gcsfuse.sh
```

This prints a **Service URL**, e.g. `https://threathawk-xyz-ew.a.run.app`

## 3) Create Cloud Scheduler job (5‑min ingestion)
```bash
REGION=europe-west4
SERVICE_URL="https://YOUR_CLOUD_RUN_URL"
bash scheduler-create.sh "$SERVICE_URL"
```
The job calls `POST $SERVICE_URL/ingest?source=cloudflare&minutes=5` with `X-API-Key`.

## 4) Verify
```bash
URL="https://YOUR_CLOUD_RUN_URL"
API_KEY="your API key"

curl -H "X-API-Key: $API_KEY" "$URL/health"        # -> {"ok": true}
curl -H "X-API-Key: $API_KEY" "$URL/findings"       # -> { items: [...], count: N }
```

## 5) Hook to ChatGPT (Action)
- Server URL: `https://YOUR_CLOUD_RUN_URL`
- Auth: API Key, header `X-API-Key`, value = your API key
- Import `openapi.ultimate.threathawk.yaml`

Now your AI Agent can fetch findings on demand; ingestion happens automatically.

---

## Notes
- Cloudflare Logpull time windows smaller than 5 min ensure you don't re‑ingest too much. The code dedupes on `(ip, ts, path)` best‑effort.
- You can add multiple sites by adding more **zone IDs** and scheduling per site (or extend `/ingest` to accept a list). This pack uses one zone for simplicity.
- If you don't use Cloudflare, adapt `integrations/*` to your log source and call `/ingest` similarly.
