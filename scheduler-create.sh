#!/usr/bin/env bash
set -euo pipefail
SERVICE_URL="${1:?Pass Cloud Run URL as first arg}"
REGION="${REGION:-europe-west4}"
JOB="${JOB:-threathawk-ingest}"
# Create a job that hits /ingest every 5 minutes
gcloud scheduler jobs create http "$JOB"   --schedule="*/5 * * * *"   --time-zone="Europe/Amsterdam"   --uri="${SERVICE_URL}/ingest?source=cloudflare&minutes=5"   --http-method=POST   --headers="X-API-Key=$(gcloud secrets versions access latest --secret=threathawk_api_key)"   --location="$REGION" || gcloud scheduler jobs update http "$JOB"   --schedule="*/5 * * * *"   --time-zone="Europe/Amsterdam"   --uri="${SERVICE_URL}/ingest?source=cloudflare&minutes=5"   --http-method=POST   --headers="X-API-Key=$(gcloud secrets versions access latest --secret=threathawk_api_key)"   --location="$REGION"
echo "Scheduler configured."
