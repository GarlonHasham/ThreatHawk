#!/usr/bin/env bash
set -euo pipefail
REGION="${REGION:-europe-west4}"
PROJECT_ID="$(gcloud config get-value project)"
REPO="${REPO:-threathawk}"
IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO/api:latest"
BUCKET="${BUCKET:?Set BUCKET=your-gcs-bucket}"

gcloud artifacts repositories create "$REPO" --repository-format=docker --location="$REGION" --description="ThreatHawk images" || true

# Build
gcloud builds submit --tag "$IMAGE"

# Enable GCS Fuse
gcloud run deploy threathawk   --image "$IMAGE"   --region "$REGION"   --platform managed   --allow-unauthenticated   --port 8000   --timeout 60   --update-secrets X_API_KEY=threathawk_api_key:latest,THREATHAWK_API_KEY=threathawk_api_key:latest,THREATHAWK_BAN_ENABLED=threathawk_ban_enabled:latest,CF_API_TOKEN=cf_api_token:latest,CF_ZONE_ID=cf_zone_id:latest   --set-env-vars THREATHAWK_FINDINGS_PATH=/data/findings.jsonl,THREATHAWK_BANLIST_PATH=/data/banlist.txt,THREATHAWK_BAN_ENABLED=false   --mounts=/data=gcsfuse:bucket=$BUCKET
