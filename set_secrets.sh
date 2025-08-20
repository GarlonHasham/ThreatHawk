#!/usr/bin/env bash
set -euo pipefail
API_KEY="${API_KEY:-thk_live_CHANGE_ME}"
CF_API_TOKEN="${CF_API_TOKEN:-cf_live_CHANGE_ME}"
CF_ZONE_ID="${CF_ZONE_ID:-CHANGE_ZONE}"

printf "%s" "$API_KEY" | gcloud secrets create threathawk_api_key --data-file=- || gcloud secrets versions add threathawk_api_key --data-file=<(printf "%s" "$API_KEY")

printf "%s" "$CF_API_TOKEN" | gcloud secrets create cf_api_token --data-file=- || gcloud secrets versions add cf_api_token --data-file=<(printf "%s" "$CF_API_TOKEN")

printf "%s" "$CF_ZONE_ID" | gcloud secrets create cf_zone_id --data-file=- || gcloud secrets versions add cf_zone_id --data-file=<(printf "%s" "$CF_ZONE_ID")

printf "false" | gcloud secrets create threathawk_ban_enabled --data-file=- || gcloud secrets versions add threathawk_ban_enabled --data-file=<(printf "false")

echo "Secrets created/updated."
