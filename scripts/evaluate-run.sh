#!/usr/bin/env bash
# Tải evidence của một lần chạy secure-ci và đánh giá lại offline bằng Trust Evaluation Engine.
# Usage: scripts/evaluate-run.sh RUN_ID [default|strict]
set -euo pipefail

run_id="${1:?Usage: scripts/evaluate-run.sh RUN_ID [policy]}"
policy="${2:-default}"

command -v gh >/dev/null || { echo "Cần GitHub CLI (gh)" >&2; exit 1; }
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

dir="results/evidence/run-$run_id"
rm -rf "$dir"
mkdir -p "$dir"
gh run download "$run_id" --pattern 'evidence-*' -D "$dir"

out="results/decisions/run-$run_id-$policy"
mkdir -p "$(dirname "$out")"
PYTHONPATH=trust-engine python3 -m trust_engine evaluate \
  --evidence "$dir" \
  --policy "trust-engine/policy/$policy.yaml" \
  --out "$out.json" --markdown "$out.md" --no-fail >/dev/null

jq -r --arg run "$run_id" --arg policy "$policy" '
  [$run, $policy, .decision, .trust_score,
   (.violations | map(.id) | join(",")),
   (.warnings | map(.id) | join(",")),
   .evaluation_ms] | @tsv' "$out.json"
