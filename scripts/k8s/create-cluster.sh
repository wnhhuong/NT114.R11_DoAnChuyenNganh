#!/usr/bin/env bash
# Tạo cluster kind "nt114" có audit log. Chạy từ bất kỳ đâu trong repo.
set -euo pipefail
cd "$(dirname "$0")/../.."

POLICY="$(pwd)/k8s/kind/audit-policy.yaml"
TMP_CONFIG="$(mktemp)"
sed "s#__AUDIT_POLICY__#${POLICY}#" k8s/kind/kind-config.yaml > "$TMP_CONFIG"

kind create cluster --config "$TMP_CONFIG" --wait 120s
rm -f "$TMP_CONFIG"

kubectl cluster-info --context kind-nt114
kubectl get nodes -o wide
