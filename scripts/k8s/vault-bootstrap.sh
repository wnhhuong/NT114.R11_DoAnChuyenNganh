#!/usr/bin/env bash
# Cài HashiCorp Vault (dev mode) làm nơi lưu secret tập trung, cấu hình Kubernetes auth cho
# External Secrets và nạp các secret nt114/*. Chạy lại an toàn; PHẢI chạy lại sau khi Pod vault-0
# khởi động lại (dev mode lưu trong RAM). Secret không bao giờ được in ra hay ghi vào file.
#
# Usage: scripts/k8s/vault-bootstrap.sh
#        ROTATE=1 scripts/k8s/vault-bootstrap.sh                 # xoay vòng mật khẩu (kịch bản K12)
#        DISCORD_WEBHOOK_URL=... scripts/k8s/vault-bootstrap.sh  # đặt webhook Discord thật
set -euo pipefail
cd "$(dirname "$0")/../.."
NS=vault

if ! helm status vault -n "$NS" >/dev/null 2>&1; then
  # Root token ngẫu nhiên, chỉ nằm trong cluster (env của Pod vault-0)
  helm install vault hashicorp/vault -n "$NS" --create-namespace -f k8s/values/vault.yaml \
    --set server.dev.devRootToken="$(openssl rand -hex 16)" --wait --timeout 10m
fi
kubectl -n "$NS" wait --for=condition=Ready pod/vault-0 --timeout=180s

# Chạy CLI vault trong Pod, dùng root token lấy từ env của chính Pod
v() { kubectl -n "$NS" exec -i vault-0 -- sh -c 'VAULT_TOKEN="$VAULT_DEV_ROOT_TOKEN_ID" vault "$@"' vault "$@"; }

# 1) Kubernetes auth: ESO đăng nhập bằng token ServiceAccount của nó => không cần credential tĩnh ("secret zero")
v auth list -format=json | grep -q '"kubernetes/"' || v auth enable kubernetes
v write auth/kubernetes/config kubernetes_host="https://kubernetes.default.svc:443" >/dev/null
v policy write nt114-eso-read - < k8s/secrets/vault-policy.hcl
v write auth/kubernetes/role/external-secrets \
  bound_service_account_names=external-secrets \
  bound_service_account_namespaces=external-secrets \
  audience=vault token_policies=nt114-eso-read token_ttl=1h >/dev/null

# 2) Secret nt114/* (KV v2 tại secret/, dev mode bật sẵn). Giá trị đi qua stdin, không nằm trong tham số lệnh
exists() { v kv get "secret/$1" >/dev/null 2>&1; }
gen() { printf 'Nt114-%s' "$(openssl rand -hex 8)"; }   # chữ hoa + thường + số (Harbor yêu cầu)

if [ "${ROTATE:-0}" = 1 ] || ! exists nt114/harbor-admin; then
  gen | v kv put secret/nt114/harbor-admin password=- >/dev/null
fi
if [ "${ROTATE:-0}" = 1 ] || ! exists nt114/grafana-admin; then
  gen | v kv put secret/nt114/grafana-admin username=admin password=- >/dev/null
fi
if [ -n "${DISCORD_WEBHOOK_URL:-}" ] || ! exists nt114/alertmanager-discord; then
  printf '%s' "${DISCORD_WEBHOOK_URL:-https://discord.com/api/webhooks/0/placeholder}" \
    | v kv put secret/nt114/alertmanager-discord webhook_url=- >/dev/null
fi

v kv list secret/nt114
echo "OK: Vault sẵn sàng cho External Secrets"
