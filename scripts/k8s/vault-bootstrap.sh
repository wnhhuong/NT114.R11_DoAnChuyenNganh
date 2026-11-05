#!/usr/bin/env bash
# Cài HashiCorp Vault (dev mode) làm nơi lưu secret tập trung, cấu hình Kubernetes auth cho
# External Secrets và nạp các secret nt114/*. Chạy lại an toàn; PHẢI chạy lại sau khi Pod vault-0
# khởi động lại (dev mode lưu trong RAM). Khi Vault trống, giá trị được nạp lại từ K8s Secret hiện có
# nên mật khẩu giữ nguyên qua các lần restart. Secret không bao giờ được in ra hay ghi vào file.
#
# Usage: scripts/k8s/vault-bootstrap.sh
#        DISCORD_WEBHOOK_URL=... scripts/k8s/vault-bootstrap.sh  # đặt/xoay vòng webhook Discord (kịch bản K12)
#        ROTATE=1 scripts/k8s/vault-bootstrap.sh                 # sinh lại mật khẩu Harbor/Grafana
# Lưu ý ROTATE=1: Harbor và Grafana chỉ đọc mật khẩu admin ở lần khởi động đầu (lưu vào DB), nên K8s Secret
# đổi nhưng mật khẩu đăng nhập thì không — phải đổi thêm trong ứng dụng. K12 vì vậy xoay vòng webhook Discord.
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
# Giá trị cũ trong K8s Secret do ESO tạo (etcd vẫn giữ khi Vault dev mode mất dữ liệu). Dùng lại để
# mật khẩu không đổi sau mỗi lần restart — Harbor lưu mật khẩu admin trong DB nên đổi là không đăng nhập được.
k8s_val() { kubectl -n "$1" get secret "$2" -o go-template="{{index .data \"$3\" | base64decode}}" 2>/dev/null || true; }
gen_or_keep() { local old; old=$(k8s_val "$@"); if [ -n "$old" ] && [ "${ROTATE:-0}" != 1 ]; then printf '%s' "$old"; else gen; fi; }

if [ "${ROTATE:-0}" = 1 ] || ! exists nt114/harbor-admin; then
  gen_or_keep harbor harbor-admin HARBOR_ADMIN_PASSWORD | v kv put secret/nt114/harbor-admin password=- >/dev/null
fi
if [ "${ROTATE:-0}" = 1 ] || ! exists nt114/grafana-admin; then
  gen_or_keep monitoring grafana-admin admin-password | v kv put secret/nt114/grafana-admin username=admin password=- >/dev/null
fi
if [ -n "${DISCORD_WEBHOOK_URL:-}" ] || ! exists nt114/alertmanager-discord; then
  hook="${DISCORD_WEBHOOK_URL:-$(k8s_val monitoring alertmanager-discord webhook-url)}"
  printf '%s' "${hook:-https://discord.com/api/webhooks/0/placeholder}" \
    | v kv put secret/nt114/alertmanager-discord webhook_url=- >/dev/null
fi

v kv list secret/nt114
echo "OK: Vault sẵn sàng cho External Secrets"
