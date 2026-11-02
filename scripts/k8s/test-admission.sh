#!/usr/bin/env bash
# Thử tạo Pod trong namespace demo (server-side dry-run: qua đủ admission nhưng không chạy thật)
# với từng image, ghi kết quả + thời gian. Usage: scripts/k8s/test-admission.sh [số lần lặp, mặc định 1]
set -uo pipefail
N="${1:-1}"
H="harbor.nt114.local:30002/ghcr/wnhhuong/nt114.r11_doanchuyennganh"
G="ghcr.io/wnhhuong/nt114.r11_doanchuyennganh"
TAG="secure-$(git rev-parse bab2670 2>/dev/null || echo bab2670)"

CASES=(
  "GD3-25 hop le|$H@sha256:2ac1abe5f98b448eadd1460e28482b0ad7cab7011d4ebdb531b3905e3edb157d|ALLOW"
  "GD3-26 lo hong|$H@sha256:23fe5d29b9a08a8539b9c4ae24e8ed1f8b9e9034cb231f8ad5533c75ff460231|DENY"
  "GD3-27 khong chu ky|$H@sha256:d8dee24d9266c032d074fb3ee6f84dc1afc59ee898d3c3a2b2980b75ddd5de32|DENY"
  "GD3-28 khong provenance|$H@sha256:96adf84fa88b1515f9be517ec9f3b38580eb4cddd3909fce78c462decbc924ee|DENY"
  "GD3-29 policy strict|$H@sha256:d702f2794a95a7bed9aa75459ad0a7ff8f62d5dd824fac99e6d9702f014e30ba|DENY"
  "GD2-case1 chua qua engine|$H@sha256:22b18fc83ad4c7d43fd70f203201aeaa4577f4965dbf56e8f8d4d44b88c31b4e|DENY"
  "Bo qua Harbor (GHCR)|$G@sha256:2ac1abe5f98b448eadd1460e28482b0ad7cab7011d4ebdb531b3905e3edb157d|DENY"
  "Image Docker Hub|docker.io/library/nginx:1.27-alpine|DENY"
  "Dung tag thay digest|$H:$TAG|DENY"
)

printf "case\texpected\tgot\tms\tmessage\n"
for c in "${CASES[@]}"; do
  IFS='|' read -r name image expect <<<"$c"
  for _ in $(seq 1 "$N"); do
    start=$(date +%s%N)
    # Pod hợp lệ với Pod Security "restricted" để chỉ Kyverno là yếu tố quyết định
    out=$(kubectl apply --dry-run=server -o name -f - 2>&1 <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: admission-test-$RANDOM
  namespace: demo
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile: { type: RuntimeDefault }
  containers:
    - name: app
      image: $image
      resources: { limits: { memory: 512Mi } }
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: { drop: [ALL] }
EOF
)
    rc=$?
    ms=$(( ($(date +%s%N) - start) / 1000000 ))
    got=$([ $rc -eq 0 ] && echo ALLOW || echo DENY)
    msg=$(echo "$out" | tr '\n\t' '  ' | cut -c1-220)
    printf "%s\t%s\t%s\t%s\t%s\n" "$name" "$expect" "$got" "$ms" "$msg"
  done
done
