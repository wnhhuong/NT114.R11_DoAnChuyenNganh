package main

import rego.v1

rollout(image, non_root) := {
	"kind": "Rollout",
	"metadata": {"name": "demo-app", "namespace": "demo"},
	"spec": {"template": {"spec": {
		"securityContext": {"runAsNonRoot": non_root},
		"containers": [{
			"name": "app",
			"image": image,
			"resources": {"limits": {"memory": "512Mi"}},
			"securityContext": {"allowPrivilegeEscalation": false},
		}],
	}}},
}

good_image := "harbor.nt114.local:30002/ghcr/wnhhuong/nt114.r11_doanchuyennganh@sha256:abc"

test_allow_valid_rollout if {
	msgs := deny with input as rollout(good_image, true)
	count(msgs) == 0
}

test_deny_tag if {
	msgs := deny with input as rollout("harbor.nt114.local:30002/ghcr/wnhhuong/nt114.r11_doanchuyennganh:latest", true)
	some m in msgs
	contains(m, "digest")
}

test_deny_other_registry if {
	msgs := deny with input as rollout("ghcr.io/wnhhuong/nt114.r11_doanchuyennganh@sha256:abc", true)
	some m in msgs
	contains(m, "phải lấy từ")
}

test_deny_root if {
	msgs := deny with input as rollout(good_image, false)
	some m in msgs
	contains(m, "runAsNonRoot")
}

test_other_namespace_ignored if {
	obj := json.patch(rollout("nginx:latest", false), [{"op": "replace", "path": "/metadata/namespace", "value": "loadgen"}])
	msgs := deny with input as obj
	count(msgs) == 0
}
