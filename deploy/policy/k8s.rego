# Policy-as-code cho manifest Kubernetes, chạy bằng conftest trong CI TRƯỚC khi manifest vào Git.
# Kyverno kiểm tra artifact (chữ ký, decision); file này kiểm tra cấu hình triển khai.
package main

import rego.v1

allowed_image := "harbor.nt114.local:30002/ghcr/wnhhuong/nt114.r11_doanchuyennganh"

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job", "Rollout"}

pod_spec := input.spec.template.spec if input.kind in workload_kinds

pod_spec := input.spec if input.kind == "Pod"

in_demo if input.metadata.namespace == "demo"

name := sprintf("%s/%s", [input.kind, input.metadata.name])

deny contains msg if {
	in_demo
	some c in pod_spec.containers
	not startswith(c.image, allowed_image)
	msg := sprintf("%s: image %q phải lấy từ %s", [name, c.image, allowed_image])
}

deny contains msg if {
	in_demo
	some c in pod_spec.containers
	not contains(c.image, "@sha256:")
	msg := sprintf("%s: image %q phải ghim theo digest (@sha256:...), không dùng tag", [name, c.image])
}

deny contains msg if {
	in_demo
	pod_spec
	not pod_spec.securityContext.runAsNonRoot == true
	msg := sprintf("%s: thiếu securityContext.runAsNonRoot: true", [name])
}

deny contains msg if {
	in_demo
	some c in pod_spec.containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("%s: container %q phải đặt allowPrivilegeEscalation: false", [name, c.name])
}

deny contains msg if {
	in_demo
	some c in pod_spec.containers
	c.securityContext.privileged == true
	msg := sprintf("%s: container %q không được privileged", [name, c.name])
}

deny contains msg if {
	in_demo
	some c in pod_spec.containers
	not c.resources.limits.memory
	msg := sprintf("%s: container %q thiếu resources.limits.memory", [name, c.name])
}
