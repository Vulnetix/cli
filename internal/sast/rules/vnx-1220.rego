# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1220

import rego.v1

metadata := {
	"id": "VNX-1220",
	"name": "Insufficient Granularity of Access Control",
	"description": "Access control is implemented with only coarse-grained checks (e.g. is_admin / not is_admin) without fine-grained permission checks for specific actions or resources. Attackers who gain any elevated role can perform any administrative action regardless of their actual intended access scope.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1220/",
	"languages": ["python", "javascript", "java", "go", "php", "ruby"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1220],
	"capec": ["CAPEC-122"],
	"attack_technique": ["T1078"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["access-control", "authorization", "rbac", "permissions", "cwe-1220"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")

# Coarse-grained is_admin-only checks
_coarse_admin_patterns := {
	"if is_admin",
	"if user.is_admin",
	"if current_user.is_admin",
	"if request.user.is_admin",
	"if user.admin",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _coarse_admin_patterns
	contains(line, p)
	not contains(line, "permission")
	not contains(line, "has_perm")
	not contains(line, "can_")
	not startswith(trim_space(line), "#")
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Coarse-grained access check '%s' without fine-grained permission validation; implement RBAC or ABAC with specific permission checks (e.g. user.has_perm('app.delete_record')) rather than relying solely on admin status", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Django coarse decorators
_django_coarse_decorators := {
	"@staff_member_required",
	"user_passes_test(lambda u: u.is_superuser",
	"user_passes_test(lambda u: u.is_staff",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _django_coarse_decorators
	contains(line, p)
	not startswith(trim_space(line), "#")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Coarse access control decorator '%s' detected; consider object-level permissions (django-guardian, DRF permissions) for fine-grained access control", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Node.js: simple admin-only middleware
_node_admin_check_patterns := {
	"req.user.isAdmin",
	"req.session.isAdmin",
}

findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	some p in _node_admin_check_patterns
	contains(line, p)
	not contains(line, "permission")
	not contains(line, "hasPermission")
	not contains(line, "can(")
	not startswith(trim_space(line), "//")
	not startswith(trim_space(line), "*")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Coarse admin role check '%s' without resource-level permissions; implement fine-grained permission checks per action and resource type", [p]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
