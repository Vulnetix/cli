# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_284

import rego.v1

metadata := {
	"id": "VNX-284",
	"name": "Improper Access Control (IDOR)",
	"description": "The software does not restrict access to a resource in a way that allows an attacker to directly reference that resource using an identifier they control (Insecure Direct Object Reference). An attacker can access or modify other users' data by manipulating object identifiers.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-284/",
	"languages": ["python", "ruby", "node", "java", "php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [284],
	"capec": ["CAPEC-122"],
	"attack_technique": ["T1548"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["access-control", "idor", "authorization", "direct-object-reference", "cwe-284"],
}

_skip(path) if endswith(path, ".lock")
_skip(path) if endswith(path, ".sum")
_skip(path) if endswith(path, ".min.js")
_skip(path) if endswith(path, ".min.css")

_is_comment_line(line) if startswith(trim_space(line), "//")
_is_comment_line(line) if startswith(trim_space(line), "*")
_is_comment_line(line) if startswith(trim_space(line), "/*")
_is_comment_line(line) if startswith(trim_space(line), "#")

# Python Django: User.objects.get(id=request.GET['id']) without current_user check
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".py")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, ".objects.get(")
	some _ap_60f700 in {"request.GET[", "request.POST[", "request.data["}
	contains(line, _ap_60f700)
	finding := {
		"rule_id": metadata.id,
		"message": "Direct object lookup using user-supplied ID without ownership verification. Add an ownership check (e.g., filter by request.user) to prevent IDOR: use .get(id=..., user=request.user) or equivalent.",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Ruby Rails: User.find(params[:id]) - IDOR pattern
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".rb")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, ".find(params[")
	not contains(line, "current_user")
	finding := {
		"rule_id": metadata.id,
		"message": "Direct object reference via .find(params[:id]) without current_user scope. Scope the query to the current user (e.g., current_user.records.find(params[:id])) to prevent IDOR.",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Node.js: db.findById(req.params.id) without auth check in same block
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	some _ext in {".js", ".ts"}
	endswith(path, _ext)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _ap_a47bcd in {"findById(req.params", "findById(req.query", "findOne({id: req.params"}
	contains(line, _ap_a47bcd)
	finding := {
		"rule_id": metadata.id,
		"message": "Direct object lookup using request parameter without ownership verification. Verify the returned object belongs to the authenticated user before returning or modifying it.",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Java: entity.findById(request.getParameter("id")) without auth check
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".java")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	contains(line, "findById(")
	contains(line, "request.getParameter(")
	finding := {
		"rule_id": metadata.id,
		"message": "Direct object reference from request parameter passed to findById() without authorization check. Verify that the retrieved entity belongs to the authenticated principal.",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# PHP: direct lookup using $_GET/$_POST id
findings contains finding if {
	some path in object.keys(input.file_contents)
	not _skip(path)
	endswith(path, ".php")
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	not _is_comment_line(line)
	some _ap_fad142 in {"$_GET['id']", "$_POST['id']", "$_REQUEST['id']"}
	contains(line, _ap_fad142)
	some _ap_691fc5 in {"WHERE id =", "findById", "find_by_id"}
	contains(line, _ap_691fc5)
	finding := {
		"rule_id": metadata.id,
		"message": "Direct database lookup using user-supplied 'id' without authorization check. Verify that the retrieved record belongs to the current authenticated user before processing.",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
