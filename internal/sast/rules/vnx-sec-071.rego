package vulnetix.rules.vnx_sec_071

import data.vulnetix.lib.secrets
import rego.v1

metadata := {
	"id": "VNX-SEC-071",
	"name": "GitLab session cookie",
	"description": "Reports a captured GitLab session cookie value: _gitlab_session followed by = (a Cookie header, document.cookie, a curl -b/-H argument) by a quoted or symbol key and : / = / => (a cookies dict, hash or object), by a call argument pair (cookies.set(\"_gitlab_session\", \"...\")) or by a tab (Netscape cookies.txt), or a cookie object whose \"name\" is _gitlab_session and whose \"value\" (on the same line or up to 12 lines below, inside the same object, as browser cookie exports write it) is set, and then a 32-character lowercase hexadecimal session id, in any file. The value is masked in the snippet. Not reported: the cookie name on its own (Rails session_store key: \"_gitlab_session\"), a value read from a variable or the environment, placeholder values (all zeros, xxxx...), and generated, vendored and test-suffixed files and testdata/fixtures directories.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-071/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "secrets",
	"cwe": [798],
	"capec": ["CAPEC-191"],
	"attack_technique": ["T1552.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["secrets", "gitlab", "session", "credentials"],
}

_hexval := `([0-9a-f]{32})(?:[^0-9a-zA-Z]|$)`

# _gitlab_session=VALUE, a quoted or symbol key then : / = / =>, a call
# argument pair ("_gitlab_session", "VALUE") and a Netscape cookies.txt tab.
_inline := concat("", [`_gitlab_session(?:=|\t|['"]?\s*[:=]>?\s*['"\x60]|['"]\s*,\s*['"\x60])`, _hexval])

# A cookie object: {"name": "_gitlab_session", ..., "value": "VALUE"}.
_name_key := `['"]name['"]\s*:\s*['"]_gitlab_session['"]`

_value_key := concat("", [`['"]value['"]\s*:\s*['"]`, _hexval])

_ok(v) if {
	not secrets.is_placeholder(v)
	secrets.high_entropy(v, 3.0)
}

_inline_values(lines, i) := {m[1] |
	contains(lines[i], "_gitlab_session")
	some m in regex.find_all_string_submatch_n(_inline, lines[i], -1)
	_ok(m[1])
}

_object_values(lines, i) := {m[1] |
	contains(lines[i], "_gitlab_session")
	regex.match(_name_key, lines[i])
	some m in regex.find_all_string_submatch_n(_value_key, lines[i], -1)
	_ok(m[1])
}

# The value key on a later line of the same cookie object (browser cookie
# exports list domain, name, path, ... value one per line).
_later_values(lines, i) := {m[1] |
	not contains(lines[i], "_gitlab_session")
	regex.match(`['"]value['"]\s*:`, lines[i])
	some j in numbers.range(max([0, i - 12]), i - 1)
	regex.match(_name_key, lines[j])
	every k in numbers.range(j, i - 1) {
		not contains(lines[k], "}")
	}
	some m in regex.find_all_string_submatch_n(_value_key, lines[i], -1)
	_ok(m[1])
}

findings contains finding if {
	some path, content in input.file_contents
	contains(content, "_gitlab_session")
	not secrets.skip_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`_gitlab_session|['"]value['"]\s*:`, line)
	some v in (_inline_values(lines, i) | _object_values(lines, i)) | _later_values(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "GitLab session cookie value found; revoke the session under GitLab User Settings > Active sessions and never commit browser cookies",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": replace(line, v, "***"),
	}
}
