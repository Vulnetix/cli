package vulnetix.rules.vnx_node_032

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-NODE-032",
	"name": "Angular DomSanitizer bypass with a non-constant value",
	"description": "Reports a call to an Angular DomSanitizer bypassSecurityTrustHtml, bypassSecurityTrustStyle, bypassSecurityTrustScript, bypassSecurityTrustUrl or bypassSecurityTrustResourceUrl whose argument is not a constant. These calls tell Angular to stop sanitising the value, so a value that carries user, API or database data becomes stored or DOM cross-site scripting. The argument may start on the line after the opening parenthesis. Not reported: a string literal or a template literal with no interpolation, an ALL_CAPS constant (or a dotted path of them), comments, and test and spec files (*.spec.ts, *.test.ts, __tests__, e2e directories). A value that was sanitised with sanitize() first is still reported, because the bypass call then re-trusts whatever remains.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-node-032/",
	"languages": ["node"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-63"],
	"attack_technique": ["T1059.007"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xss", "angular", "sanitization-bypass", "typescript"],
}

_is_js(path) if endswith(path, ".ts")
_is_js(path) if endswith(path, ".js")
_is_js(path) if endswith(path, ".tsx")
_is_js(path) if endswith(path, ".jsx")
_is_js(path) if endswith(path, ".mjs")

_call_re := `^(.*?)\.bypassSecurityTrust(?:Html|Style|Script|Url|ResourceUrl)\s*\((.*)$`

# True when the text before the call has an unclosed quote, i.e. the call is
# inside a string literal.
_in_string(prefix) if count(split(prefix, "'")) % 2 == 0

_in_string(prefix) if count(split(prefix, "\"")) % 2 == 0

_in_string(prefix) if count(split(prefix, "`")) % 2 == 0

_const_re := "^\\s*(?:'[^'\\\\]*'|\"[^\"\\\\]*\"|`[^`$\\\\]*`|[A-Z][A-Z0-9_]*(?:\\.[A-Z][A-Z0-9_]*)*)\\s*(?:\\)|$)"

# The argument text: the rest of the line, or the next code line when the
# parenthesis ends the line.
_arg(lines, i, rest) := rest if trim_space(rest) != ""

_arg(lines, i, rest) := lines[i + 1] if {
	trim_space(rest) == ""
	i + 1 < count(lines)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	not endswith(path, ".min.js")
	not helpers.is_test_path(path)
	contains(content, "bypassSecurityTrust")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "bypassSecurityTrust")
	count(line) < 1000
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_call_re, line, 1)
	count(m) > 0
	not _in_string(m[0][1])
	arg := _arg(lines, i, m[0][2])
	not regex.match(_const_re, arg)
	finding := {
		"rule_id": metadata.id,
		"message": "DomSanitizer.bypassSecurityTrust* is called with a non-constant value; Angular will not sanitise it, so any user-controlled data in it is cross-site scripting. Bind the value as text or sanitise it with a vetted library and pass only the result",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
