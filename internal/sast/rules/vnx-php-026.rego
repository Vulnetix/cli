package vulnetix.rules.vnx_php_026

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-026",
	"name": "PHP session poisoning via user-controlled session key",
	"description": "A request value chooses which top-level session variable is written, so a client can overwrite trusted session state (user_id, role, an authenticated flag, a CSRF token). Reported: a write to $_SESSION[<key>] (=, .=, ??=, +=, or a nested write under it) whose key is a $_GET/$_POST/$_REQUEST/$_COOKIE element, or a variable whose nearest assignment within 20 lines above reads one of those, filter_input(INPUT_*), $request->input/get/query/post/cookie(), request('...') or Input::get(), or that is the key or value of a foreach over a superglobal or $request->all(); the same key passed to Session::put(), session()->put(), $request->session()->put(), $session->set() or ->set_userdata(); and copying a whole request array into the session ($_SESSION = array_merge($_SESSION, $_POST), array_replace, $_SESSION += $_GET). Not reported: literal or constant keys, request values stored as the value under a fixed key, a user key nested under a fixed outer key ($_SESSION['prefs'][$k]) or concatenated with a fixed prefix, reads of $_SESSION[$k], keys checked between source and write with in_array/array_key_exists/isset($allowed[$k])/preg_match/a comparison/switch/match, keys cast with intval or (int), variables reassigned to a constant before the write, and mentions inside strings or comments. Deeper flows (a key passed through a helper function or across files) are out of scope.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-026/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [284],
	"capec": ["CAPEC-61"],
	"attack_technique": ["T1565.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["session-poisoning", "session", "access-control", "php"],
}

_sg := `\$_(?:GET|POST|REQUEST|COOKIE)\b`

_src := concat("", [`(?:`, _sg, `|\bfilter_input\s*\(\s*INPUT_(?:GET|POST|COOKIE|REQUEST)|\$request->(?:input|get|query|post|cookie)\s*\(|\brequest\(\s*['"]|\bInput::get\s*\()`])

_assign := `(?:\s*\[[^\]]*\])*\s*(?:=(?:[^=>]|$)|\.=|\?\?=|\+=)`

# Remove string literals (keeping their quotes empty) and trailing comments.
_code(line) := c if {
	s := regex.replace(line, `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`, "''")
	c := regex.replace(s, `(?://|#).*$`, "")
}

_msg := "A request value chooses which $_SESSION key is written; a client can overwrite arbitrary session variables (role, user id, CSRF token). Use fixed key names, or validate the key against an allowlist"

# ── 1. superglobal element used directly as the key ──────────────────────
_direct_re := concat("", [`\$_SESSION\s*\[\s*`, _sg, `\s*\[[^\]]*\]\s*\]`, _assign])

_direct_guard := concat("", [`(?:\bin_array|\barray_key_exists|\bpreg_match|\bisset\s*\(\s*\$\w+\s*\[)\s*\(?[^;]*`, _sg])

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "$_SESSION")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "$_SESSION")
	not helpers.is_comment_line(line)
	c := _code(line)
	regex.match(_direct_re, c)
	not regex.match(_direct_guard, _code(helpers.code_window(lines, i, 3, 0)))
	finding := _finding(path, i, line)
}

# ── 2. a tainted variable used as the key ────────────────────────────────
_var_key_re := concat("", [`\$_SESSION\s*\[\s*\$([A-Za-z]\w*)\s*\]`, _assign])

_put_re := `(?:\bSession::put|\bsession\(\)\s*->\s*put|->\s*session\(\)\s*->\s*put|\$session\s*->\s*set|->\s*set_userdata)\s*\(\s*\$([A-Za-z]\w*)\s*,`

_sink_var(c) := v if {
	m := regex.find_all_string_submatch_n(_var_key_re, c, 1)
	count(m) > 0
	v := m[0][1]
}

_sink_var(c) := v if {
	m := regex.find_all_string_submatch_n(_put_re, c, 1)
	count(m) > 0
	v := m[0][1]
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	_sink_text(content)
	_source_text(content)
	lines := split(content, "\n")
	some i, line in lines
	_sink_text(line)
	not helpers.is_comment_line(line)
	c := _code(line)
	some v in {x | x := _sink_var(c)}
	_tainted_key(lines, i, v)
	finding := _finding(path, i, line)
}

# A framework put with a request value as the key directly.
_put_direct_re := concat("", [`(?:\bSession::put|\bsession\(\)\s*->\s*put|->\s*session\(\)\s*->\s*put|\$session\s*->\s*set|->\s*set_userdata)\s*\(\s*`, _src])

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	_put_text(content)
	lines := split(content, "\n")
	some i, line in lines
	_put_text(line)
	not helpers.is_comment_line(line)
	regex.match(_put_direct_re, _code(line))
	not regex.match(_direct_guard, _code(helpers.code_window(lines, i, 3, 0)))
	finding := _finding(path, i, line)
}

# Cheap text gates (file and line) before any regular expression.
_sink_text(t) if contains(t, "$_SESSION[")

_sink_text(t) if _put_text(t)

_put_text(t) if contains(t, "put(")

_put_text(t) if contains(t, "->set(")

_put_text(t) if contains(t, "set_userdata(")

_source_text(t) if contains(t, "$_")

_source_text(t) if contains(t, "filter_input")

_source_text(t) if contains(t, "request")

_source_text(t) if contains(t, "Input::")

_defines(line, v) if regex.match(concat("", [`^\s*\$`, v, `\s*(?:=[^=]|\?\?=|\.=)`]), line)

_defines(line, v) if regex.match(concat("", [`\bforeach\s*\(.*\bas\s+(?:\$\w+\s*=>\s*)?&?\$`, v, `\s*(?:=>|\))`]), line)

# The definition reads the request and does not itself constrain the value.
_source_def(line, v) if {
	regex.match(concat("", [`^\s*\$`, v, `\s*(?:=[^=]|\?\?=|\.=)`]), line)
	regex.match(_src, line)
	not regex.match(`\bin_array\s*\(|\barray_key_exists\s*\(|\bintval\s*\(|\(int\)|\bmatch\s*\(`, line)
}

_source_def(line, v) if {
	regex.match(concat("", [`\bforeach\s*\(\s*(?:`, _sg, `|\$request->(?:all|input|post|query)\s*\(\s*\))\s+as\s`]), line)
	regex.match(concat("", [`\bas\s+(?:\$\w+\s*=>\s*)?&?\$`, v, `\s*(?:=>|\))`]), line)
}

_tainted_key(lines, i, v) if {
	i > 0
	start := max([0, i - 20])
	defs := [j |
		some j in numbers.range(start, i - 1)
		not helpers.is_comment_line(lines[j])
		_defines(_code(lines[j]), v)
	]
	count(defs) > 0
	j := max(defs)
	_source_def(_code(lines[j]), v)
	not _guarded(lines, j, i, v)
}

_guarded(lines, j, i, v) if {
	some k in numbers.range(j + 1, i)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(_guard_re(v), l)
}

_guard_re(v) := concat("", [
	`\b(?:in_array|array_key_exists)\s*\(\s*\$`, v, `\b`,
	`|\bpreg_match\s*\([^,]+,\s*\$`, v, `\b`,
	`|\bisset\s*\(\s*\$\w+\s*\[\s*\$`, v, `\s*\]`,
	`|\$`, v, `\s*(?:===|!==|==|!=)`,
	`|(?:===|!==|==|!=)\s*\$`, v, `\b`,
	`|\b(?:switch|match)\s*\(\s*\$`, v, `\b`,
	`|^\s*\$`, v, `\s*=\s*(?:\(int\)|intval\s*\()`,
])

# ── 3. the whole request array copied into the session ───────────────────
_req_array := concat("", [`(?:`, _sg, `|\$request->(?:all|input|post|query)\s*\(\s*\))`])

_merge_re := concat("", [
	`\$_SESSION\s*=\s*array_(?:merge|replace)(?:_recursive)?\s*\([^;]*`, _req_array,
	`|\$_SESSION\s*\+=\s*`, _req_array,
	`|\$_SESSION\s*=\s*`, _req_array, `\s*;`,
])

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "$_SESSION")
	regex.match(`\$_SESSION\s*\+?=`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "$_SESSION")
	not helpers.is_comment_line(line)
	regex.match(_merge_re, _code(line))
	finding := _finding(path, i, line)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
