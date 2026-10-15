# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_621

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-621",
	"name": "Variable extraction from request data (PHP extract/parse_str/variable variables)",
	"description": "Reports PHP code that turns request data into local variables, letting a client define or overwrite any variable in scope (an $is_admin flag, a $price, a $file path): extract() whose argument contains a superglobal ($_GET, $_POST, $_REQUEST, $_COOKIE, $_FILES, $_SERVER, $_ENV), directly or wrapped (array_merge($_GET, $_POST), array_map('trim', $_REQUEST)), on a framework's request array ($request->all(), $request->input(), $this->input->post(), Input::all()) or on a variable assigned from one a few lines above; parse_str() and mb_parse_str() with a single argument (which write into the current scope); import_request_variables(); and $$key / ${$key} / $GLOBALS[$key] assignments inside (or on the same line as) a foreach over a superglobal. Not reported: extract() with EXTR_PREFIX_ALL, extract() of array_intersect_key(...)/->only([...])/Arr::only() (a fixed key set) or of $request->validated(), extract() on a trusted array (template data, a database row, a constant array), parse_str() with a result array, method calls named extract (->extract, ::extract) and SQL/JSON extract functions, variable-variable reads, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-621/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [621],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["variable-extraction", "php", "cwe-621"],
}

_php_ext := {".php", ".phtml", ".inc", ".php5", ".php7"}

_superglobal := `\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\b`

_request_src := `(\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\b|\$request->(all|input|post|query|toArray)\(|\$this->input->(post|get|get_post)\(|\$this->request->(getPost|getQuery|getData|data)\b|Input::all\(|Request::all\(|request\(\)->all\()`

# A bare call to extract() (not ->extract, ::extract, json_extract).
_extract_re := `(^|[^\w$>:])extract\s*\(\s*(.*)$`

_strip_strings(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `'(?:[^'\\]|\\.)*'`, `''`)

_php_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*=[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_message := "Request data is extracted into local variables: a client can define or overwrite any variable in scope. Read the fields you need explicitly ($name = $_POST['name'] ?? '') or use EXTR_PREFIX_ALL"

_candidate(path, content) if {
	some ext in _php_ext
	endswith(path, ext)
	regex.match(`extract\s*\(|parse_str\s*\(|import_request_variables|\$\$|\$\{\$|\$GLOBALS\s*\[\s*\$`, content)
}

findings contains finding if {
	some path, content in input.file_contents
	_candidate(path, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	code := _strip_strings(line)
	_reported(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": _message,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# extract() on request data, directly.
_reported(_, _, code) if {
	contains(code, "extract")
	m := regex.find_all_string_submatch_n(_extract_re, code, 1)
	count(m) > 0
	args := m[0][2]
	regex.match(_request_src, args)
	# array_intersect_key($_POST, ...) and ->only([...]) keep a fixed set of keys
	not regex.match(`array_intersect_key\s*\(|Arr::only\s*\(|->only\s*\(`, args)
	not contains(code, "EXTR_PREFIX_ALL")
}

# extract($v) where $v was assigned from request data a few lines above.
_reported(lines, i, code) if {
	contains(code, "extract")
	m := regex.find_all_string_submatch_n(`(?:^|[^\w$>:])extract\s*\(\s*\$(\w+)\s*[,)]`, code, 1)
	count(m) > 0
	v := m[0][1]
	not contains(code, "EXTR_PREFIX_ALL")
	some j in numbers.range(max([0, i - 15]), i - 1)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	_php_assigned(prev) == v
	regex.match(_request_src, prev)
}

# parse_str() with one argument writes into the current scope.
_reported(lines, i, code) if {
	contains(code, "parse_str")
	m := regex.find_all_string_submatch_n(`(?:^|[^\w$>:])(?:mb_)?parse_str\s*\(([^,;]*)\)\s*;`, code, 1)
	count(m) > 0
	trim_space(m[0][1]) != ""
}

_reported(_, _, code) if {
	regex.match(`(?:^|[^\w$>:])import_request_variables\s*\(`, code)
}

# $$key = ... / ${$key} = ... inside foreach ($_GET as $key => ...).
_reported(lines, i, code) if {
	m := regex.find_all_string_submatch_n(`(?:^\s*|\{\s*)(?:\$\$(\w+)|\$\{\s*\$(\w+)\s*\}|\$GLOBALS\s*\[\s*\$(\w+)\s*\])\s*=[^=]`, code, 1)
	count(m) > 0
	k := concat("", [m[0][1], m[0][2], m[0][3]])
	some j in numbers.range(max([0, i - 6]), i)
	f := regex.find_all_string_submatch_n(concat("", [`foreach\s*\(\s*`, _superglobal, `\s+as\s+\$(\w+)\s*=>`]), lines[j], 1)
	count(f) > 0
	f[0][2] == k
}
