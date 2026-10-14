package vulnetix.rules.vnx_php_018

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-018",
	"name": "PHP sensitive debug output disclosure",
	"description": "A debug dump writes a whole sensitive superglobal to the response: var_dump(), print_r(), var_export(), debug_zval_dump() or the Laravel/Symfony dump()/dd() helpers called with $_SESSION, $_SERVER, $_ENV, $_COOKIE, $GLOBALS or getenv() with no argument as one of their direct arguments (also across line breaks), or print_r()/var_export() in return mode (second argument true) whose result is echoed, printed or emitted with <?= or die()/exit(). Session tokens, cookies, server paths and every environment secret then reach the browser. Not reported: a single element ($_SESSION['cart'], getenv('APP_ENV')), the return-mode result passed to error_log(), a logger or a file, a method named dump() on an object ($dumper->dump()), lookalike variables ($_SESSION_DEFAULTS), test files, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-018/",
	"languages": ["php"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [200],
	"capec": ["CAPEC-118"],
	"attack_technique": ["T1082"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["information-disclosure", "debug", "php"],
}

_call_re := `(^|[^\w$>:\\])(var_dump|print_r|var_export|debug_zval_dump|dump|dd)\s*\(`

# A whole sensitive array (or the full environment) as a direct argument of
# the dump call: no nested call between the dump's parenthesis and it.
_whole_re := `^(var_dump|print_r|var_export|debug_zval_dump|dump|dd)\s*\(\s*(?:[^()]*,\s*)?(?:\$(?:_SESSION|_SERVER|_ENV|_COOKIE|GLOBALS)\s*[,)]|getenv\s*\(\s*\))`

_return_mode_re := `^(print_r|var_export)\s*\([^;]*,\s*(true|TRUE|1)\s*\)`

_output_re := `(^|[^\w$>:])(echo|print|die|exit)\b|<\?=`

_no_strings(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_call_text(lines, i, code) := t if {
	end := min([count(lines) - 1, i + 3])
	rest := concat(" ", array.slice(lines, i + 1, end + 1))
	joined := concat(" ", [code, _no_strings(rest)])
	m := regex.find_n(_call_re, joined, 1)[0]
	tail := substring(joined, indexof(joined, m), -1)
	t := regex.replace(split(tail, ";")[0], `^[^A-Za-z_]*`, "")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`(var_dump|print_r|var_export|debug_zval_dump|dump|dd)\s*\(`, content)
	regex.match(`\$(_SESSION|_SERVER|_ENV|_COOKIE|GLOBALS)\b|getenv\s*\(\s*\)`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(var_dump|print_r|var_export|debug_zval_dump|dump|dd)\s*\(`, line)
	not helpers.is_comment_line(line)
	code := _no_strings(line)
	regex.match(_call_re, code)
	call := _call_text(lines, i, code)
	regex.match(_whole_re, call)
	_writes_output(call, code)
	finding := {
		"rule_id": metadata.id,
		"message": "Debug output of a whole $_SESSION/$_SERVER/$_ENV/$_COOKIE/$GLOBALS array (or getenv()) is sent to the response, exposing session tokens, cookies and environment secrets; remove the dump from production code",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# var_dump/dump/dd/debug_zval_dump print directly; print_r/var_export do too
# unless their second argument asks for the string back.
_writes_output(call, _) if not regex.match(_return_mode_re, call)

_writes_output(call, code) if {
	regex.match(_return_mode_re, call)
	regex.match(_output_re, code)
}
