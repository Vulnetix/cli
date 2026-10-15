# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_455

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-455",
	"name": "Non-exit on Failed Initialization",
	"description": "C/C++ code checks an initialisation call for failure and then only logs: the failure branch of an if whose condition tests an init/setup/startup function (sodium_init, OPENSSL_init_ssl, curl_global_init, pthread_mutex_init, a project's own foo_init/initialize_engine...) for failure (!f(), < 0, <= 0, != 0, == -1, == NULL/nullptr/false, != *_OK/*SUCCESS, != 1), directly or through a status/handle variable assigned from the call in the 3 lines above, consists only of printf/fprintf/perror/puts/syslog/std::cerr/log*/warn* statements, so execution continues with an uninitialised library, context or lock. Reported for braced, Allman, single-statement and same-line bodies. Not reported: a failure branch that exits, returns, aborts, jumps, throws or does anything other than log (setting a fallback flag counts as handling), a success test (== 0, != NULL) that logs, predicates named is*/has*Initialized, non-initialisation calls, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-455/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [455],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["non-exit-on-failed-init", "cwe-455", "error-handling"],
}

_c_ext := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_is_c(path) if {
	some ext in _c_ext
	endswith(path, ext)
}

# An initialisation function name (not an is/has predicate).
_init_name := `(?:[A-Za-z_]\w*)?(?:[Ii]nit|INIT|[Ss]etup|SETUP|[Ss]tartup|STARTUP)\w*`

_fail_cmp := `(?:<=?\s*0\b|!=\s*0\b|==\s*-\s*1\b|==\s*(?:NULL|nullptr|false|FALSE)\b|!=\s*(?:1\b|[A-Z_]*(?:OK|SUCCESS)\b))`

# if (!init(...)) or if (init(...) <failure comparison>)
_direct_neg_re := concat("", [`^\s*(?:\}\s*else\s+)?if\s*\(.*!\s*(?:[\w]+(?:\.|->|::))*(`, _init_name, `)\s*\(`])

_direct_cmp_re := concat("", [`^\s*(?:\}\s*else\s+)?if\s*\(.*\b(`, _init_name, `)\s*\([^;]*\)\s*`, _fail_cmp])

_var_test_re := concat("", [`^\s*(?:\}\s*else\s+)?if\s*\(\s*(?:!\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*)\s*`, _fail_cmp, `\s*\))`])

_predicate(name) if regex.match(`^(?:is|has|was|did|get|Is|Has|Get)[A-Z_]|[Ii]nitiali[sz]ed$|_inited$|^initialized`, name)

# Teardown calls (codec_deinit, sensor_uninit, *_cleanup): logging their
# failure and carrying on is the normal shutdown path.
_predicate(name) if regex.match(`(?i)(?:de|un)_?init|cleanup|teardown|shutdown`, name)

# The index of the line that closes the if condition (a condition may wrap
# onto up to 3 further lines).
_cond_end(lines, i) := i if _balanced(lines[i])

_cond_end(lines, i) := e if {
	not _balanced(lines[i])
	es := [k |
		some k in numbers.range(i + 1, min([count(lines) - 1, i + 3]))
		_balanced(concat(" ", array.slice(lines, i, k + 1)))
	]
	count(es) > 0
	e := es[0]
}

_balanced(s) if strings.count(s, "(") == strings.count(s, ")")

# A "log" that terminates the process: LOG(FATAL), log_fatal(), g_error().
_fatal(body) if {
	some l in body
	code := regex.replace(l, `"(?:[^"\\]|\\.)*"`, `""`)
	regex.match(`(?i)fatal|\bg_error\s*\(|\b(?:abort|die|panic|exit|_exit)\s*\(`, code)
}

_failed_init(_, line) if {
	m := regex.find_all_string_submatch_n(_direct_neg_re, line, 1)
	count(m) > 0
	not _predicate(m[0][1])
}

_failed_init(_, line) if {
	m := regex.find_all_string_submatch_n(_direct_cmp_re, line, 1)
	count(m) > 0
	not _predicate(m[0][1])
}

_failed_init(ctx, line) if {
	m := regex.find_all_string_submatch_n(_var_test_re, line, 1)
	count(m) > 0
	v := concat("", [m[0][1], m[0][2]])
	v != ""
	lines := ctx[0]
	i := ctx[1]
	i > 0
	some j in numbers.range(max([0, i - 3]), i - 1)
	a := regex.find_all_string_submatch_n(concat("", [`\b`, v, `\s*=\s*[^=;]*?\b(`, _init_name, `)\s*\(`]), lines[j], 1)
	count(a) > 0
	not _predicate(a[0][1])
}

_indent(line) := count(line) - count(trim_left(line, " \t"))

_code(l) if {
	t := trim_space(l)
	t != ""
	t != "{"
	t != "}"
	not helpers.is_comment_line(l)
}

# The failure branch's statements.
# braced on the if line
_body(lines, i) := body if {
	regex.match(`\)\s*\{\s*(?://.*)?$`, lines[i])
	body := _block(lines, i + 1, _indent(lines[i]))
}

# Allman brace or a single statement on the next code line
_body(lines, i) := body if {
	regex.match(`\)\s*(?://.*)?$`, lines[i])
	k := helpers.next_code_index(lines, i, 3)
	trim_space(lines[k]) == "{"
	body := _block(lines, k + 1, _indent(lines[k]))
}

_body(lines, i) := [lines[k]] if {
	regex.match(`\)\s*(?://.*)?$`, lines[i])
	k := helpers.next_code_index(lines, i, 3)
	trim_space(lines[k]) != "{"
}

# a statement on the if line itself
_body(lines, i) := [m[0][1]] if {
	not regex.match(`[{)]\s*(?://.*)?$`, lines[i])
	m := regex.find_all_string_submatch_n(`^\s*(?:\}\s*else\s+)?if\s*\(.*\)\s*((?:std::)?[A-Za-z_][^;]*;)\s*$`, lines[i], 1)
	count(m) > 0
}

# Code lines from s up to the closing brace at indent `ind` (at most 20 lines).
_block(lines, s, ind) := [l |
	ends := [k |
		some k in numbers.range(s, min([count(lines) - 1, s + 20]))
		_indent(lines[k]) <= ind
		startswith(trim_space(lines[k]), "}")
	]
	count(ends) > 0
	some k in numbers.range(s, ends[0] - 1)
	l := lines[k]
	_code(l)
]

_log_re := `^\s*(?:(?:std::)?(?:cerr|cout|clog)\s*<<|(?:\w+::)*(?:f?printf|dprintf|perror|puts|fputs|v?syslog|warnx?|ERR_print_errors\w*|g_warning|g_message|g_printerr|OutputDebugString\w*|q(?:Warning|Debug|Critical)|\w*[Ll]og(?:_\w*|[A-Z]\w*)?|\w*LOG\w*|\w*[Ww]arn\w*|\w*WARN\w*|\w*[Dd]ebug\w*|\w*DEBUG\w*|\w*[Tt]race\w*|\w*TRACE\w*)\s*\()`

# Every statement only logs; a line continuing the previous call counts too.
_log_only(body) if {
	count(body) > 0
	regex.match(_log_re, body[0])
	every t in numbers.range(0, count(body) - 1) {
		_logs_or_continues(body, t)
	}
}

_logs_or_continues(body, t) if regex.match(_log_re, body[t])

_logs_or_continues(body, t) if {
	t > 0
	not regex.match(`[;{}]\s*(?://.*)?$`, body[t - 1])
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(`(?m)^\s*(?:\}\s*else\s+)?if\s*\(`, content)
	regex.match(`(?:[Ii]nit|INIT|[Ss]etup|SETUP|[Ss]tartup|STARTUP)\w*\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "if")
	regex.match(`^\s*(?:\}\s*else\s+)?if\s*\(`, line)
	e := _cond_end(lines, i)
	cond := concat(" ", [trim_space(l) | some l in array.slice(lines, i, e + 1)])
	_failed_init([lines, i], cond)
	body := _body(lines, e)
	_log_only(body)
	not _fatal(body)
	finding := {
		"rule_id": metadata.id,
		"message": "Initialisation failure is only logged and execution continues with an uninitialised library or context; exit, return an error or abort in the failure branch",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
