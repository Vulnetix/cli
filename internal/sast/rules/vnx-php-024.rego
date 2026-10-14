package vulnetix.rules.vnx_php_024

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-024",
	"name": "PHP mb_ereg_replace with variable options enabling eval modifier",
	"description": "mb_ereg_replace() or mb_eregi_replace() is called with the 'e' (evaluate) modifier in its options argument (the fourth), given as a literal that contains e ('e', 'msre', also across line breaks), or with options taken from the request ($_GET, $_POST, $_REQUEST, $_COOKIE, a Laravel/Symfony request accessor) inline or through a variable assigned from one in the 25 lines above, or mb_regex_set_options() sets a default option string containing e. With e, PHP (before 8.0) evaluates the replacement as PHP code, so a replacement built from input or back-references is code execution. Not reported: calls with three arguments (no options), literal options without e ('msr', 'i', 'x'), options from a constant, property or configuration variable, mb_ereg_replace_callback(), the pattern or subject containing the letter e, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-024/",
	"languages": ["php"],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [94],
	"capec": ["CAPEC-242"],
	"attack_technique": ["T1059.004"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["code-injection", "mb-ereg-replace", "eval", "php"],
}

_arg := `(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|\((?:[^()'"]|'[^']*'|"[^"]*"|\([^()]*\))*\)|\[[^\[\]]*\]|[^,'"()\[\]])+`

_call_re := concat("", [`^mb_eregi?_replace\s*\(\s*`, _arg, `\s*,\s*`, _arg, `\s*,\s*`, _arg, `\s*,\s*(`, _arg, `)\s*\)`])

_sink_re := `(^|[^\w$>:\\])mb_eregi?_replace\s*\(`

_set_re := `(^|[^\w$>:\\])mb_regex_set_options\s*\(\s*['"][a-z]*e[a-z]*['"]\s*\)`

_e_lit := `^['"][a-z]*e[a-z]*['"]$`

_source_re := `\$_(GET|POST|REQUEST|COOKIE)\b|\$request\s*->\s*(input|get|query|post|string)\s*\(|\$request\s*->\s*(query|request)\s*->\s*get\s*\(|\bRequest::(input|get|query|post)\s*\(|\brequest\(\s*\)\s*->\s*(input|get|query|post)\s*\(|\brequest\(\s*['"]|\bInput::get\s*\(|\bfilter_input\s*\(\s*INPUT_(GET|POST|COOKIE|REQUEST)`

_no_strings(s) := regex.replace(s, `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`, `""`)

_stmt(lines, i) := s if {
	end := min([count(lines) - 1, i + 6])
	joined := concat(" ", array.slice(lines, i, end + 1))
	s := substring(joined, indexof(joined, "mb_ereg"), -1)
}

_origin(lines, i, v) := j if {
	re := concat("", [`^\s*\$`, v, `\s*=[^=>]`])
	cands := [k |
		some k in numbers.range(max([0, i - 25]), i - 1)
		k < i
		regex.match(re, lines[k])
	]
	count(cands) > 0
	j := max(cands)
}

_evaluating(_, _, opt) if regex.match(_e_lit, opt)

_evaluating(_, _, opt) if regex.match(_source_re, opt)

_evaluating(lines, i, opt) if {
	m := regex.find_all_string_submatch_n(`^\$([A-Za-z_]\w*)$`, opt, 1)
	count(m) > 0
	j := _origin(lines, i, m[0][1])
	regex.match(_source_re, lines[j])
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "mb_ereg")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "mb_ereg")
	not helpers.is_comment_line(line)
	regex.match(_sink_re, _no_strings(line))
	m := regex.find_all_string_submatch_n(_call_re, _stmt(lines, i), 1)
	count(m) > 0
	_evaluating(lines, i, trim_space(m[0][1]))
	finding := {
		"rule_id": metadata.id,
		"message": "mb_ereg_replace()/mb_eregi_replace() runs with the 'e' modifier (literal or request-controlled options), which evaluates the replacement as PHP code; drop 'e', pass literal options and use mb_ereg_replace_callback() for computed replacements",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	contains(content, "mb_regex_set_options")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "mb_regex_set_options")
	not helpers.is_comment_line(line)
	regex.match(`(^|[^\w$>:\\])mb_regex_set_options\s*\(`, _no_strings(line))
	regex.match(_set_re, line)
	finding := {
		"rule_id": metadata.id,
		"message": "mb_regex_set_options() makes 'e' (evaluate) a default option, so every later mb_ereg_replace() evaluates its replacement as PHP code; remove 'e' from the option string",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
