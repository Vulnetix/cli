package vulnetix.rules.vnx_php_012

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-012",
	"name": "PHP reflected XSS via echo/print of user input",
	"description": "Request input is written into the response without HTML encoding. Reported: echo, print, <?= ?>, printf()/vprintf() and die()/exit() whose output contains a $_GET/$_POST/$_REQUEST/$_COOKIE/$_SERVER element, or a variable assigned from one within the 30 lines above (through any function that is not an encoder, such as trim() or str_replace()); and an HTML fragment (a string literal containing a tag) assigned or appended (.=) to a variable together with such a value, which is how a page buffer like $html is built before it is printed. Not reported: values passed through htmlspecialchars(), htmlentities(), strip_tags(), intval()/(int)/floatval(), json_encode(), urlencode()/rawurlencode(), esc_html()/esc_attr() or e(); isset()/empty()/count() tests of input; user input inside a single-quoted literal (not interpolated); constant output; and the statement inside a comment or a string. A value that travels through a second variable before it is echoed, stored XSS read back from a database, and template engines (Blade, Twig) are not tracked.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-012/",
	"languages": ["php"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [79],
	"capec": ["CAPEC-86"],
	"attack_technique": ["T1189"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xss", "injection", "php"],
}

# $_SERVER counts only for the keys a client controls (request headers, the
# URL and the HTTP auth credentials), not SERVER_NAME or DOCUMENT_ROOT.
_source_re := `\$_(GET|POST|REQUEST|COOKIE)\b|\$_SERVER\s*\[\s*['"]?(HTTP_\w+|PHP_SELF|REQUEST_URI|QUERY_STRING|PATH_INFO|ORIG_PATH_INFO|PHP_AUTH_USER|PHP_AUTH_PW)\b`

_stmt_re := `(?i)(^|[;{}:]|<\?php|\?>)\s*(echo|print)\b|<\?=|\b(printf|vprintf|die|exit)\s*\(`

_build_re := `^\s*\$\w+(?:\s*\[[^\]]*\])*\s*\.?=[^=]`

_encoder_re := `(?i)(\(\s*(int|integer|float|double|bool)\s*\)\s*\$[\w\[\]'"\->]+|\b(htmlspecialchars|htmlentities|strip_tags|intval|floatval|boolval|abs|json_encode|urlencode|rawurlencode|http_build_query|esc_html|esc_attr|esc_url|esc_js|e|filter_var|filter_input|number_format|count|sizeof|isset|empty|is_numeric|strlen|array_key_exists|in_array|md5|sha1|hash|base64_encode|bin2hex)\s*\((?:[^()]|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))*\))`

_lit_re := `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`

# Encoders replaced by a constant, then single-quoted literals emptied (they
# do not interpolate). Literals are tokenised left to right.
_clean(text) := out if {
	s := regex.replace(regex.replace(text, _encoder_re, "0"), `\[\s*'(\w+)'\s*\]`, "[$1]")
	out := strings.replace_n(
		{lit: `''` | some lit in regex.find_n(_lit_re, s, -1); startswith(lit, "'")},
		s,
	)
}

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*\.?=[^=]`, line, 1)
	v := m[0][1]
}

_rhs(line) := r if {
	parts := regex.split(`\.?=`, line)
	r := concat("=", array.slice(parts, 1, count(parts)))
}

_tainted(lines, i) := {v |
	i > 0
	some j in numbers.range(max([0, i - 30]), i - 1)
	prev := lines[j]
	regex.match(_source_re, prev)
	not helpers.is_comment_line(prev)
	v := _assigned(prev)
	regex.match(_source_re, _clean(_rhs(prev)))
	not _reassigned(lines, i, j, v)
}

_reassigned(lines, i, j, v) if {
	j + 1 <= i - 1
	some k in numbers.range(j + 1, i - 1)
	_assigned(lines[k]) == v
	not regex.match(concat("", [`\$`, v, `\b`]), _clean(_rhs(lines[k])))
}

_user(text, _) if regex.match(_source_re, text)

_user(text, tainted) if {
	some v in tainted
	regex.match(concat("", [`\$`, v, `\b|\{\$`, v, `\b`]), text)
}

# The output of an echo-like statement: the text after the keyword, up to the
# statement's end.
_output(line) := out if {
	parts := regex.split(_stmt_re, line)
	count(parts) > 1
	rest := concat(" ", array.slice(parts, 1, count(parts)))
	out := regex.split(`;\s*(\$\w+\s*\.?=[^=]|\}|if\b|else\b|\?>|$)`, rest)[0]
}

_reflected(line, tainted) if {
	_has_stmt(line)
	_user(_clean(_output(line)), tainted)
}

_has_stmt(line) if regex.match(_stmt_re, regex.replace(line, _lit_re, `''`))

# In template markup the PHP tag often sits inside an HTML attribute's quotes.
_has_stmt(line) if regex.match(`(?i)<\?(=|php\s+(echo|print)\b)`, line)

# An HTML fragment built from input: a tag inside a literal on the right of
# an assignment that also carries the input.
_reflected(line, tainted) if {
	regex.match(_build_re, line)
	rhs := _rhs(line)
	some lit in regex.find_n(_lit_re, rhs, -1)
	regex.match(`<[A-Za-z!/]`, lit)
	_joined(rhs, lit)
	_user(_clean(rhs), tainted)
}

# The tag literal is part of the built string: concatenated with `.`, or a
# double-quoted literal that interpolates. A tag passed as an argument
# (str_replace('<script>', '', $x)) is not output.
_joined(rhs, lit) if {
	idx := indexof(rhs, lit)
	after := trim_left(substring(rhs, idx + count(lit), -1), " \t")
	startswith(after, ".")
}

_joined(rhs, lit) if {
	idx := indexof(rhs, lit)
	before := trim_right(substring(rhs, 0, idx), " \t")
	endswith(before, ".")
}

_joined(_, lit) if {
	startswith(lit, `"`)
	contains(lit, "$")
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(_source_re, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(?i)echo|print|<\?=|die|exit|=`, line)
	not helpers.is_comment_line(line)
	_reflected(line, _tainted(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": "Reflected XSS: request input is written into the page without HTML encoding; wrap it in htmlspecialchars($v, ENT_QUOTES, 'UTF-8')",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
