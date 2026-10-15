package vulnetix.rules.vnx_go_041

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-041",
	"name": "Use of deprecated TLS version",
	"description": "Reports a Go TLS configuration whose MinVersion or MaxVersion field (or an options-struct field such as TLSMinVersion or MinTLSVersion) is set to SSL 3.0, TLS 1.0 or TLS 1.1: a struct literal field or an assignment naming tls.VersionSSL30, tls.VersionTLS10 or tls.VersionTLS11 (under any import alias, optionally wrapped in uint16()), the raw protocol numbers 0x0300-0x0302 in a file that imports a TLS package, a value on the line after the field name, a local variable assigned one of those values a few lines above, or a package-level const/var declared as one. Also reported: a string-typed MinVersion/MaxVersion option set to the constant's name (Traefik-style MinVersion: \"VersionTLS10\"), and an Envoy go-control-plane TlsMinimumProtocolVersion/TlsMaximumProtocolVersion set to TlsParameters_TLSv1_0 or TLSv1_1. Comparisons (state.Version == tls.VersionTLS10, cfg.MinVersion < ...), switch cases, version-name maps, comments, string literals including multi-line code-generation templates, and _test.go files are not reported; a version chosen at runtime from configuration or passed through a function argument is not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-041/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [326],
	"capec": ["CAPEC-63"],
	"attack_technique": ["T1068.003"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["tls", "crypto", "version"],
}

# A deprecated protocol version value. The raw protocol numbers count only in
# a file that imports a TLS package: elsewhere 0x0300 is just a number.
_weak_named := `(uint16\(\s*)?\b[A-Za-z_]\w*\.Version(TLS1[01]|SSL30)\b`

_weak_any := `(uint16\(\s*)?(\b[A-Za-z_]\w*\.Version(TLS1[01]|SSL30)\b|\b0x030[0-2]\b)`

_weak_re(content) := _weak_any if regex.match(`(?m)^\s*(import\s+)?(\w+\s+)?"[^"]*tls"`, content)

_weak_re(content) := _weak_named if not regex.match(`(?m)^\s*(import\s+)?(\w+\s+)?"[^"]*tls"`, content)

# The version field: tls.Config's MinVersion/MaxVersion set by a struct
# literal `Field:` or an assignment `.Field =` (never `==`), or an options
# struct's TLSMinVersion / MinTLSVersion style field set the same way.
_fname := `(MinVersion|MaxVersion|\w*(Min|Max)TLSVersion|TLS(Min|Max)Version)`

_field := concat("", [`(\b(MinVersion|MaxVersion)\s*(:|=)|\b`, _fname, `\s*:|\.`, _fname, `\s*=)(\s|$)`])

# Remove string literals and a trailing line comment.
_code(line) := c if {
	s := regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`|'(?:[^'\\\\]|\\\\.)*'", `""`)
	c := regex.replace(s, `//.*$`, "")
}

# Inside a /* ... */ block opened on an earlier line.
_in_block(lines, i) if {
	txt := concat("\n", array.slice(lines, max([0, i - 40]), i))
	opens := indexof_n(txt, "/*")
	count(opens) > 0
	last_open := max(opens)
	closes := indexof_n(txt, "*/")
	_after_last_close(closes, last_open)
}

_after_last_close(closes, _) if count(closes) == 0

_after_last_close(closes, last_open) if {
	count(closes) > 0
	max(closes) < last_open
}

# Inside a multi-line raw string (a code-generation template): an odd number
# of backticks in the lines above, outside double-quoted strings.
_in_raw_string(lines, i) if {
	txt := concat("\n", array.slice(lines, max([0, i - 80]), i))
	contains(txt, "`")
	stripped := regex.replace(txt, "\"(?:[^\"\\\\\\n]|\\\\.)*\"", `""`)
	count(indexof_n(stripped, "`")) % 2 == 1
}

# Value on the same line as the field.
_weak_setting(lines, i, c, _, w) if {
	regex.match(concat("", [_field, `\s*`, w]), c)
}

# Field name at line end, value on the next code line.
_weak_setting(lines, i, c, _, w) if {
	regex.match(concat("", [`\b`, _fname, `\s*:\s*$`]), c)
	j := helpers.next_code_index(lines, i, 3)
	regex.match(concat("", [`^\s*`, w]), _code(lines[j]))
}

# A string-typed option (Traefik's tls.Options and similar config structs)
# set to the Go constant's name: MinVersion: "VersionTLS10". The string is
# read from the raw line, since _code blanks string literals.
_weak_setting(lines, i, c, _, _) if {
	regex.match(`\b(MinVersion|MaxVersion)\s*:\s*""`, c)
	regex.match(`\b(MinVersion|MaxVersion)\s*:\s*"Version(TLS1[01]|SSL30)"`, lines[i])
}

# Field set from an identifier whose latest assignment a few lines above is
# weak, or, with no local assignment, a package-level const/var declared weak.
_weak_setting(lines, i, c, content, w) if {
	m := regex.find_all_string_submatch_n(concat("", [`\b`, _fname, `\s*(?::|=)\s*([A-Za-z_]\w*)\s*,?\s*$`]), c, 1)
	name := m[0][count(m[0]) - 1]
	not regex.match(`^(tls|uint16|nil|true|false)$`, name)
	_ident_weak(lines, i, name, content, w)
}

_assign_re(name) := concat("", [`(^|[\s,(])(var\s+|const\s+)?`, name, `\b(\s+\w+)?\s*(:=|=)([^=]|$)`])

_local_assigns(lines, i, name) := [j |
	some j in numbers.range(max([0, i - 40]), i - 1)
	regex.match(_assign_re(name), _code(lines[j]))
]

_ident_weak(lines, i, name, _, w) if {
	idxs := _local_assigns(lines, i, name)
	count(idxs) > 0
	regex.match(w, _code(lines[max(idxs)]))
}

_ident_weak(lines, i, name, content, w) if {
	count(_local_assigns(lines, i, name)) == 0
	regex.match(concat("", [`(?m)^\s*((var|const)\s+)?`, name, `(\s+\w+)?\s*=\s*`, w]), content)
}

# Envoy go-control-plane TlsParameters: TlsMinimumProtocolVersion or
# TlsMaximumProtocolVersion set to the TLSv1_0 / TLSv1_1 enum value.
_hits contains [path, i, line] if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	contains(content, "TlsParameters_TLSv1_")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "ProtocolVersion")
	not helpers.is_comment_line(line)
	c := _code(line)
	regex.match(`(\bTls(Minimum|Maximum)ProtocolVersion\s*:|\.Tls(Minimum|Maximum)ProtocolVersion\s*=)\s*(\w+\.)?TlsParameters_TLSv1_[01]\b`, c)
	not _in_block(lines, i)
	not _in_raw_string(lines, i)
}

_hits contains [path, i, line] if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	contains(content, "Version")
	regex.match(`(Min|Max)(TLS)?Version`, content)
	regex.match(`(Version(TLS1[01]|SSL30)\b|0x030[0-2]\b)`, content)
	w := _weak_re(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Version")
	not helpers.is_comment_line(line)
	c := _code(line)
	regex.match(_field, c)
	not _in_block(lines, i)
	not _in_raw_string(lines, i)
	_weak_setting(lines, i, c, content, w)
}

findings contains finding if {
	some hit in _hits
	path := hit[0]
	i := hit[1]
	line := hit[2]
	finding := {
		"rule_id": metadata.id,
		"message": "TLS configuration allows or caps at a deprecated protocol version (SSL 3.0, TLS 1.0 or TLS 1.1); set MinVersion to tls.VersionTLS12 or higher",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
