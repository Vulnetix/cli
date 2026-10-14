package vulnetix.rules.vnx_go_041

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-041",
	"name": "Use of deprecated TLS version",
	"description": "Reports a Go crypto/tls configuration whose MinVersion or MaxVersion field is set to SSL 3.0, TLS 1.0 or TLS 1.1: a struct literal field or an assignment naming tls.VersionSSL30, tls.VersionTLS10 or tls.VersionTLS11 (under any import alias, optionally wrapped in uint16()), the raw protocol numbers 0x0300-0x0302, a value on the line after the field name, or a local variable or constant assigned one of those values a few lines above. Comparisons (state.Version == tls.VersionTLS10, cfg.MinVersion < ...), switch cases, version-name maps, comments, string literals and _test.go files are not reported, and a version chosen at runtime from configuration is not followed.",
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

# A deprecated protocol version value.
_weak := `(uint16\(\s*)?(\b[A-Za-z_]\w*\.Version(TLS1[01]|SSL30)\b|\b0x030[0-2]\b)`

# Field set (struct literal `Field:` or assignment `.Field =`, never `==`).
_field := `\b(MinVersion|MaxVersion)\s*(:|=)(\s|$)`

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

# Value on the same line as the field.
_weak_setting(lines, i, c) if {
	regex.match(concat("", [_field, `\s*`, _weak]), c)
}

# Field name at line end, value on the next code line.
_weak_setting(lines, i, c) if {
	regex.match(`\b(MinVersion|MaxVersion)\s*:\s*$`, c)
	j := helpers.next_code_index(lines, i, 3)
	regex.match(concat("", [`^\s*`, _weak]), _code(lines[j]))
}

# Field set from a local identifier whose latest assignment above is weak.
_weak_setting(lines, i, c) if {
	m := regex.find_all_string_submatch_n(`\b(?:MinVersion|MaxVersion)\s*(?::|=)\s*([A-Za-z_]\w*)\s*,?\s*$`, c, 1)
	name := m[0][1]
	not regex.match(`^(tls|uint16|nil|true|false)$`, name)
	assign_re := concat("", [`(^|[\s,(])(var\s+|const\s+)?`, name, `\b(\s+\w+)?\s*(:=|=)([^=]|$)`])
	idxs := [j |
		some j in numbers.range(max([0, i - 40]), i - 1)
		regex.match(assign_re, _code(lines[j]))
	]
	count(idxs) > 0
	last := max(idxs)
	regex.match(_weak, _code(lines[last]))
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	contains(content, "Version")
	regex.match(`(MinVersion|MaxVersion)`, content)
	regex.match(`(Version(TLS1[01]|SSL30)\b|0x030[0-2]\b)`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Version")
	not helpers.is_comment_line(line)
	c := _code(line)
	regex.match(_field, c)
	not _in_block(lines, i)
	_weak_setting(lines, i, c)
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
