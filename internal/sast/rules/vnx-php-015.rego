package vulnetix.rules.vnx_php_015

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PHP-015",
	"name": "PHP unrestricted file upload via move_uploaded_file",
	"description": "An uploaded file is stored under a name the client chose, with no extension allowlist, so an attacker can upload shell.php into a served directory and run it. Reported: move_uploaded_file() whose destination (the second argument, on the call line or the following lines of a call broken across lines) contains $_FILES[...]['name'], a $_GET/$_POST/$_REQUEST/$_COOKIE value, or a variable built from one of those (assigned or appended with .= , directly or through one more variable) within the 40 lines above; and Laravel/Symfony UploadedFile ->move()/->storeAs()/->storePubliclyAs() given getClientOriginalName(). A file is treated as validated, and not reported, when the 40 lines above the call extract the extension (pathinfo(..., PATHINFO_EXTENSION), strrpos/strrchr/explode on '.', getClientOriginalExtension()) and compare it with an allowlist (in_array(), a comparison with a literal extension, preg_match()), or preg_match() the name against an extension pattern. A check of the client-supplied MIME type ($_FILES[...]['type']) is not validation and does not suppress the finding. Not reported: generated names (random_bytes(), uniqid(), hashName(), store()), the call in a comment or a string. Whether the destination is outside the web root is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-php-015/",
	"languages": ["php"],
	"severity": "high",
	"level": "warning",
	"kind": "sast",
	"cwe": [434],
	"capec": ["CAPEC-1"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["file-upload", "rce", "php"],
}

_source_re := `\$_FILES\s*\[[^\]]*\]\s*\[\s*['"]name['"]\s*\]|\$_(GET|POST|REQUEST|COOKIE)\b|getClientOriginalName\s*\(`

_lit_re := `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`

_code(line) := regex.replace(line, _lit_re, `''`)

_call_text(lines, i, re) := t if {
	parts := regex.split(re, lines[i])
	count(parts) > 1
	rest := concat(" ", array.slice(parts, 1, count(parts)))
	t := _continue(lines, i, rest)
}

_continue(lines, i, rest) := rest if contains(rest, ";")

_continue(lines, i, rest) := concat("\n", array.concat([rest], array.slice(lines, i + 1, min([count(lines), i + 5])))) if {
	not contains(rest, ";")
}

# The destination: everything after the first top-level comma.
_dest(text) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`^(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)|\[(?:[^\[\]]|\[[^\[\]]*\])*\]|[^,()'"\[\]])*,((?:.|\n)*)$`, text, 1)
	count(m) > 0
}

_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*\$(\w+)\s*\.?=[^=]`, line, 1)
	v := m[0][1]
}

_window(i) := numbers.range(max([0, i - 40]), i - 1)

_level0(lines, i) := {v |
	i > 0
	some j in _window(i)
	prev := lines[j]
	regex.match(_source_re, prev)
	not helpers.is_comment_line(prev)
	v := _assigned(prev)
}

_level1(lines, i, l0) := {v |
	i > 0
	some j in _window(i)
	prev := lines[j]
	not helpers.is_comment_line(prev)
	v := _assigned(prev)
	some u in l0
	u != v
	regex.match(concat("", [`\$`, u, `\b`]), prev)
}

_refs_any(text, vs) if {
	some v in vs
	regex.match(concat("", [`\$`, v, `\b|\{\$`, v, `\b`]), text)
}

_user_dest(_, _, dest) if regex.match(_source_re, dest)

_user_dest(lines, i, dest) if {
	l0 := _level0(lines, i)
	_refs_any(dest, l0)
}

_user_dest(lines, i, dest) if {
	l0 := _level0(lines, i)
	_refs_any(dest, _level1(lines, i, l0))
}

_ext_extract_re := `(?i)PATHINFO_EXTENSION|getClientOriginalExtension\s*\(|guessExtension\s*\(|\b(strrpos|strrchr|explode)\s*\([^;]*['"]\.['"]`

_ext_compare_re := `(?i)\bin_array\s*\(|(==|!=)=?\s*['"]\.?[a-z0-9]{2,5}['"]|\bpreg_match\s*\(|\bmatch\s*\(\s*\$\w*ext`

_name_pattern_re := `(?i)\bpreg_match\s*\(\s*['"][^'"]*\\\.[^'"]*(jpe?g|png|gif|webp|pdf|txt|csv|docx?|xlsx?|zip)`

_validated(lines, i) if {
	w := helpers.code_window(lines, i, 40, 0)
	regex.match(_ext_extract_re, w)
	regex.match(_ext_compare_re, w)
}

_validated(lines, i) if {
	w := helpers.code_window(lines, i, 40, 0)
	regex.match(_name_pattern_re, w)
}

_move_re := `\bmove_uploaded_file\s*\(`

_framework_re := `->\s*(move|storeAs|storePubliclyAs)\s*\(`

_unrestricted(lines, i) if {
	regex.match(_move_re, _code(lines[i]))
	dest := _dest(_call_text(lines, i, _move_re))
	_user_dest(lines, i, dest)
	not _validated(lines, i)
}

_unrestricted(lines, i) if {
	regex.match(_framework_re, _code(lines[i]))
	t := _call_text(lines, i, _framework_re)
	regex.match(`getClientOriginalName\s*\(`, t)
	not _validated(lines, i)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".php")
	regex.match(`move_uploaded_file|getClientOriginalName`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`move_uploaded_file|->\s*(move|storeAs|storePubliclyAs)\b`, line)
	not helpers.is_comment_line(line)
	_unrestricted(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Unrestricted file upload: the stored file keeps a client-chosen name with no extension allowlist; generate the name server-side, allowlist the extension and store outside the web root",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
