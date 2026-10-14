package vulnetix.rules.vnx_go_013

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-013",
	"name": "Go zip/tar slip via archive entry name",
	"description": "An archive entry's name (a *zip.File from range over Reader.File or a parameter, a *tar.Header from tar.Reader.Next(), its .Name or .FileHeader.Name, directly or through a variable assigned from it) is joined into a destination path with filepath.Join, path.Join or string concatenation, and that path is written to (os.Create, OpenFile, Mkdir/MkdirAll, WriteFile, Symlink, Link, Rename, Chmod...), or the name is written to directly; a tar entry's Linkname passed to os.Symlink/os.Link is reported too. An entry named ../../etc/cron.d/x then writes outside the destination. Not reported when the function checks containment: strings.HasPrefix of the result against a non-literal prefix (the destination), filepath.Rel, filepath.IsLocal, fs.ValidPath, a '..' test, filepath.Base of the entry name, a rooted clean (filepath.Clean(\"/\"+name)), securejoin.SecureJoin, os.OpenRoot (os.Root) or a helper named for the check (sanitize/within/safe/insecure/traversal/zipslip/subpath, checkPath/validateDest/verifyEntry/ensureInside...). A HasPrefix against a string literal (skipping \"__MACOSX/\" entries), filepath.Clean of the bare name and filepath.Base of something else (the archive's own path) are not containment checks and do not suppress the finding; nor when the joined path is only printed, compared or indexed, or the code builds an archive (header.Name = ...) rather than extracting one, nor in comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-013/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": ["CAPEC-139"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["path-traversal", "zip-slip", "go"],
}

_gate(content) if contains(content, "\"archive/zip\"")

_gate(content) if contains(content, "\"archive/tar\"")

_gate(content) if contains(content, "/compress/zip\"")

# Archive entry variables: range over a zip Reader's File slice, the header
# returned by tar.Reader.Next(), or a parameter/field of the entry type.
_entry_res := [
	`\bfor\s+\w+\s*,\s*(\w+)\s*:=\s*range\s+[\w\.\(\)]*\bFile\s*\{`,
	`\b(\w+)\s*,\s*\w+\s*:?=\s*\w+\.Next\(\)`,
	`\b(\w+)\s+\*(?:zip\.File|zip\.FileHeader|tar\.Header)\b`,
]

_entry_hint(line) if contains(line, "range")

_entry_hint(line) if contains(line, ".Next()")

_entry_hint(line) if contains(line, "zip.File")

_entry_hint(line) if contains(line, "tar.Header")

_entry_vars(lines) := {v |
	some line in lines
	_entry_hint(line)
	not helpers.is_comment_line(line)
	some re in _entry_res
	some m in regex.find_all_string_submatch_n(re, line, -1)
	v := m[1]
	v != "_"
}

# Writes to the filesystem.
_write_re := `\bos\.(?:Create|OpenFile|Mkdir|MkdirAll|WriteFile|Symlink|Link|Rename|Chmod|Chtimes|Lchown|Chown|Truncate)\(|\bioutil\.WriteFile\(`

# Containment checks and safe joins anywhere in the function. A HasPrefix
# against a string literal (skipping "__MACOSX/" entries) checks a name, not
# containment; a rooted Clean ("/"+name) cannot climb above the root.
_guard_re := `strings\.HasPrefix\([^,]+,\s*[^"\s]|filepath\.Rel\(|filepath\.IsLocal\(|fs\.ValidPath\(|"\.\."|\x60\.\.\x60|(?:filepath|path)\.Clean\(\s*(?:"/"|string\(\w+\.(?:PathSeparator|Separator)\))\s*\+|\.Join\(\s*[^,()]+,\s*(?:filepath|path)\.Join\(\s*"/"\s*,|SecureJoin|securejoin\.|os\.OpenRoot\(|\.OpenInRoot\(|(?i:sanitiz|within|safe_?join|is_?safe|insecure|traversal|zip_?slip|contained|escapes|sub_?path|in_?dir\b|(?:check|valid|verify|ensure)\w*(?:path|dir|dest|target|name|entry|inside|under)\w*\()`

# filepath.Base of the entry name (or an alias of it) flattens it; Base of
# anything else (the archive's own path) is not a check.
_base_guard(fn, entry_re, aliases) if {
	some m in regex.find_all_string_submatch_n(`\b(?:filepath|path)\.Base\(([^)]*)\)`, fn, -1)
	_named(m[1], entry_re, aliases)
}

_fn_start(lines, i) := max(array.concat([0], [j | some j in numbers.range(0, i); startswith(lines[j], "func ")]))

_fn_end(lines, i) := e if {
	n := count(lines) - 1
	ends := [j | some j in numbers.range(min([i + 1, n]), n); startswith(lines[j], "}")]
	e := min(array.concat([n], ends))
}

# The call's text: the line, plus the continuation lines of a call broken
# after '(' or ','.
_stmt(lines, i, line) := line if not regex.match(`[(,]\s*$`, line)

_stmt(lines, i, line) := s if {
	regex.match(`[(,]\s*$`, line)
	end := min([count(lines) - 1, i + 3])
	s := concat("\n", [lines[k] | some k in numbers.range(i, end)])
}

_word(n) := concat("", [`\b`, n, `\b`])

_named(text, entry_re, aliases) if regex.match(entry_re, text)

_named(text, _, aliases) if {
	some n in aliases
	regex.match(_word(n), text)
}

# A joined (or concatenated) destination path built from the entry name...
_joins(stmt, entry_re, aliases) if {
	regex.match(`\b(?:filepath|path)\.Join\(`, stmt)
	_named(split(stmt, ".Join(")[1], entry_re, aliases)
}

_joins(stmt, entry_re, aliases) if {
	regex.match(`\+`, stmt)
	parts := regex.split(`\+`, stmt)
	count(parts) > 1
	some p in array.slice(parts, 1, count(parts))
	_named(p, entry_re, aliases)
}

_joins(stmt, entry_re, aliases) if {
	regex.match(`\+`, stmt)
	parts := regex.split(`\+`, stmt)
	count(parts) > 1
	_named(regex.replace(parts[0], `^.*[=(,]\s*`, ""), entry_re, aliases)
}

# ...that is written: the join or concatenation is the write call's first
# argument, or it is assigned to a variable a later line of the function
# passes to a write.
_written(_, _, _, line) if regex.match(concat("", [`(?:`, _write_re, `)\s*(?:(?:filepath|path)\.Join\(|[\w\.]+\s*\+)`]), line)

_written(lines, i, e, line) if {
	t := helpers.assigned_first(line)
	i + 1 <= e
	some k in numbers.range(i + 1, e)
	l := lines[k]
	regex.match(_write_re, l)
	not helpers.is_comment_line(l)
	regex.match(concat("", [`(?:` , _write_re, `)\s*` , t, `\b`]), l)
}

_written(lines, i, e, line) if {
	t := helpers.assigned_first(line)
	i + 1 <= e
	some k in numbers.range(i + 1, e)
	l := lines[k]
	regex.match(`\bos\.(?:Symlink|Link|Rename)\(`, l)
	not helpers.is_comment_line(l)
	regex.match(concat("", [`\bos\.(?:Symlink|Link|Rename)\([^,]+,\s*`, t, `\b`]), l)
}

_sink(lines, i, line, e, entry_re, aliases) if {
	stmt := _stmt(lines, i, line)
	_joins(stmt, entry_re, aliases)
	_written(lines, i, e, line)
}

# The entry name (or its Linkname) is the write call's first argument.
_sink(_, _, line, _, entry_re, aliases) if {
	m := regex.find_all_string_submatch_n(`\b(?:os\.(?:Create|OpenFile|Mkdir|MkdirAll|WriteFile|Symlink|Link)|ioutil\.WriteFile)\(\s*([^,)]+)`, line, 1)
	count(m) > 0
	_named(m[0][1], entry_re, aliases)
}

# Variables assigned from the entry name itself (name := f.Name), file-wide.
_aliases(lines, entry_re) := {v |
	some l in lines
	regex.match(entry_re, l)
	not helpers.is_comment_line(l)
	not regex.match(`\.Join\(|\+`, l)
	v := helpers.assigned_first(l)
}

# The line, or the call it opens, names the entry or an alias of it.
_mentions(lines, i, line, entry_re, aliases) if {
	stmt := _stmt(lines, i, line)
	_named(stmt, entry_re, aliases)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	_gate(content)
	lines := split(content, "\n")
	entries := _entry_vars(lines)
	count(entries) > 0
	entry_re := concat("", [`\b(?:`, concat("|", [v | some v in entries]), `)\.(?:FileHeader\.)?(?:Name|Linkname)(?:[^\w(]|$)`])
	aliases := _aliases(lines, entry_re)
	some i, line in lines
	regex.match(`\.Join\(|\+|\bos\.|ioutil\.`, line)
	not helpers.is_comment_line(line)
	_mentions(lines, i, line, entry_re, aliases)
	e := _fn_end(lines, i)
	_sink(lines, i, line, e, entry_re, aliases)
	s := _fn_start(lines, i)
	fn := helpers.code_window(lines, s, 0, e - s)
	not regex.match(_guard_re, fn)
	not _base_guard(fn, entry_re, aliases)
	finding := {
		"rule_id": metadata.id,
		"message": "Archive entry name reaches a destination path that is written without checking it stays inside the destination (zip/tar slip); reject names that are not filepath.IsLocal, or verify the joined path with filepath.Rel / strings.HasPrefix, or extract through os.Root",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
