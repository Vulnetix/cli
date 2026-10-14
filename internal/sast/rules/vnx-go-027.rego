package vulnetix.rules.vnx_go_027

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-027",
	"name": "Potential path traversal via file path construction",
	"description": "A file is opened, read, written, created, removed or served using a path that contains a value from the request (r.FormValue, r.URL.Query(), r.Form.Get, r.URL.Path, r.Header.Get, mux.Vars, r.PathValue, httprouter ps.ByName, gin c.Query/Param/PostForm, echo c.QueryParam/Param, fiber c.Params/Query): the value is passed inline, through the variable it was assigned to, or through one path built from it (filepath.Join, path.Join, fmt.Sprintf, concatenation), to os.Open/OpenFile/ReadFile/WriteFile/Create/Remove/RemoveAll/Mkdir/MkdirAll/ReadDir/Rename/Chmod, ioutil.ReadFile/WriteFile/ReadDir, http.ServeFile, http.Dir, gin c.File/FileAttachment, echo c.File/Attachment/Inline or fiber c.SendFile/Download. Not reported: a value checked or reduced first (filepath.Base, filepath.IsLocal, filepath.Rel, strings.HasPrefix on the joined path, a '..' test, fs.ValidPath, SecureJoin, a Clean of a rooted \"/\"+value, strconv number parsing, a helper named validate/sanitize/safe), files opened through os.Root, r.URL.Path given to http.ServeFile (which itself rejects '..' in the URL path), os.Args and environment values (the operator, not a requester), comments and strings. A bare filepath.Clean of a relative value is not a check: it keeps leading '../'. os.Stat existence probes and flows across functions are not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-027/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": ["CAPEC-128"],
	"attack_technique": ["T1082"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["path-traversal", "file", "directory"],
}

# A value the requester chooses. os.Args is the program's own operator, not an
# attacker, so a command-line tool reading its argument is not a source here.
_source_core := `\b(?:r|req|request|rq)\.(?:FormValue|PostFormValue)\(|\.URL\.Query\(\)|\b(?:r|req|request|rq)\.(?:Form|PostForm)\.Get\(|\b(?:r|req|request|rq)\.Header\.Get\(|\bmux\.Vars\(|\.PathValue\(|\bps\.ByName\(|\b(?:c|ctx|g|e)\.(?:Query|DefaultQuery|Param|Params|PostForm|DefaultPostForm|FormValue|QueryParam)\(`

_source := concat("|", [_source_core, `\b(?:r|req|request|rq)\.URL\.Path\b`])

_gate_needles := ["FormValue", "URL.Query", "URL.Path", "Form.Get", "Header.Get", "mux.Vars", "PathValue", "ByName(", "Query(", "Param(", "Params(", "PostForm", "QueryParam"]

_gate(content) if {
	some n in _gate_needles
	contains(content, n)
}

# File operations; the match ends where the arguments begin.
_sink_re := `\bos\.(?:Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll|Mkdir|MkdirAll|ReadDir|Rename|Chmod|Chown|Truncate|Symlink|Link|DirFS)\(|\bioutil\.(?:ReadFile|WriteFile|ReadDir)\(|\bhttp\.(?:ServeFile|Dir)\(|\b(?:c|ctx)\.(?:File|FileAttachment|Attachment|Inline|SendFile|Download)\(`

_sink_hint(line) if contains(line, "os.")

_sink_hint(line) if contains(line, "ioutil.")

_sink_hint(line) if contains(line, "ServeFile(")

_sink_hint(line) if contains(line, "http.Dir(")

_sink_hint(line) if contains(line, ".File(")

_sink_hint(line) if contains(line, "SendFile(")

_sink_hint(line) if contains(line, "Attachment(")

_sink_hint(line) if contains(line, "Inline(")

_sink_hint(line) if contains(line, "Download(")

# A check or reduction that keeps the path inside its directory.
_guard_re := `\b(?:filepath|path)\.(?:Base|Rel|IsLocal)\(|\bfs\.ValidPath\(|strings\.HasPrefix\(|"\.\."|\x60\.\.\x60|SecureJoin|securejoin\.|\b(?:filepath|path)\.Clean\(\s*(?:"/"|string\(os\.PathSeparator\)|"\\\\")\s*\+|\bstrconv\.|\buuid\.Parse|(?i:validat|sanitiz|sanitis|issafe|safe_?path|safe_?join|within|contained|allowlist|whitelist)`

# String literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `//.*$`, "")

# The call's arguments, with the continuation lines of a call broken after
# '(' or ','.
_args(_, _, line, rest) := rest if not regex.match(`[(,]\s*$`, line)

_args(lines, i, line, rest) := a if {
	regex.match(`[(,]\s*$`, line)
	end := min([count(lines) - 1, i + 4])
	a := concat(" ", array.concat([rest], [lines[k] | some k in numbers.range(i + 1, end)]))
}

_word(n) := concat("", [`\b`, n, `\b`])

# At most 25 lines up, never above the enclosing top-level func.
_lo(lines, i) := lo if {
	floor := max([0, i - 25])
	starts := [j | some j in numbers.range(floor, i); startswith(lines[j], "func ")]
	lo := max(array.concat([floor], starts))
}

_tainted(lines, i, lo, src) := {v |
	i - 1 >= lo
	some k in numbers.range(lo, i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(src, l)
	not regex.match(_guard_re, l)
	v := helpers.assigned_first(l)
}

_rhs(l) := substring(l, indexof(l, "=") + 1, -1)

# One propagation step: a path built from a tainted variable.
_derived(lines, i, lo, t1) := {v |
	i - 1 >= lo
	some k in numbers.range(lo, i - 1)
	l := lines[k]
	contains(l, "=")
	not helpers.is_comment_line(l)
	some t in t1
	regex.match(_word(t), _rhs(l))
	not regex.match(_guard_re, l)
	v := helpers.assigned_first(l)
	v != t
}

_guarded(lines, i, lo, names) if {
	i - 1 >= lo
	some k in numbers.range(lo, i - 1)
	l := lines[k]
	not helpers.is_comment_line(l)
	some n in names
	regex.match(_word(n), l)
	regex.match(_guard_re, l)
}

# r.URL.Path is no source for http.ServeFile, which rejects ".." in it.
_src_for(m) := _source_core if startswith(m, "http.ServeFile(")

_src_for(m) := _source if not startswith(m, "http.ServeFile(")

_reaches(_, _, src, args) if regex.match(src, args)

_reaches(lines, i, src, args) if {
	lo := _lo(lines, i)
	t1 := _tainted(lines, i, lo, src)
	count(t1) > 0
	names := t1 | _derived(lines, i, lo, t1)
	some n in names
	regex.match(_word(n), args)
	not _guarded(lines, i, lo, names)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	_gate(content)
	regex.match(_sink_re, content)
	regex.match(_source, content)
	lines := split(content, "\n")
	some i, line in lines
	_sink_hint(line)
	regex.match(_sink_re, line)
	not helpers.is_comment_line(line)
	ms := regex.find_all_string_submatch_n(_sink_re, _code(line), 1)
	count(ms) > 0
	m := ms[0][0]
	args := _args(lines, i, line, substring(line, indexof(line, m) + count(m), -1))
	not regex.match(_guard_re, args)
	_reaches(lines, i, _src_for(m), args)
	finding := {
		"rule_id": metadata.id,
		"message": "File path built from request input may allow path traversal; clean the path and confirm it stays inside the intended directory",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
