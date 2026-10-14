package vulnetix.rules.vnx_go_007

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-007",
	"name": "Go path traversal",
	"description": "A file is read, listed or sent to the client from a path that contains a value the requester chooses: the path argument of os.Open, os.OpenFile, os.ReadFile, os.ReadDir, os.DirFS, ioutil.ReadFile/ReadDir, http.ServeFile, http.Dir, gin c.File/FileAttachment, echo c.File/Attachment/Inline or fiber c.SendFile/Download holds a request read (r.FormValue, r.PostFormValue, r.URL.Query(), r.Form/PostForm.Get, r.Header.Get, r.PathValue, gorilla/mux Vars, httprouter ps.ByName, gin c.Query/DefaultQuery/Param/PostForm, echo c.QueryParam/Param/FormValue, fiber c.Query/Params) inline, through the variable it was assigned to in the 25 lines above (within the same function), or through one path built from that variable (filepath.Join, path.Join, fmt.Sprintf, concatenation), so ../../etc/passwd escapes the directory. Calls broken over several lines are read as one. filepath.Clean alone is not a check (it keeps a leading ../). Not reported: a value reduced or checked first (filepath.Base, filepath.IsLocal, filepath.Rel, strings.HasPrefix, a '..' test, fs.ValidPath, SecureJoin, a Clean of a rooted \"/\"+value, strconv number parsing, uuid.Parse, a helper named validate/sanitize/safe/within), files opened through os.Root (root.Open), http.FileServer, r.URL.Path given to http.ServeFile (which itself rejects '..' elements), paths from flags, os.Args or the environment (the operator, not a requester), and the call inside a string literal or comment. Flows across functions are not followed. Writes with a request-chosen path are VNX-GO-018; VNX-GO-027 covers reads and writes together.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-007/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": ["CAPEC-126"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["path-traversal", "file-access", "lfi"],
}

# A value the requester chooses (not r.URL.Path: see _src_for).
_source_core := `\b(?:r|req|request|rq)\.(?:FormValue|PostFormValue)\(|\.URL\.Query\(\)|\b(?:r|req|request|rq)\.(?:Form|PostForm)\.Get\(|\b(?:r|req|request|rq)\.Header\.Get\(|\bmux\.Vars\(|\.PathValue\(|\bps\.ByName\(|\b(?:c|ctx|g|e)\.(?:Query|DefaultQuery|Param|Params|PostForm|DefaultPostForm|FormValue|QueryParam)\(`

_source := concat("|", [_source_core, `\b(?:r|req|request|rq)\.URL\.Path\b`])

# The cheap whole-file test that precedes the regex gate.
_gate_needles := ["FormValue", "URL.Query", "URL.Path", "Form.Get", "Header.Get", "mux.Vars", "PathValue", "ByName(", "Query(", "Param(", "Params(", "PostForm", "QueryParam"]

_gate(content) if {
	some n in _gate_needles
	contains(content, n)
}

# Reads, listings and downloads; the match ends where the arguments begin.
_sink_re := `\bos\.(?:Open|OpenFile|ReadFile|ReadDir|DirFS)\(|\bioutil\.(?:ReadFile|ReadDir)\(|\bhttp\.(?:ServeFile|Dir)\(|\b(?:c|ctx)\.(?:File|FileAttachment|Attachment|Inline|SendFile|Download)\(`

_sink_needles := ["os.Open", "os.ReadFile(", "os.ReadDir(", "os.DirFS(", "ioutil.Read", "ServeFile(", "http.Dir(", ".File(", "FileAttachment(", ".Attachment(", ".Inline(", "SendFile(", ".Download("]

_sink_hint(line) if {
	some n in _sink_needles
	contains(line, n)
}

# A check or reduction that keeps the path inside its directory.
_guard_re := `\b(?:filepath|path)\.(?:Base|Rel|IsLocal)\(|\bfs\.ValidPath\(|strings\.HasPrefix\(|"\.\."|\x60\.\.\x60|SecureJoin|securejoin\.|\b(?:filepath|path)\.Clean\(\s*(?:"/"|string\(os\.PathSeparator\)|"\\\\")\s*\+|\bstrconv\.|\buuid\.Parse|(?i:validat|sanitiz|sanitis|issafe|safe_?path|safe_?join|safe_?name|within|contained|allowlist|whitelist)`

# String literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `//.*$`, "")

# The call's arguments, joined with the continuation lines of a call broken
# after '(' or ','.
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
	not helpers.is_comment_line(line)
	ms := regex.find_all_string_submatch_n(_sink_re, _code(line), 1)
	count(ms) > 0
	m := ms[0][0]
	args := _args(lines, i, line, substring(line, indexof(line, m) + count(m), -1))
	not regex.match(_guard_re, args)
	_reaches(lines, i, _src_for(m), args)
	finding := {
		"rule_id": metadata.id,
		"message": "File is read or served from a path that contains request input (path traversal); reduce it with filepath.Base or confirm the cleaned path stays inside the intended directory, or open it through os.Root",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
