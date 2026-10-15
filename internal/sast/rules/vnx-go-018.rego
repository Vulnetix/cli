package vulnetix.rules.vnx_go_018

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-018",
	"name": "Go arbitrary file write via os.WriteFile/os.Create with user-controlled path",
	"description": "A file or directory is created, written, renamed or linked at a path built from HTTP request data with nothing confining it to the intended directory. Writes are os.Create, os.WriteFile, ioutil.WriteFile, os.OpenFile with a write flag (O_WRONLY, O_RDWR, O_CREATE, O_APPEND, O_TRUNC), os.Mkdir/MkdirAll, os.Rename/Symlink/Link/Truncate, gin SaveUploadedFile and fiber SaveFile. Request data is a form, query, path, header or router parameter (r.FormValue, r.URL.Query().Get, r.PathValue, gin's c.Request.FormValue, mux.Vars, chi.URLParam, httprouter ByName, gin/echo/fiber c.Param/c.Query/c.PostForm/c.FormValue) and, in a file that reads multipart uploads, a part's client-supplied .Filename; it reaches the path directly, through the variable it was assigned to, or through one more assignment (name := r.FormValue(...); p := filepath.Join(dir, name); os.WriteFile(p, ...)). filepath.Clean alone is not confinement: Clean(Join(dir, \"../../etc/x\")) is /etc/x. Not reported when the function confines the path (filepath.Base or path.Base of the name, filepath.IsLocal, filepath.Rel, strings.HasPrefix on the cleaned or joined result (a prefix test on the raw name, HasPrefix(name, \"report-\"), confines nothing and is still reported), a '..' check, securejoin, os.OpenRoot / os.Root, Clean(\"/\" + name), or a helper named for validation or sanitising), when the file name is chosen by the server or is a number parsed from the request (strconv.Atoi/ParseInt, uuid.Parse), when the path comes from flags or os.Args (the operator, not a requester), for opening files read-only (path traversal on reads is VNX-GO-027), in comments and in test files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-018/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [22],
	"capec": ["CAPEC-139"],
	"attack_technique": ["T1083"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["path-traversal", "file-write", "go"],
}

# Calls whose first argument is a path that is written.
_first_arg_write := `\b(?:os\.(?:Create|WriteFile|OpenFile|Mkdir|MkdirAll|Truncate)|ioutil\.WriteFile)\(`

# Calls where any argument is a path that is moved, linked or saved to.
_any_arg_write := `\b(?:os\.(?:Rename|Symlink|Link)|\w+\.SaveUploadedFile|c\.SaveFile)\(`

_write_re := concat("|", [_first_arg_write, _any_arg_write])

_req_src := `\b(?:r|req|request|(?:c|ctx)\.Request)\.(?:FormValue|PostFormValue|PathValue)\(|\b(?:r|req|request|(?:c|ctx)\.Request)\.(?:URL\.(?:Query\(|RawQuery|Path)|Header\.Get\()|\bmux\.Vars\(|\bchi\.URLParam\(|\b(?:c|ctx|g|e)\.(?:Query|DefaultQuery|Param|Params|PostForm|DefaultPostForm|FormValue|QueryParam|GetHeader)\(|\.ByName\(`

# A multipart part's file name is the client's choice too.
_upload_src := concat("", [_req_src, `|\b\w+\.Filename\b`])

_uploads(content) if regex.match(`FormFile\(|MultipartForm|multipart\.FileHeader|MultipartReader\(`, content)

_src(content) := _upload_src if _uploads(content)

_src(content) := _req_src if not _uploads(content)

# Confinement of the path, on the path itself or anywhere it is checked.
_guard_re := `\b(?:filepath|path)\.(?:Base|IsLocal|Rel)\(|"\.\."|\x60\.\.\x60|SecureJoin|securejoin\.|os\.OpenRoot\(|\.OpenInRoot\(|Clean\(\s*(?:"/"|string\(\s*(?:os|filepath)\.(?:PathSeparator|Separator)\s*\))\s*\+|(?i:sanitiz|validat|is_?safe|safe_?(?:path|name|join)|within|contained|confine)`

# An assignment that confines the value, or keeps only its extension (Ext never
# contains a separator), taints nothing. Ext is not a guard on its own: a
# checked extension says nothing about the directories before it. A number
# parsed from the value, or a prefix test's boolean, carries no separator.
_no_taint_re := concat("|", [_guard_re, `\b(?:filepath|path)\.Ext\(|\bstrings\.HasPrefix\(|\bstrconv\.(?:Atoi|Parse(?:Int|Uint|Float|Bool))\(|\buuid\.Parse\(`])

_fn_start(lines, i) := max(array.concat([max([0, i - 80])], [j | some j in numbers.range(max([0, i - 80]), i); startswith(lines[j], "func ")]))

_word(v) := concat("", [`\b`, v, `\b`])

# Variables assigned from request data in this function, and variables
# assigned from those (one more hop). An assignment that confines the value
# (name := filepath.Base(...)) taints nothing.
_t1(lines, fs, i, src) := {v |
	some j in numbers.range(fs, i - 1)
	j < i
	l := lines[j]
	regex.match(src, l)
	not helpers.is_comment_line(l)
	not regex.match(_no_taint_re, l)
	v := helpers.assigned_first(l)
}

_t2(lines, fs, i, t1) := {v |
	some j in numbers.range(fs, i - 1)
	j < i
	l := lines[j]
	some t in t1
	regex.match(_word(t), l)
	not helpers.is_comment_line(l)
	not regex.match(_no_taint_re, l)
	v := helpers.assigned_first(l)
}

# The call's text, with continuation lines when it is broken after ( or ,.
_stmt(lines, i, line) := line if not regex.match(`[(,]\s*$`, line)

_stmt(lines, i, line) := concat(" ", array.slice(lines, i, min([count(lines), i + 5]))) if regex.match(`[(,]\s*$`, line)

# The path argument(s) of the write call.
_paths(stmt) := m[0][1] if {
	m := regex.find_all_string_submatch_n(concat("", [`(?:`, _first_arg_write, `)\s*((?:[^,()]|\((?:[^()]|\([^()]*\))*\))+)`]), stmt, 1)
	count(m) > 0
}

_paths(stmt) := m[0][1] if {
	m := regex.find_all_string_submatch_n(concat("", [`(?:`, _any_arg_write, `)([^\n]*)`]), stmt, 1)
	count(m) > 0
}

_writes(stmt) if not regex.match(`\bos\.OpenFile\(`, stmt)

_writes(stmt) if {
	regex.match(`\bos\.OpenFile\(`, stmt)
	regex.match(`\bO_(?:WRONLY|RDWR|CREATE|APPEND|TRUNC)\b`, stmt)
}

_tainted_path(p, src, _) if regex.match(src, p)

_tainted_path(p, _, tainted) if {
	some v in tainted
	regex.match(_word(v), p)
}

# A prefix check confines only a cleaned or joined path: HasPrefix(name,
# "report-") on the raw name still lets "report-/../../x" through.
_cleaned_re := `\b(?:filepath|path)\.(?:Clean|Join|Abs)\(`

_cleaned(_, _, _, a) if regex.match(_cleaned_re, a)

_cleaned(lines, fs, i, a) if {
	v := trim_space(a)
	regex.match(`^\w+$`, v)
	some j in numbers.range(fs, i)
	contains(lines[j], v)
	regex.match(concat("", [`^\s*`, v, `\s*(?:,\s*\w+\s*)?:?=.*`, _cleaned_re]), lines[j])
}

_guard_line(_, _, _, l) if regex.match(_guard_re, l)

_guard_line(lines, fs, i, l) if {
	m := regex.find_all_string_submatch_n(`\bstrings\.HasPrefix\(\s*((?:[^,()]|\([^()]*\))+),`, l, 1)
	count(m) > 0
	_cleaned(lines, fs, i, m[0][1])
}

_guarded(lines, fs, i, tainted) if {
	some j in numbers.range(fs, i)
	l := lines[j]
	_guard_line(lines, fs, i, l)
	not helpers.is_comment_line(l)
	some v in tainted
	regex.match(_word(v), l)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(_write_re, content)
	regex.match(`FormValue|PostFormValue|URL\.Query|URL\.Path|Header\.Get|mux\.Vars|URLParam|PathValue|\.Param|\.Query\(|\.PostForm|QueryParam|ByName|Filename`, content)
	not helpers.is_test_path(path)
	src := _src(content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_write_re, line)
	not helpers.is_comment_line(line)
	stmt := _stmt(lines, i, line)
	_writes(stmt)
	p := _paths(stmt)
	not regex.match(_guard_re, p)
	fs := _fn_start(lines, i)
	t1 := _t1(lines, fs, i, src)
	tainted := t1 | _t2(lines, fs, i, t1)
	_tainted_path(p, src, tainted)
	not _guarded(lines, fs, i, tainted)
	finding := {
		"rule_id": metadata.id,
		"message": "A file is written at a path built from request data with no check that it stays inside the intended directory; strip directories with filepath.Base or reject names that are not filepath.IsLocal, verify the joined path with filepath.Rel, or write through os.Root",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
