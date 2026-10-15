package vulnetix.rules.vnx_go_026

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-026",
	"name": "Missing file type validation on upload",
	"description": "An uploaded file is written to disk under the name the client sent, and nothing in the handler checks what kind of file it is. The handler receives a multipart file (r.FormFile, c.FormFile in gin/echo/fiber, beego GetFile, MultipartForm().File[...], a MultipartReader part) and saves it with os.Create, os.OpenFile, os.WriteFile, ioutil.WriteFile, gin SaveUploadedFile, fiber SaveFile, beego SaveToFile or iris SaveFormFile to a path built from the client's FileHeader.Filename or Part.FileName(), so the client picks the extension (shell.php, page.html, .htaccess) of a file the server stores and may serve. Not reported: a handler that checks the type anywhere (filepath.Ext/path.Ext, strings.HasSuffix, http.DetectContentType, the part's Content-Type header, mime/mimetype/filetype detection, image.Decode/DecodeConfig, or a helper named for the check such as validateUpload/isAllowedType), a file saved under a server-generated name, a file parsed in memory and never written, a client building a multipart request, comments and strings. A check in another function the handler does not call by such a name is not seen.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-026/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [434],
	"capec": ["CAPEC-177"],
	"attack_technique": ["T1105"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["file-upload", "validation", "mime-type"],
}

# The handler receives an uploaded file.
_upload_re := `\b\w+\.(?:FormFile|GetFile)\(|\bMultipartForm\b|\.MultipartReader\(\)`

# The client-supplied name.
_client_name_re := `\.Filename\b|\.FileName\(\)`

# A write of the upload to disk; the match ends where the arguments begin.
_save_re := `\bos\.(?:Create|OpenFile|WriteFile)\(|\bioutil\.WriteFile\(|\.(?:SaveUploadedFile|SaveFile|SaveToFile|SaveFormFile)\(`

# A check of the file's type, anywhere in the handler.
_type_check_re := `\b(?:filepath|path)\.Ext\(|strings\.HasSuffix\(|DetectContentType\(|"Content-Type"|\bmime\.|\bmimetype\.|\bfiletype\.|\bimage\.Decode|\b(?:png|jpeg|gif|webp)\.Decode|(?i:\b(?:is|has|check|validate|verify|ensure|allowed|permitted|valid)\w*(?:type|ext|extension|mime|image|upload|file|content)\w*\s*\()|(?i:allowed_?(?:types|ext|extensions|mimes?))`

# String literals blanked, a trailing // comment removed.
_code(line) := regex.replace(regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"|`[^`]*`", `""`), `//.*$`, "")

_fn_start(lines, i) := max(array.concat([0], [j | some j in numbers.range(max([0, i - 120]), i); startswith(lines[j], "func ")]))

_fn_end(lines, i) := e if {
	n := count(lines) - 1
	ends := [j | some j in numbers.range(min([i + 1, n]), min([i + 200, n])); startswith(lines[j], "}")]
	e := min(array.concat([min([i + 200, n])], ends))
}

_word(n) := concat("", [`\b`, n, `\b`])

# Variables of this function that hold the client name or a path built from
# it, assigned above the write.
_name_vars(lines, fs, i) := {v |
	i - 1 >= fs
	some k in numbers.range(fs, i - 1)
	l := lines[k]
	regex.match(_client_name_re, l)
	not helpers.is_comment_line(l)
	v := helpers.assigned_first(l)
}

_names_client(_, _, _, args) if regex.match(_client_name_re, args)

_names_client(lines, fs, i, args) if {
	some v in _name_vars(lines, fs, i)
	regex.match(_word(v), args)
}

# One more hop: target := path.Join(dir, name), where name holds the client
# name.
_names_client(lines, fs, i, args) if {
	nv := _name_vars(lines, fs, i)
	count(nv) > 0
	i - 1 >= fs
	some k in numbers.range(fs, i - 1)
	l := lines[k]
	contains(l, "=")
	not helpers.is_comment_line(l)
	some v in nv
	regex.match(_word(v), substring(l, indexof(l, "=") + 1, -1))
	d := helpers.assigned_first(l)
	d != v
	regex.match(_word(d), args)
}

_has_upload(lines, fs, i) if {
	some k in numbers.range(fs, i)
	regex.match(_upload_re, _code(lines[k]))
	not helpers.is_comment_line(lines[k])
}

_type_checked(lines, fs, e) if {
	some k in numbers.range(fs, e)
	l := lines[k]
	not helpers.is_comment_line(l)
	regex.match(_type_check_re, l)
}

# The call's arguments, with the continuation lines of a call broken after
# '(' or ','.
_args(_, _, line, rest) := rest if not regex.match(`[(,]\s*$`, line)

_args(lines, i, line, rest) := a if {
	regex.match(`[(,]\s*$`, line)
	end := min([count(lines) - 1, i + 3])
	a := concat(" ", array.concat([rest], [lines[k] | some k in numbers.range(i + 1, end)]))
}

_save_hint(line) if contains(line, "os.")

_save_hint(line) if contains(line, "ioutil.")

_save_hint(line) if contains(line, ".Save")

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`FormFile\(|GetFile\(|MultipartForm|MultipartReader\(`, content)
	regex.match(`\.Filename\b|\.FileName\(\)`, content)
	lines := split(content, "\n")
	some i, line in lines
	_save_hint(line)
	not helpers.is_comment_line(line)
	code := _code(line)
	ms := regex.find_all_string_submatch_n(_save_re, code, 1)
	count(ms) > 0
	args := _args(lines, i, line, substring(line, indexof(line, ms[0][0]) + count(ms[0][0]), -1))
	fs := _fn_start(lines, i)
	_has_upload(lines, fs, i)
	_names_client(lines, fs, i, args)
	not _type_checked(lines, fs, _fn_end(lines, i))
	finding := {
		"rule_id": metadata.id,
		"message": "Uploaded file is saved under the client's own file name with no check of its type or extension: a .php, .html or .htaccess upload lands where the server can serve or run it. Allow-list the extension and sniff the content (http.DetectContentType), and store under a generated name",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
