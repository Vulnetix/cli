# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1230

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1230",
	"name": "Exposure of Sensitive Information Through Metadata",
	"description": "Reports a handler that stores a user-uploaded image byte for byte, so the EXIF block it carries (GPS coordinates, device make and serial, capture time, sometimes the owner's name) is published with it when the image is served. Reported, in a file that handles images (an image/ MIME check, an image extension, or avatar/photo/picture naming) and never re-encodes or strips them (no sharp, jimp, gm, Pillow Image.open/ImageOps, piexif, exif or strip-metadata call in the file; Python's str.strip() does not count, and comment lines are ignored when judging image context): Node fs.writeFile/writeFileSync of an uploaded buffer (req.file.buffer, or a variable taken from req.file/req.files or a .buffer), express-fileupload .mv() on a req.files entry, multer({ dest }) and multer.diskStorage(); Python Flask request.files[...] .save() (directly, through a variable, or in a for loop over request.files.getlist()), Django default_storage/FileSystemStorage .save() of a request.FILES entry, and a chunks() loop copying one to disk. Not reported: images decoded and re-encoded or stripped in the same file, uploads in files with no image context (documents, CSV), comments and test files. Stripping performed in another module is not visible to this line-oriented rule.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1230/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [1230],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["metadata-exposure", "cwe-1230"],
}

_msg := "An uploaded image is stored exactly as received, so its EXIF metadata (GPS location, device, timestamps) is published with it. Re-encode it (sharp/Pillow) or strip the metadata before storing"

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# Image context is judged on code, not comments: a comment that mentions
# avatars must not turn a PDF upload into an image upload.
_image_context(content) if _image_context_code(regex.replace(content, `(?m)^[ \t]*(?://|#|/?\*).*$`, ""))

_image_context_code(content) if regex.match(`(?i)image/|startsWith\(\s*['"]image|\.(?:jpe?g|png|gif|webp|heic|tiff?)\b|["'](?:jpe?g|png|gif|webp|heic)["']|avatar|profile_?image|\bphotos?\b|\bpictures?\b`, content)

# ── JavaScript / TypeScript ─────────────────────────────────────────────

_is_js(path) if {
	some ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_js_strips(content) if regex.match(`(?i)\bsharp\b|\bjimp\b|\bgm\(|exif|withMetadata|\bstrip_?(?:exif|metadata)|\.strip\(\s*\)|imagemagick`, content)

_js_upload_src := `req\.files?\b|\.buffer\b`

_js_upload_expr(arg) if regex.match(`^(?:req\.files?\b|[\w$]+\??\.buffer\b)`, arg)

findings contains finding if {
	some path, content in input.file_contents
	_is_js(path)
	regex.match(`req\.files?\b|multer`, content)
	_image_context(content)
	not _js_strips(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`writeFile|\.mv\(|multer`, line)
	not helpers.is_comment_line(line)
	_js_sink(lines, i, line)
	finding := _finding(path, i, line)
}

_js_sink(_, _, line) if regex.match(`\bmulter\s*\(\s*\{[^}]*\bdest\s*:|\bmulter\.diskStorage\s*\(`, line)

_js_sink(_, _, line) if regex.match(`\breq\.files\??(?:\.\w+|\[[^\]]+\])\??\.mv\(`, line)

_js_sink(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_$][\w$]*)\.mv\(`, line, 1)
	count(m) > 0
	m[0][1] in helpers.tainted_names(lines, i, 30, `req\.files\b`)
}

_js_sink(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`\bwriteFile(?:Sync)?\(\s*(?:[^,]|\([^)]*\))+,\s*([\w$.?]+)`, line, 1)
	count(m) > 0
	arg := m[0][1]
	_js_arg_tainted(lines, i, arg)
}

_js_arg_tainted(_, _, arg) if _js_upload_expr(arg)

_js_arg_tainted(lines, i, arg) if {
	regex.match(`^[A-Za-z_$][\w$]*$`, arg)
	arg in helpers.tainted_names(lines, i, 30, _js_upload_src)
}

# ── Python ──────────────────────────────────────────────────────────────

# str.strip() is everywhere in Python, so only a metadata-specific strip counts.
_py_strips(content) if regex.match(`(?i)exif|\bPIL\b|Image\.open|ImageOps|\bstrip_?(?:exif|metadata)|pillow|wand\.image`, content)

_py_src := `request\.(?:files|FILES)\b`

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(_py_src, content)
	_image_context(content)
	not _py_strips(content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.save\(|\.chunks\(`, line)
	not helpers.is_comment_line(line)
	_py_sink(lines, i, line)
	finding := _finding(path, i, line)
}

# request.files["x"].save(...) / request.files.get("x").save(...)
_py_sink(_, _, line) if regex.match(`request\.files(?:\[[^\]]+\]|\.get\([^)]*\))\.save\(`, line)

# f = request.files["x"]; f.save(...)
_py_sink(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\.save\(`, line, 1)
	count(m) > 0
	m[0][1] in helpers.tainted_names(lines, i, 30, `request\.files\b`)
}

# for f in request.files.getlist("x"): f.save(...)
_py_sink(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\.save\(`, line, 1)
	count(m) > 0
	name := m[0][1]
	some j in numbers.range(max([0, i - 30]), i - 1)
	regex.match(sprintf(`^\s*(?:async\s+)?for\s+%s\s+in\s+request\.files\b`, [name]), lines[j])
}

# default_storage.save(name, request.FILES["x"]) or of a variable from it
_py_sink(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`\b(?:default_storage|storage|fs|FileSystemStorage\([^)]*\))\.save\(\s*(?:[^,]|\([^)]*\))+,\s*([\w.\[\]"']+)`, line, 1)
	count(m) > 0
	_py_arg_tainted(lines, i, m[0][1])
}

# for chunk in f.chunks(): dest.write(chunk)
_py_sink(lines, i, line) if {
	m := regex.find_all_string_submatch_n(`\bfor\s+\w+\s+in\s+([\w.\[\]"']+)\.chunks\(`, line, 1)
	count(m) > 0
	_py_arg_tainted(lines, i, m[0][1])
}

_py_arg_tainted(_, _, arg) if regex.match(`^request\.FILES\b`, arg)

_py_arg_tainted(lines, i, arg) if {
	regex.match(`^[A-Za-z_]\w*$`, arg)
	arg in helpers.tainted_names(lines, i, 30, `request\.FILES\b`)
}
