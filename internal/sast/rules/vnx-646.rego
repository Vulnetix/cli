# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_646

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-646",
	"name": "Uploaded file accepted or classified by its client-supplied name or extension",
	"description": "Server code decides whether, or how, to handle an uploaded file from the file name the client sent, which the client chooses freely: shell.php.jpg, a renamed executable or an HTML page called report.pdf passes (CWE-646). Reported in JavaScript/TypeScript (multer originalname, formidable originalFilename, express-fileupload req.files.x.name) and Python (Flask/Werkzeug and FastAPI .filename, a filename parameter, Django request.FILES[...].name or an upload variable's .name, Django FileExtensionValidator) in a file that handles uploads: a condition, return, membership test or regex test that looks at the extension (endsWith/endswith, extname, splitext, rsplit/split on '.', lastIndexOf('.'), .suffix, a /\\.(png|jpg)$/ regex) of the upload's name, directly or through a variable assigned from it up to 10 lines above. Not reported: files that also inspect the content (file-type/fileTypeFromBuffer, mmmagic, magic bytes, image-size, sharp, jimp; python-magic, filetype, puremagic, imghdr, PIL Image.open/verify), building a storage filename from the extension, extension checks on paths that are not uploads (static file serving, build scripts), comments and string literals. Whether a content check elsewhere in the project covers the upload is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-646/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [646],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["file-upload", "file-extension", "cwe-646"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "js" if {
	some ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
	endswith(path, ext)
}

_upload := {
	"js": `originalname|originalFilename|\breq\.files\b`,
	"py": `request\.files|request\.FILES|UploadFile|FileStorage|FileField|UploadedFile|FileExtensionValidator`,
}

_content_check := {
	"js": `file-type|fileTypeFrom|fromBuffer|mmmagic|magic-bytes|magicBytes|readChunk|image-size|imageSize\(|\bsharp\(|jimp|Jimp`,
	"py": `\bmagic\.|\bfiletype\.|puremagic|imghdr|Image\.open\(|\.verify\(\)|from_buffer\(|imagesize\.`,
}

# The upload's client-supplied name.
_name := {
	"js": `\.originalname\b|\.originalFilename\b|\breq\.files\??\.[\w?.\[\]'"]*\.name\b|\b(?:upload|uploaded\w*|file|doc|attachment|avatar|image)\??\.name\b`,
	"py": `\.filename\b|\bfile_?name\b|\bfname\b|\brequest\.FILES\[[^\]]+\]\.name\b|\b(?:upload\w*|uploaded\w*|file|f|doc|document|attachment|avatar|image|photo|resume)\.name\b`,
}

# An extension test or extraction.
_ext := {
	"js": `\.endsWith\(\s*['"\x60]\.|/\\\.[^/\n]*\$/[a-z]*\.test\(|\.match\(\s*/[^/\n]*\\\.|\bextname\(|lastIndexOf\(\s*['"]\.['"]\s*\)|\.split\(\s*['"]\.['"]\s*\)`,
	"py": `\.endswith\(|\.rsplit\(\s*['"]\.['"]|\.split\(\s*['"]\.['"]\s*\)|\bsplitext\(|\.suffix\b`,
}

# The line decides something.
_decision := {
	"js": `\bif\s*\(|\breturn\b|(?:^|[^?])\?(?:[^.?]|$)|&&|\|\||[!=]==?|\.includes\(|\.indexOf\(|\.test\(|\bcase\b`,
	"py": `\bif\b|\breturn\b|\bin\b|==|!=|\band\b|\bor\b|\bassert\b|\bwhile\b`,
}

# String literals containing whitespace are prose.
_strip_prose(line) := c if {
	lits := [l |
		some l in regex.find_all_string_submatch_n(`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`, line, -1)
		regex.match(`\s`, l[0])
	]
	c := strings.replace_n({l[0]: `""` | some l in lits}, line)
}

# Every name on the left of a plain assignment (const x =, _, ext =, x: T =).
_lhs(line) := {n |
	m := regex.find_all_string_submatch_n(`^\s*(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*)*)\s*(?::\s*[\w<>\[\]| ]+)?=[^=]`, line, 1)
	count(m) > 0
	some part in split(m[0][1], ",")
	n := trim_space(part)
	n != "_"
}

# Variables assigned from the upload name (with or without an extension
# extraction) in the ten lines above i.
_derived(lines, i, lang, need_ext) := {n |
	some j in numbers.range(max([0, i - 10]), i - 1)
	prev := _strip_prose(lines[j])
	not helpers.is_comment_line(lines[j])
	regex.match(_name[lang], prev)
	_ext_ok(prev, lang, need_ext)
	some n in _lhs(prev)
}

_ext_ok(_, _, false)

_ext_ok(line, lang, true) if regex.match(_ext[lang], line)

_refs(line, names) if {
	some n in names
	regex.match(concat("", [`(?:^|[^\w.$])`, n, `\b`]), line)
}

_extension_decision(_, _, c, lang) if {
	regex.match(_name[lang], c)
	regex.match(_ext[lang], c)
}

_extension_decision(lines, i, c, lang) if {
	regex.match(_ext[lang], c)
	_refs(c, _derived(lines, i, lang, false))
}

_extension_decision(lines, i, c, lang) if _refs(c, _derived(lines, i, lang, true))

_in_docstring(lines, i) if {
	n := sum([count(regex.find_all_string_submatch_n(`"""|'''`, lines[j], -1)) | some j in numbers.range(0, i - 1)])
	n % 2 == 1
}

_docstring(lines, i, "py") if _in_docstring(lines, i)

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	regex.match(_upload[lang], content)
	not regex.match(_content_check[lang], content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_decision[lang], line)
	not helpers.is_comment_line(line)
	c := _strip_prose(line)
	regex.match(_decision[lang], c)
	_extension_decision(lines, i, c, lang)
	not _docstring(lines, i, lang)
	finding := {
		"rule_id": metadata.id,
		"message": "The uploaded file is judged by the name or extension the client sent, which the client chooses freely. Check the content (magic bytes, a decoder) and store it under a server-chosen name and type",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "FileExtensionValidator(")
	not regex.match(_content_check.py, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "FileExtensionValidator(")
	not helpers.is_comment_line(line)
	not regex.match(`^\s*(?:from|import)\s`, line)
	finding := {
		"rule_id": metadata.id,
		"message": "FileExtensionValidator checks only the name the client sent. Validate the content as well (python-magic, Pillow verify) before trusting the file type",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
