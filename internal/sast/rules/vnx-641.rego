# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_641

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-641",
	"name": "Improper Restriction of Names for Files and Other Resources",
	"description": "An uploaded or user-supplied file name is classified by a part of the name that is not its real extension, so a double extension such as shell.php.jpg or avatar.jpg.php passes the check while the stored file keeps the dangerous one. Reported, on a file-name expression (filename/fileName/fname/originalname/originalFilename, f.filename, file.name, getOriginalFilename(), getSubmittedFileName(), $_FILES[...]['name'], or a variable assigned straight from one in the 15 lines above): the extension taken from the FIRST dot (Python split('.')[1], split('.', 1)[1], partition('.'); JavaScript and Java split('.')/split(\"\\\\.\")[1] and substring/substr/slice from indexOf('.'); PHP explode('.', $name)[1], substr from strpos($name, '.'), strstr($name, '.')); and an allowlist tested as a substring (Python '.png' in name or any(ext in name for ext in ALLOWED), JavaScript includes('.jpg') or indexOf('.jpg') !== -1, Java contains(\".pdf\") or indexOf(\".pdf\") >= 0, PHP strpos/stripos/strstr($name, '.jpg'), and a regular expression for an extension with no end anchor in JavaScript .test()/.match() or PHP preg_match()). Not reported: the last extension (rsplit('.', 1), split('.')[-1], split('.').pop(), lastIndexOf('.'), os.path.splitext, path.extname, pathinfo, FilenameUtils.getExtension), endswith/endsWith checks and $-anchored patterns, the same calls on names that are not file names (versions, hosts, emails, JWTs), comments and string literals. Storing under the client's name (VNX-66) and case-sensitive extension checks (VNX-178) are separate rules.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-641/",
	"languages": ["java", "node", "python", "php"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [641],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["file-upload", "double-extension", "file-name", "cwe-641"],
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "java" if endswith(path, ".java")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "js" if {
	some ext in {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
	endswith(path, ext)
}

_files_name := `\$_FILES\[\s*['"][^'"]*['"]\s*\]\s*\[\s*['"]name['"]\s*\]`

_name_re := `(?:\b[\w.?]*[.?])?\b(?:file_?name|fileName|filename|fname|original_?name|originalname|originalFilename|uploaded_?name|uploadedName)\b|\b[\w.?]*\.(?:getOriginalFilename|getSubmittedFileName)\(\)|\b(?:file|f|upload|uploaded_?file|attachment)\.name\b`

# Normalise a line: the client file name becomes FN, a '.' literal DOT, an
# extension literal EXT; every other string literal is blanked.
_norm(line, vars) := out if {
	a := regex.replace(line, _files_name, "FN")
	b := regex.replace(a, `["']\\{0,2}\.["']`, "DOT")
	c := regex.replace(b, `["']\.[A-Za-z0-9]{2,5}["']`, "EXT")
	d := regex.replace(regex.replace(c, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)
	e := regex.replace(d, concat("", [`\$?(?:`, _name_re, `)`]), "FN")
	out := _sub_vars(e, vars)
}

_sub_vars(s, vars) := s if count(vars) == 0

_sub_vars(s, vars) := regex.replace(s, concat("", [`\$?\b(?:`, concat("|", sort(vars)), `)\b`]), "FN") if count(vars) > 0

# Variables assigned straight from a file-name expression, found once per
# file as [line, name] pairs; a sink uses those in the 15 lines above it.
_assigns(lines) := [[j, v] |
	some j, l in lines
	contains(l, "=")
	_has_name(l)
	regex.match(concat("", [`=\s*(?:`, _files_name, `|`, _name_re, `)\s*;?\s*$`]), l)
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:var|let|const|final|String|auto)\s+)?\$?([A-Za-z_]\w*)\s*=[^=]`, l, 1)
	count(m) > 0
	v := m[0][1]
]

_vars(assigns, i) := {a[1] |
	some a in assigns
	a[0] < i
	a[0] >= i - 15
}

_bad_re := {
	"py": [
		`\bFN\.split\(\s*DOT\s*(?:,\s*1\s*)?\)\s*\[\s*1\s*\]`,
		`\bFN\.partition\(\s*DOT\s*\)`,
		`\bFN\s*\[\s*FN\.(?:find|index)\(\s*DOT`,
		`\bEXT\s+(?:not\s+)?in\s+FN\b`,
		`\bany\(\s*\w+\s+in\s+FN(?:\.lower\(\))?\s+for\s+\w+\s+in\b`,
	],
	"js": [
		`\bFN\.split\(\s*DOT\s*\)\s*\[\s*1\s*\]`,
		`\.(?:substring|substr|slice)\(\s*FN\.indexOf\(\s*DOT\s*\)`,
		`\bFN\.includes\(\s*EXT\s*\)`,
		`\bFN\.indexOf\(\s*EXT\s*\)\s*(?:!==?\s*-1|>=?\s*-?[01]\b|>\s*-1)`,
		`/\\\.\(?[\w|?]+\)?/[a-z]*\.test\(\s*FN\b`,
		`\bFN\.match\(\s*/\\\.\(?[\w|?]+\)?/[a-z]*\s*\)`,
	],
	"java": [
		`\bFN\.split\(\s*DOT\s*\)\s*\[\s*1\s*\]`,
		`\.substring\(\s*FN\.indexOf\(\s*DOT\s*\)`,
		`\bFN\.contains\(\s*EXT\s*\)`,
		`\bFN\.indexOf\(\s*EXT\s*\)\s*(?:!=\s*-1|>=?\s*0\b|>\s*-1)`,
	],
	"php": [
		`\bexplode\(\s*DOT\s*,\s*FN\s*\)\s*\[\s*1\s*\]`,
		`\b(?:strpos|stripos|strstr|stristr)\(\s*FN\s*,\s*(?:EXT|DOT)`,
		`\bsubstr\(\s*FN\s*,\s*strpos\(\s*FN\s*,\s*DOT`,
	],
}

_bad(lang, _, n) if {
	some re in _bad_re[lang]
	regex.match(re, n)
}

# preg_match('/\.(jpe?g|png)/i', $name): read from the raw line, since the
# pattern is a string literal.
_bad("php", line, n) if {
	regex.match(`\bpreg_match\(\s*['"]/[^'"$]*\\\.\(?[\w|?]+\)?/[a-z]*['"]\s*,`, line)
	regex.match(`\bpreg_match\(\s*''\s*,\s*FN\b`, n)
}

# Cheap substring gates (a dot or extension literal; a file-name word).
_dot_needles := {`".`, `'.`, `"\\.`, `/\.`}

_has_dot(s) if {
	some n in _dot_needles
	contains(s, n)
}

_name_needles := {"ilename", "ileName", "ile_name", "fname", "riginalname", "riginalName", "riginal_name", "ubmittedFileName", "_FILES", "ploaded_name", "ploadedName", "file.name", "f.name", "upload.name", "attachment.name"}

_has_name(s) if {
	some n in _name_needles
	contains(s, n)
}


# A dot or extension literal on the line, or Python's any(ext in name for
# ext in ALLOWED) over a list defined elsewhere in the file.
_line_gate(line) if _has_dot(line)

_line_gate(line) if contains(line, "any(")

# Every reported shape calls one of these.
_op_gate := `split|partition|find|index|\sin\s|includes|substr|slice|contains|explode|strpos|stripos|strstr|stristr|preg_match|\.test\(|\.match\(`

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	_has_dot(content)
	_has_name(content)
	lines := split(content, "\n")
	assigns := _assigns(lines)
	some i, line in lines
	_line_gate(line)
	regex.match(_op_gate, line)
	not helpers.is_comment_line(line)
	n := _norm(line, _vars(assigns, i))
	contains(n, "FN")
	_bad(lang, line, n)
	finding := {
		"rule_id": metadata.id,
		"message": "File name classified by a part that is not its final extension (first dot, or a substring test): a double extension such as shell.php.jpg passes. Compare the lower-cased final extension (after the last dot) against an allowlist and store under a generated name",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
