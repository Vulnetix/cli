# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_178

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-178",
	"name": "Improper Handling of Case Sensitivity",
	"description": "An uploaded file's name or extension is compared case-sensitively against a dangerous extension (php/phtml/phar, jsp/jspx, asp/aspx, exe/dll, sh/bat/cmd/ps1, cgi/pl/py/rb, js, html/svg, htaccess, war/jar): endswith/endsWith/HasSuffix/str_ends_with, ==/===/!=, equals, in [...]/in_array/includes/contains, or a membership test (in X, X.includes/contains/has, in_array($ext, $X), slices.Contains) against a deny-list collection of such extensions defined in the same file, or a case-sensitive regular expression for them (a JavaScript literal without the i flag in .test()/.match(), re.search/re.match without re.I, Java String.matches without (?i)), in a Python, JavaScript/TypeScript, Java, Go or PHP file that handles uploads (request.files, multer originalname, MultipartFile, FormFile, $_FILES), on a line that names the value as a file name, extension, suffix or path. Such a deny check is bypassed by \"shell.PHP\" or \"x.Jsp\", which the server still executes. Not reported: a format, language or output parameter compared with \"html\" or \"py\", a value lower- or upper-cased on the same line or assigned from lower()/toLowerCase()/strings.ToLower/strtolower/casefold in the ten lines above, equalsIgnoreCase/EqualFold, allow-lists of harmless extensions (png, jpg), files that do not handle uploads, the comparison inside a string literal, comments. Equality against a role name such as \"admin\" fails closed and is not reported.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-178/",
	"languages": ["go", "java", "node", "python", "php"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [178],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["case-sensitivity", "validation", "file-upload", "cwe-178"],
}

_exts := {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".go", ".php"}

_upload := `request\.files|\$_FILES|originalname|getOriginalFilename|MultipartFile|FormFile|[Mm]ultipart|[Uu]pload|UPLOAD`

_danger_lit := `["']\.?(?:php[3-8]?|phtml|phar|jsp|jspx|asp|aspx|ashx|asmx|exe|dll|sh|bat|cmd|ps1|cgi|pl|py|rb|js|html?|shtml|svg|htaccess|war|jar)["']`

_compare := `(?:\bends_?[wW]ith|\bendsWith|\bHasSuffix|\bstr_ends_with)\s*\(|[!=]==?|\.equals\s*\(|\bin\s*[\[\(\{]|\bin_array\s*\(|\.includes\s*\(|\.contains\s*\(`

_gate := concat("", [`(?:[wW]ith|Suffix|=|equals|in_array|includes|contains|\bin)\s*[\(\[\{]?[^\n]{0,60}`, _danger_lit, `|`, _danger_lit, `[^\n]{0,60}(?:\.equals|\.includes|\.contains)\s*\(`])

# What says the compared value is a file name or extension, not a format,
# language or role parameter that happens to equal "html" or "py".
_filename_word := `(?i)name|ext|file|suffix|path|upload`

_danger_alt := `(?:php[3-8]?|phtml|phar|jspx?|aspx?|ashx|asmx|exe|dll|sh|bat|cmd|ps1|cgi|pl|py|rb|js|html?|shtml|svg|htaccess|war|jar)`

# A case-sensitive regular expression over the name: a JS literal without the
# i flag, re.search/match without re.I, Java String.matches without (?i).
_regex_check := concat("", [
	`/[^/\n]*\\\.\(?(?:\?:)?[\w|]*\b`, _danger_alt, `\b[^/\n]*/[gmsuy]*\.test\s*\(`,
	`|\.match\s*\(\s*/[^/\n]*\\\.\(?(?:\?:)?[\w|]*\b`, _danger_alt, `\b[^/\n]*/[gmsuy]*\s*\)`,
	`|\bre\.(?:search|match|fullmatch)\s*\(\s*r?["'][^"'\n]*\\\.\(?(?:\?:)?[\w|]*\b`, _danger_alt, `\b[^"'\n]*["']\s*,`,
	`|\.matches\s*\(\s*"[^"\n]*\\\\\.\(?(?:\?:)?[\w|]*\b`, _danger_alt, `\b[^"\n]*"\s*\)`,
])

_regex_insensitive := `\bre\.I\b|re\.IGNORECASE|\(\?i\)|flags\s*=\s*re\.I`

# A deny-list collection of dangerous extensions bound to a name in this
# file; its later membership test on an un-normalised name is the comparison.
_denylist_def := concat("", [`(?m)^[^\n]*?\$?\b([A-Za-z_]\w*)\s*(?::[^=\n]*)?=\s*(?:array\s*\(|\[|\{|\(|frozenset\(|set\(|(?:List|Set)\.of\(|Arrays\.asList\(|new\s+[\w.]+\s*\[\]\s*\{|\[\]string\{|new\s+Set\(\s*\[)[^\n]*`, _danger_lit])

_member_use(line, name) if regex.match(concat("", [`\bin\s+(?:self\.)?`, name, `\b`]), line)

_member_use(line, name) if regex.match(concat("", [`\b`, name, `\.(?:includes|contains|has)\s*\(`]), line)

_member_use(line, name) if regex.match(concat("", [`\bin_array\s*\([^,]+,\s*\$`, name, `\b`]), line)

_member_use(line, name) if regex.match(concat("", [`\bslices\.Contains\s*\(\s*`, name, `\b`]), line)

_normalised_inline :=`(?i)lower|upper|casefold|EqualFold|IgnoreCase`

_norm_src := `(?i)\.lower\(\)|\.casefold\(\)|\.upper\(\)|to(?:Lower|Upper)Case\(|strings\.To(?:Lower|Upper)\(|\bstrto(?:lower|upper)\(|\bmb_strto(?:lower|upper)\(`

_in_string(line, word) if {
	idx := indexof(line, word)
	idx >= 0
	pre := regex.replace(substring(line, 0, idx), `\\.`, "")
	_odd(pre)
}

_odd(pre) if count(regex.find_n(`"`, pre, -1)) % 2 == 1

_odd(pre) if count(regex.find_n(`'`, pre, -1)) % 2 == 1

findings contains finding if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not endswith(path, ".min.js")
	regex.match(_danger_lit, content)
	regex.match(_upload, content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 400
	regex.match(_gate, line)
	not helpers.is_comment_line(line)
	not regex.match(`\bin_array\s*\(\s*["']`, line)
	cmps := regex.find_n(_compare, line, 1)
	count(cmps) > 0
	not _in_string(line, cmps[0])
	_unnormalised_name(lines, i, line)
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in _upload_files
	regex.match(_danger_lit, content)
	names := {m[1] | some m in regex.find_all_string_submatch_n(_denylist_def, content, -1)}
	count(names) > 0
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 400
	some name in names
	_member_use(line, name)
	not regex.match(_danger_lit, line)
	not helpers.is_comment_line(line)
	not _in_string(line, name)
	_unnormalised_name(lines, i, line)
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in _upload_files
	regex.match(_regex_check, content)
	lines := split(content, "\n")
	some i, line in lines
	count(line) < 400
	regex.match(_regex_check, line)
	not regex.match(_regex_insensitive, line)
	not helpers.is_comment_line(line)
	_unnormalised_name(lines, i, line)
	finding := _finding(path, i, line)
}

_upload_files[path] := content if {
	some path, content in input.file_contents
	some ext in _exts
	endswith(path, ext)
	not endswith(path, ".min.js")
	regex.match(_upload, content)
}

_unnormalised_name(lines, i, line) if {
	regex.match(_filename_word, line)
	not regex.match(_normalised_inline, line)
	count(helpers.tainted_vars(lines, i, 10, _norm_src)) == 0
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Uploaded file name/extension is compared case-sensitively against a dangerous extension; \"shell.PHP\" passes this check. Lower-case the name before comparing, and prefer an allow-list",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
