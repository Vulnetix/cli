# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_687

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-687",
	"name": "Function Call With Incorrectly Specified Argument Value",
	"description": "A call passes an argument value that is wrong for what the function expects, visible on the call line. Reported in C and C++: strncat(dst, src, sizeof dst), whose bound must be the space left (sizeof dst - strlen(dst) - 1), not the whole buffer; strncpy/strncat bounded by strlen() of the source itself, which bounds nothing and drops the terminator; fgets, snprintf, vsnprintf, strncpy, strlcpy, strlcat, memset, memcpy, memmove, bzero, getcwd, gethostname, read, recv, recvfrom, pread and readlink given sizeof(buf) + N for the very buffer they write; and fopen/freopen/fdopen with a mode string that is not a valid mode (\"rw\", \"wr+\"). Reported in C, C++, Python and Go: a file permission written in decimal where octal was meant (chmod(p, 755), mkdir(d, 644), open(p, flags, 600), os.chmod/os.makedirs/os.open/Path.mkdir(mode=...), os.Chmod/os.Mkdir/os.MkdirAll/os.OpenFile/os.WriteFile/os.FileMode(...)); the same in PHP (chmod/mkdir/umask), JavaScript and TypeScript (fs.chmod/chmodSync, fs.mkdir/open with a numeric mode, and { mode: 755 } options to fs.mkdir/writeFile/open/createWriteStream) and Ruby (File.chmod/FileUtils.chmod, Dir.mkdir, File.open/new perm, mode:/perm: options to FileUtils.mkdir_p and File.write), which sets unrelated permission bits (755 is 0o1363). Not reported: the correct bound expressions, sizeof(buf) + N passed to an allocator, valid modes such as r+, rb, wbx and a+e, octal (0755, 0o755) or symbolic (S_IRUSR) permissions, comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-687/",
	"languages": ["c", "cpp", "python", "go", "php", "javascript", "typescript", "ruby"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [687],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["function-call-wrong-argument-specification", "cwe-687"],
}

_is_c(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_blank(s) := regex.replace(regex.replace(s, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_pre := `(?:^|[^\w.>])(?:std::)?`

_dmode := `([1-7][0-7]{2,3})`

# ── C and C++ ────────────────────────────────────────────────────────────

_c_bad(_, code) if {
	contains(code, "strncat")
	m := regex.find_all_string_submatch_n(concat("", [_pre, `strncat\s*\(\s*([\w.>\[\]-]+)\s*,[^,]+,\s*sizeof\s*(?:\(\s*([\w.>\[\]-]+)\s*\)|\s+([\w.>\[\]-]+))\s*\)`]), code, 1)
	count(m) > 0
	m[0][1] in {m[0][2], m[0][3]}
}

_c_bad(_, code) if {
	contains(code, "strlen")
	m := regex.find_all_string_submatch_n(concat("", [_pre, `(?:strncpy|strncat)\s*\(\s*[^,]+,\s*([^,]+?)\s*,\s*strlen\s*\(\s*([^()]+?)\s*\)\s*\)`]), code, 1)
	count(m) > 0
	m[0][1] == m[0][2]
}

_size_plus := `sizeof\s*\(?\s*([\w.>-]+)\s*\)?\s*\+\s*[1-9]`

_c_bad(_, code) if {
	contains(code, "sizeof")
	m := regex.find_all_string_submatch_n(concat("", [_pre, `(?:fgets|snprintf|vsnprintf|strncpy|strlcpy|strlcat|memset|memcpy|memmove|bzero|explicit_bzero|getcwd|gethostname)\s*\(\s*&?\s*([\w.>-]+)\s*,(?:[^;]*?,)?\s*`, _size_plus]), code, 1)
	count(m) > 0
	m[0][1] == m[0][2]
}

_c_bad(_, code) if {
	contains(code, "sizeof")
	m := regex.find_all_string_submatch_n(concat("", [_pre, `(?:read|recv|recvfrom|pread|readlink)\s*\(\s*[^,]+,\s*&?\s*([\w.>-]+)\s*,\s*`, _size_plus]), code, 1)
	count(m) > 0
	m[0][1] == m[0][2]
}

_c_bad(line, _) if {
	contains(line, "open")
	m := regex.find_all_string_submatch_n(concat("", [_pre, `(?:fopen|freopen|fdopen|_wfopen)\s*\([^;]*?,\s*L?"([^"]*)"`]), line, 1)
	count(m) > 0
	not regex.match(`^[rwa](?:\+|b|t|x|e|m|c|n|N)*(?:,\s*ccs=[\w-]+)?$`, m[0][1])
}

_c_bad(_, code) if {
	regex.match(concat("", [_pre, `(?:chmod|fchmod|lchmod|fchmodat|mkdir|mkdirat|mkfifo|creat|open|openat)\s*\([^;]*,\s*`, _dmode, `\s*\)`]), code)
}

# ── Python ───────────────────────────────────────────────────────────────

_py_bad(code) if {
	regex.match(concat("", [`\bos\.(?:chmod|lchmod|fchmod|mkdir|makedirs|open|mkfifo|mknod)\s*\(.*(?:,\s*|\bmode\s*=\s*)`, _dmode, `\s*[,)]`]), code)
}

_py_bad(code) if {
	regex.match(concat("", [`\.(?:chmod|lchmod)\s*\(\s*`, _dmode, `\s*\)`]), code)
}

_py_bad(code) if {
	regex.match(concat("", [`\.(?:mkdir|touch)\s*\(.*\bmode\s*=\s*`, _dmode, `\s*[,)]`]), code)
}

# ── Go ───────────────────────────────────────────────────────────────────

# The decimal must be the call's own last argument: the text before it has
# balanced parentheses. os.WriteFile(p, []byte(strings.Repeat("x", 5000)), 0o644)
# holds a 5000 that is Repeat's count, not a mode.
_go_bad(code) if {
	some m in regex.find_all_string_submatch_n(concat("", [`\b(?:os|ioutil)\.(?:Chmod|Lchmod|Mkdir|MkdirAll|OpenFile|WriteFile|MkdirTemp)\s*\((.*),\s*(?:os\.FileMode\s*\(\s*|fs\.FileMode\s*\(\s*)?`, _dmode, `\s*\)?\s*\)`]), code, -1)
	strings.count(m[1], "(") == strings.count(m[1], ")")
}

_go_bad(code) if {
	regex.match(concat("", [`\b(?:os|fs)\.FileMode\s*\(\s*`, _dmode, `\s*\)`]), code)
}

_go_bad(code) if {
	regex.match(concat("", [`\.Chmod\s*\(\s*`, _dmode, `\s*\)`]), code)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(`strncat|strncpy|sizeof|open|chmod|mkdir|mkfifo|creat`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`strn|sizeof|open|chmod|mkdir|mkfifo|creat`, line)
	not helpers.is_comment_line(line)
	_c_bad(line, _blank(line))
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`chmod|mkdir|makedirs|os\.open|mkfifo|mknod|touch`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`chmod|mkdir|makedirs|os\.open|mkfifo|mknod|touch`, line)
	not helpers.is_comment_line(line)
	_py_bad(_blank(line))
	finding := _finding(path, i, line)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`Chmod|Mkdir|OpenFile|WriteFile|FileMode`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`Chmod|Mkdir|OpenFile|WriteFile|FileMode`, line)
	not helpers.is_comment_line(line)
	_go_bad(_blank(line))
	finding := _finding(path, i, line)
}

# ── PHP, JavaScript/TypeScript, Ruby ─────────────────────────────────────

_php_bad(code) if {
	regex.match(concat("", [`(?:^|[^\w>:$])(?:chmod|lchmod|mkdir|umask)\s*\((?:[^;]*?,)?\s*`, _dmode, `\s*[,)]`]), code)
}

_js_bad(code) if {
	regex.match(concat("", [`\b(?:fs|fsp|fse|fsPromises|promises)\.(?:chmod|lchmod|fchmod)(?:Sync)?\s*\([^;]*?,\s*`, _dmode, `\s*[,)]`]), code)
}

_js_bad(code) if {
	regex.match(concat("", [`\b(?:fs|fsp|fse|fsPromises|promises)\.(?:mkdir|writeFile|appendFile|open|createWriteStream|mkdirp|ensureDir|outputFile|copyFile)(?:Sync)?\s*\([^;]*\bmode\s*:\s*`, _dmode, `\s*[,})]`]), code)
}

_js_bad(code) if {
	regex.match(concat("", [`\b(?:fs|fsp|fse|fsPromises|promises)\.(?:mkdir|open)(?:Sync)?\s*\([^;]*?,\s*(?:[^,;]*,\s*)?`, _dmode, `\s*[,)]`]), code)
}

_rb_bad(code) if {
	regex.match(concat("", [`\b(?:File|FileUtils)\.(?:chmod|lchmod|chmod_R)\s*\(?\s*`, _dmode, `\s*,`]), code)
}

_rb_bad(code) if {
	regex.match(concat("", [`\b(?:FileUtils\.(?:mkdir_p|mkdir|makedirs|mkpath|install)|File\.(?:open|new|write)|IO\.write)\s*\(?[^;]*?(?:\bmode:\s*|:mode\s*=>\s*|\bperm:\s*|:perm\s*=>\s*)`, _dmode, `\s*(?:[,)]|$)`]), code)
}

_rb_bad(code) if {
	regex.match(concat("", [`\bDir\.mkdir\s*\(?\s*(?:[^,;()]|\([^()]*\))+,\s*`, _dmode, `\s*(?:[,)]|$)`]), code)
}

_rb_bad(code) if {
	regex.match(concat("", [`\bFile\.(?:open|new)\s*\(?\s*(?:[^,;()]|\([^()]*\))+,\s*[^,;]+,\s*`, _dmode, `\s*(?:[,)]|$)`]), code)
}

_web_lang(path) := "php" if endswith(path, ".php")

_web_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"}
	endswith(path, ext)
}

_web_lang(path) := "rb" if {
	some ext in {".rb", ".rake"}
	endswith(path, ext)
}

_web_bad("php", code) if _php_bad(code)

_web_bad("js", code) if _js_bad(code)

_web_bad("rb", code) if _rb_bad(code)

# A permission-taking call or option and a three-digit decimal on one line.
_web_gate := `(?:chmod|mkdir|umask|mode|perm|open)[^;\n]{0,200}?[\s,(:][1-7][0-7]{2}\s*(?:[,)}]|$)`

findings contains finding if {
	some path, content in input.file_contents
	lang := _web_lang(path)
	regex.match(concat("", ["(?m)", _web_gate]), content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_web_gate, line)
	not helpers.is_comment_line(line)
	_web_bad(lang, _blank(line))
	finding := _finding(path, i, line)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Argument value is wrong for this function: a bound that does not limit the copy or exceeds the buffer, an invalid fopen mode, or a file permission written in decimal instead of octal (755 instead of 0755)",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
