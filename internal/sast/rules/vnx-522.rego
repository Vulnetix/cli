# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_522

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-522",
	"name": "Insufficiently Protected Credentials: credential file readable by other users",
	"description": "A credential (password, API key, access/refresh/session token, private key, a credentials, token, secret, .netrc or .pgpass file) is written to a file that other local users can read. Reported: Go os.WriteFile/ioutil.WriteFile/os.OpenFile with a mode that grants group or other read (0644, 0o664, 0755, os.ModePerm), including calls broken across lines, and os.Create (0666 before the umask) of a credential path in a file that never Chmods it owner-only; Python os.open(..., 0o644) and os.chmod(..., 0o644) on such a path, pathlib write_text/write_bytes of a credential or to a credential path, and open(path, 'w'/'a'/'x') of a credential path, or of a path that is then written a credential, in a file that never restricts the mode (no 0o600/0o400, S_IRUSR/S_IWUSR, os.umask or os.fchmod); JavaScript/TypeScript fs.writeFile/writeFileSync/fs.promises.writeFile of a credential with no mode option or a group/other-readable one, in a file that does not chmod it to 0o600; Java Files.write/writeString, FileWriter, FileOutputStream or PrintWriter on a credential path in a file that sets no owner-only POSIX permissions. The path or the written value must name the credential. Not reported: owner-only modes (0600, 0o400, 384), files that are not credentials (reports, logs, tokenizer vocabularies), reads, messages that merely mention a password, comments and test code. Whether the directory around the file is itself private, and credentials stored by other means (cookies, databases, recoverable encodings: VNX-256, VNX-257, VNX-261), are not judged here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-522/",
	"languages": ["go", "java", "node", "python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [522],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["credentials-protection", "file-permissions", "cwe-522"],
}

# A name or path that says it holds a credential. `token` alone counts only as
# a whole word (token, token_file, "token"), not tokens/tokenizer.
_cred := `(?i)(credential|passw(?:or)?d|\bpwd\b|passphrase|secret|(?:access|auth|api|bearer|refresh|session|id)[_-]?token|(?:^|[^a-z])token(?:[^a-z]|$)|api[_-]?key|private[_-]?key|netrc|pgpass|(?:^|[^a-z])key_?(?:file|path)\b|\.pem\b|\bid_(?:rsa|ed25519|ecdsa)\b)`

_blank(s) := regex.replace(regex.replace(s, `"(?:\\.|[^"\\])*"`, `""`), `'(?:\\.|[^'\\])*'`, `''`)

# A literal mode that lets group or other read.
_readable_mode(txt) if {
	some m in regex.find_all_string_submatch_n(`\b0o?([0-7]?)([0-7])([0-7])([0-7])\b`, txt, -1)
	some d in [m[3], m[4]]
	d in {"4", "5", "6", "7"}
}

_readable_mode(txt) if contains(txt, "os.ModePerm")

_message := "A credential is written to a file other local users can read. Create credential files owner-only (mode 0600) and keep their directory private"

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": _message,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# ── Go ───────────────────────────────────────────────────────────────────

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".go")
	regex.match(`WriteFile\(|OpenFile\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\b(?:os|ioutil)\.(?:WriteFile|OpenFile)\(`, line)
	not helpers.is_comment_line(line)
	txt := _js_call(lines, i)
	call := regex.find_n(`\b(?:os|ioutil)\.(?:WriteFile|OpenFile)\([^;{]*`, txt, 1)[0]
	regex.match(_cred, call)
	_readable_mode(call)
	f := _finding(path, i, line)
}

# os.Create makes the file 0666 before the umask (0644 in practice). Reported
# when the path names a credential, directly or through a variable assigned
# from such an expression, and the file never Chmods anything owner-only.
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "os.Create(")
	not helpers.is_test_path(path)
	not regex.match(`Chmod\([^)]*0o?[67]00\b|syscall\.Umask\(|unix\.Umask\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "os.Create(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\bos\.Create\((.*)\)`, line, 1)
	count(m) > 0
	_go_cred_path(lines, i, m[0][1])
	f := _finding(path, i, line)
}

_go_cred_path(_, _, arg) if regex.match(_cred, arg)

_go_cred_path(lines, i, arg) if {
	v := trim_space(arg)
	regex.match(`^[A-Za-z_]\w*$`, v)
	some j in numbers.range(max([0, i - 10]), i - 1)
	regex.match(concat("", [`^\s*`, v, `\s*:?=[^=]`]), lines[j])
	regex.match(_cred, lines[j])
}

# ── Python ───────────────────────────────────────────────────────────────

_py_restricted(content) if regex.match(`0o?[67]00\b|S_IRUSR|S_IWUSR|os\.umask\(|os\.fchmod\(`, content)

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`os\.(?:open|chmod)\(`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\bos\.(?:open|chmod)\(`, line)
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`\bos\.(?:open|chmod)\(\s*([^,]+),(.*)`, line, 1)
	count(m) > 0
	_py_cred_path(lines, i, m[0][1])
	_readable_mode(m[0][2])
	f := _finding(path, i, line)
}

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "open(")
	not helpers.is_test_path(path)
	not _py_restricted(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "open(")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`(?:^|[^\w.])open\(\s*([^,()]+(?:\([^()]*\))?[^,()]*),\s*(?:mode\s*=\s*)?["']([rwxab+t]+)["']`, line, 1)
	count(m) > 0
	regex.match(`[wax]`, m[0][2])
	_py_cred_target(lines, i, m[0][1])
	f := _finding(path, i, line)
}

# pathlib: <path>.write_text(...)/write_bytes(...) where the path or the
# written value names a credential, in a file that never restricts the mode.
findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`\.write_(?:text|bytes)\(`, content)
	not helpers.is_test_path(path)
	not _py_restricted(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".write_")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`^(.*?)\.write_(?:text|bytes)\((.*)$`, line, 1)
	count(m) > 0
	_py_pathlib_cred(lines, i, m[0][1], m[0][2])
	f := _finding(path, i, line)
}

_py_pathlib_cred(_, _, _, arg) if regex.match(_cred, _blank(arg))

_py_pathlib_cred(lines, i, recv, _) if {
	r := trim_space(recv)
	regex.match(`^[A-Za-z_]\w*$`, r)
	_py_cred_path(lines, i, r)
}

_py_pathlib_cred(_, _, recv, _) if {
	not regex.match(`^\s*[A-Za-z_]\w*\s*$`, recv)
	regex.match(_cred, recv)
}

# The path names a credential, directly or through a variable assigned from
# such an expression in the ten lines above.
_py_cred_path(_, _, arg) if regex.match(_cred, arg)

_py_cred_path(lines, i, arg) if {
	v := trim_space(arg)
	regex.match(`^[A-Za-z_]\w*$`, v)
	some j in numbers.range(max([0, i - 10]), i - 1)
	regex.match(concat("", [`^\s*`, v, `\s*=[^=]`]), lines[j])
	regex.match(_cred, lines[j])
}

_py_cred_target(lines, i, arg) if _py_cred_path(lines, i, arg)

# ... or what is written to it, in the three lines below, is a credential.
_py_cred_target(lines, i, _) if {
	some j in numbers.range(i + 1, min([count(lines) - 1, i + 3]))
	regex.match(`\.write\(|json\.dump\(|yaml\.(?:safe_)?dump\(|toml\.dump\(`, lines[j])
	regex.match(_cred, _blank(lines[j]))
}

# ── JavaScript / TypeScript ──────────────────────────────────────────────

_js_exts := {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

_js_restricted(content) if regex.match(`chmod(?:Sync)?\([^)]*(?:0o?[67]00|\b384\b|\b256\b)`, content)

findings contains f if {
	some path, content in input.file_contents
	some ext in _js_exts
	endswith(path, ext)
	not endswith(path, ".min.js")
	contains(content, "writeFile")
	not helpers.is_test_path(path)
	not _js_restricted(content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "writeFile")
	not helpers.is_comment_line(line)
	regex.match(`(?:^|[^\w])writeFile(?:Sync)?\(`, line)
	txt := _js_call(lines, i)
	regex.match(_cred, txt)
	not _js_owner_only(txt)
	f := _finding(path, i, line)
}

# The call up to its closing `);` (at most four lines).
_js_call(lines, i) := txt if {
	ends := [j |
		some j in numbers.range(i, min([count(lines) - 1, i + 4]))
		regex.match(`\)\s*;?\s*(//.*)?$`, lines[j])
	]
	end := min(array.concat([min([count(lines) - 1, i + 4])], ends))
	txt := concat(" ", [lines[j] | some j in numbers.range(i, end)])
}

_js_owner_only(txt) if {
	m := regex.find_all_string_submatch_n(`\bmode\s*:\s*['"]?(0o?[0-7]+|\d+)['"]?`, txt, 1)
	count(m) > 0
	not _js_mode_readable(m[0][1])
}

_js_mode_readable(v) if {
	regex.match(`^0`, v)
	_readable_mode(v)
}

_js_mode_readable(v) if {
	regex.match(`^[1-9]\d*$`, v)
	bits.and(to_number(v), 36) != 0 # 0o044
}

# ── Java ─────────────────────────────────────────────────────────────────

_java_restricted(content) if regex.match(`PosixFilePermissions|OWNER_READ|setReadable\(\s*false|"rw-------"|"r--------"`, content)

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(`Files\.write|new (?:FileWriter|FileOutputStream|PrintWriter)\(`, content)
	not helpers.is_test_path(path)
	not _java_restricted(content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`(?:\bFiles\.write(?:String)?|\bnew (?:FileWriter|FileOutputStream|PrintWriter))\(\s*([^,;]+?)\s*[,)]`, line, 1)
	count(m) > 0
	regex.match(_cred, m[0][1])
	f := _finding(path, i, line)
}
