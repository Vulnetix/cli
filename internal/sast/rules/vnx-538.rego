# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_538

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-538",
	"name": "Insertion of Sensitive Information into Externally-Accessible File or Directory",
	"description": "A secret is written into a file that other parties can read: a JavaScript/TypeScript fs.writeFile/writeFileSync/appendFile/appendFileSync/createWriteStream call, or a Python open(..., 'w'/'a'/'x').write(), Path(...).write_text()/write_bytes(), or a write/json.dump on the handle of a `with open(..., 'w') as fh:` block, whose target is a web-served directory (public/, static/, www/, htdocs/, wwwroot/, public_html/, /var/www/, or a STATIC_DIR/PUBLIC_DIR/publicDir-style name) or a fixed path under /tmp/, named on the call line or through a variable assigned from such a path up to ten lines above, and whose data names a password, secret, token, API key, private key or credential, or dumps the whole environment (process.env, os.environ). Anything in those directories is served to, or readable by, people who should never see it. Not reported: non-sensitive data written to public directories, secrets written to private paths (a home or config directory), reads, names that only contain the words (tokenizer, secretary), the pattern in comments or string literals, and test files. Whether a custom directory is web-served cannot be known and is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-538/",
	"languages": ["node", "python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [538],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["sensitive-info-file-dir", "cwe-538"],
}

_lang(path) := "js" if {
	some ext in {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
	endswith(path, ext)
	not endswith(path, ".min.js")
}

_lang(path) := "py" if endswith(path, ".py")

# A web-served directory or a fixed /tmp path, as a literal or a conventional name.
_public_re := `(?i)['"\x60/](public|static|www|htdocs|wwwroot|webroot|public_html)(/|['"\x60])|/var/www/|['"\x60]/tmp/|\b(STATIC|PUBLIC|WEB|WWW)_(DIR|ROOT|PATH|FOLDER)\b|\b(public|static|webRoot|webroot)(Dir|Path|Folder|Root)\b`

_public_needles := {"public", "static", "www", "htdocs", "wwwroot", "webroot", "/tmp/", "STATIC", "PUBLIC", "WEB_", "WWW", "Public", "Static"}

# The data names a secret: snake/plain spellings bounded by non-letters, or a
# camelCase suffix, or the whole environment.
_secret_re := `(?i)(^|[^a-z])(password|passwd|secret|api_?key|private_?key|access_?token|auth_?token|refresh_?token|token|credentials?)s?([^a-z]|$)|[a-z](Password|Passwd|Secret|Token|ApiKey|PrivateKey|Credentials?)\b|process\.env\b|os\.environ\b`

_write_js := `\b(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(`

_write_py_open := `\bopen\s*\(.*,\s*(mode\s*=\s*)?['"][wax]b?\+?['"]\s*[,)]`

# String literals blanked (f-strings and template literals are kept, so their
# interpolated names still count as data).
_code(line) := regex.replace(regex.replace(line, `(^|[^fFrRbB\w])"(\\.|[^"\\])*"`, `$1""`), `(^|[^fFrRbB\w])'(\\.|[^'\\])*'`, `$1''`)

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# The target is public on the line itself, or through a variable assigned from
# a public path in the ten lines above that the line uses.
_public_target(lines, i, line) if regex.match(_public_re, line)

_public_target(lines, i, line) if {
	start := max([0, i - 10])
	some j in numbers.range(start, i - 1)
	j >= 0
	prev := lines[j]
	not helpers.is_comment_line(prev)
	regex.match(_public_re, prev)
	v := helpers.assigned_ident(prev)
	regex.match(concat("", [`\b`, v, `\b`]), _code(line))
}

findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "js"
	_has_any(content, {"File", "WriteStream"})
	_has_any(content, _public_needles)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, {"File", "WriteStream"})
	not helpers.is_comment_line(line)
	regex.match(_write_js, _code(line))
	c := _code(_call_text(lines, i))
	regex.match(_secret_re, c)
	_public_target(lines, i, line)
	finding := _finding(path, i, line)
}

# Python: a write on the open() line itself, or Path(...).write_text().
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "py"
	contains(content, "write")
	_has_any(content, _public_needles)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "write")
	not helpers.is_comment_line(line)
	c := _code(line)
	_py_inline_write(line, c)
	regex.match(_secret_re, regex.replace(c, `^.*?\.(write|write_text|write_bytes)\s*\(`, ""))
	_public_target(lines, i, line)
	finding := _finding(path, i, line)
}

_py_inline_write(line, c) if {
	regex.match(_write_py_open, line)
	regex.match(`\)\s*\.write(lines)?\s*\(`, c)
}

_py_inline_write(_, c) if regex.match(`\)\s*\.(write_text|write_bytes)\s*\(`, c)

# Python: json.dump(secret, open(P, "w")) with the handle opened inline.
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "py"
	contains(content, ".dump")
	_has_any(content, _public_needles)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, ".dump")
	not helpers.is_comment_line(line)
	regex.match(_write_py_open, line)
	m := regex.find_all_string_submatch_n(`\b(?:json|yaml|pickle|toml|marshal)\.dump\s*\((.*?),\s*open\s*\(`, _code(line), 1)
	count(m) > 0
	regex.match(_secret_re, m[0][1])
	_public_target(lines, i, line)
	finding := _finding(path, i, line)
}

# The call text: the line and up to three continuation lines while its
# parentheses are open.
_call_text(lines, i) := t if {
	last := min([count(lines) - 1, i + 3])
	ends := [k |
		some k in numbers.range(i, last)
		seg := concat(" ", array.slice(lines, i, k + 1))
		strings.count(seg, "(") <= strings.count(seg, ")")
	]
	e := min(array.concat(ends, [last]))
	t := concat(" ", array.slice(lines, i, e + 1))
}

# Python: `with open(P, "w") as fh:` followed by fh.write(secret) / json.dump(secret, fh).
findings contains finding if {
	some path, content in input.file_contents
	_lang(path) == "py"
	contains(content, "open")
	_has_any(content, _public_needles)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "open")
	not helpers.is_comment_line(line)
	regex.match(`^\s*(async\s+)?with\s+`, line)
	regex.match(_write_py_open, line)
	m := regex.find_all_string_submatch_n(`\bas\s+([A-Za-z_]\w*)\s*[:,)]`, line, 1)
	count(m) > 0
	fh := m[0][1]
	_public_target(lines, i, line)
	some k in numbers.range(i + 1, min([count(lines) - 1, i + 6]))
	w := lines[k]
	not helpers.is_comment_line(w)
	c := _code(w)
	regex.match(concat("", [`\b`, fh, `\.write(lines)?\s*\(|\b(json|yaml|pickle|toml)\.dump\s*\(.*\b`, fh, `\b`]), c)
	_names_secret(w, c)
	finding := _finding(path, k, w)
}

_names_secret(_, c) if regex.match(_secret_re, c)

# A dict literal handed to json/yaml/toml.dump names its secret in a quoted key.
_names_secret(w, c) if {
	regex.match(`\b(json|yaml|toml)\.dump\s*\(`, c)
	regex.match(`(?i)['"][^'"]*(password|passwd|secret|api_?key|private_?key|token|credential)[^'"]*['"]\s*:`, w)
}

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "A secret (password, token, key, credential or the whole environment) is written into a web-served directory or a fixed /tmp path, where other users or the public can read it. Write secrets only to private locations with restrictive permissions, or do not persist them at all",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
