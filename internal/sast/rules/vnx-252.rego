# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_252

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-252",
	"name": "Unchecked Return Value",
	"description": "The result of a call that reports failure only through its return value is dropped. In Go: a bare statement recv.Write(...), recv.Read(...) or recv.WriteString(...), or a bare io.Copy/io.CopyN/io.CopyBuffer/io.WriteString/io.ReadFull/io.ReadAtLeast/os.WriteFile/ioutil.WriteFile call, which silently discards the error (and the byte count). In C and C++: the result of malloc/calloc/realloc/strdup/strndup/fopen/fdopen/tmpfile assigned to a variable that none of the next six code lines tests (== NULL, != NULL, !p, if (p), assert(p), serverAssert(p)), so a failed allocation or open is dereferenced; and a bare setuid/setgid/seteuid/setegid/setreuid/setregid/setresuid/setresgid/setgroups/initgroups/chroot statement, where a failed privilege drop leaves the process running privileged. Not reported in Go: an explicit discard (_ = f.Close(), _, _ = w.Write(b)), a deferred call, a returned or assigned result, writes to in-memory writers that cannot fail (bytes.Buffer, strings.Builder, bufio.Writer, hashes and HMACs, tabwriter) and to an http.ResponseWriter (w, rw, resp, res, writer), and test files. Not reported in C: a test on the same line, a pointer handed straight back to the caller by the next statement (return p;), an abort-on-failure wrapper (xmalloc, zmalloc, g_malloc), a (void) cast, comments and strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-252/",
	"languages": ["c", "cpp", "go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [252],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["error-handling", "unchecked", "cwe-252"],
}

# ── Go ──────────────────────────────────────────────────────────────────

# A bare statement: `recv.Write(...)` and nothing else on the line, so the
# results are neither assigned, tested, deferred nor returned.
_bare_call := `^\s*([A-Za-z_][\w\.]*)\.(Write|Read|WriteString)\(.*\)\s*$`

_bare_pkg_call := `^\s*(io\.(?:Copy|CopyN|CopyBuffer|WriteString|ReadFull|ReadAtLeast)|os\.WriteFile|ioutil\.WriteFile)\(\s*([A-Za-z_][\w\.]*)?.*\)\s*$`

# Receivers whose Write cannot fail: in-memory buffers and hashes. The file
# declares the receiver as one of them.
_infallible_decl := `(bytes\.Buffer|bytes\.NewBuffer|strings\.Builder|bufio\.NewWriter|bufio\.Writer|hmac\.New|sha1\.New|sha256\.New|sha3\.New\w*|blake2[bs]\.New\w*|sha512\.New|md5\.New|fnv\.New|crc32\.New|crc64\.New|adler32\.New|hash\.Hash|tabwriter\.NewWriter|\.Builder\b)`

_infallible(content, recv) if {
	name := regex.replace(recv, `^.*\.`, "")
	regex.match(concat("", [`\b`, name, `\b[^\n]*(:=|=|\s)[^\n]*`, _infallible_decl]), content)
}

# A receiver whose Sum is taken is a hash.Hash, however it was constructed.
_infallible(content, recv) if {
	name := regex.replace(recv, `^.*\.`, "")
	regex.match(concat("", [`\b`, name, `\.Sum(?:32|64)?\(`]), content)
}

# `w.Write` where w is the standard library's response writer: the client has
# gone, and there is nothing to do about it.
_response_writer(recv) if regex.match(`^(w|rw|resp|res|rec|recorder|writer)$`, recv)

# The previous code line leaves an expression open: this line continues it.
_continuation(lines, i) if {
	i > 0
	prev := trim_space(lines[i - 1])
	regex.match(`(,|\(|=|&&|\|\||\+)$`, prev)
}

_go_bare(line, content) := method if {
	m := regex.find_all_string_submatch_n(_bare_call, line, 1)
	count(m) > 0
	recv := m[0][1]
	method := m[0][2]
	not regex.match(`^(io|os|ioutil)$`, recv)
	not _infallible(content, recv)
	not _response_writer(recv)
}

_go_bare(line, content) := fn if {
	m := regex.find_all_string_submatch_n(_bare_pkg_call, line, 1)
	count(m) > 0
	fn := m[0][1]
	dst := m[0][2]
	not _response_writer(dst)
	not _pkg_infallible(fn, dst, content)
}

_pkg_infallible(fn, dst, content) if {
	startswith(fn, "io.")
	dst != ""
	_infallible(content, dst)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	not helpers.is_test_path(path)
	regex.match(`(?m)^\s*(?:[A-Za-z_][\w\.]*\.(?:Write|Read|WriteString)|io\.\w+|os\.WriteFile|ioutil\.WriteFile)\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	method := _go_bare(line, content)
	not _continuation(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Error returned by %s() is discarded; check it (or discard it explicitly with _ =)", [method]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── C / C++ ─────────────────────────────────────────────────────────────

_c_file(path) if regex.match(`\.(c|cc|cpp|cxx)$`, path)

# `type *p = malloc(n);` or `p = (char *)malloc(n);` as a statement.
_alloc_re := `^\s*(?:(?:const\s+|struct\s+|unsigned\s+)*[A-Za-z_]\w*\s*\*+\s*)?([A-Za-z_][\w\.\->\[\]]*)\s*=\s*(?:\([^()]*\)\s*)?(?:std::)?(malloc|calloc|realloc|strdup|strndup|fopen|fdopen|tmpfile)\s*\(`

_tested(text, var) if {
	v := regex.replace(var, `([\.\[\]\-\>])`, `\$1`)
	regex.match(concat("", [
		`(\b`, v, `\s*[!=]=\s*(NULL|nullptr|0)\b|\b(NULL|nullptr)\s*[!=]=\s*`, v, `\b|!\s*`, v, `\b|\b(?:if|while)\s*\(\s*`, v, `\s*(\)|&&|\|\|)|&&\s*`, v, `\s*\)|\w*(?:assert|Assert|ASSERT)\w*\s*\(\s*`, v, `|unlikely\s*\(\s*!?\s*`, v, `)`,
	]), text)
}

# The very next statement returns the pointer untouched: the caller owns the
# NULL check (a strdup/malloc wrapper).
_handed_back(next, var) if regex.match(concat("", [`^\s*return\s*\(?\s*`, regex.replace(var, `([\.\[\]\-\>])`, `\$1`), `\s*\)?\s*;`]), next)

_next_code(lines, i, n) := txt if {
	end := min([count(lines) - 1, i + 12])
	kept := [l |
		some k in numbers.range(i + 1, end)
		trim_space(lines[k]) != ""
		not helpers.is_comment_line(lines[k])
		l := lines[k]
	]
	txt := concat("\n", array.slice(kept, 0, n))
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	not helpers.is_test_path(path)
	regex.match(`(malloc|calloc|realloc|strdup|strndup|fopen|fdopen|tmpfile)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_alloc_re, line, 1)
	count(m) > 0
	var := m[0][1]
	fn := m[0][2]
	not regex.match(`\bif\s*\(|\?|assert`, line)
	not _tested(_next_code(lines, i, 6), var)
	not _handed_back(_next_code(lines, i, 1), var)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s() result is used without a NULL check; test it before dereferencing", [fn]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_priv_re := `^\s*(?:::)?(setuid|setgid|seteuid|setegid|setreuid|setregid|setresuid|setresgid|setgroups|initgroups|chroot)\s*\(.*\)\s*;\s*(?://.*|/\*.*)?$`

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	not helpers.is_test_path(path)
	regex.match(`(?m)^\s*(?:::)?(setuid|setgid|seteuid|setegid|setreuid|setregid|setresuid|setresgid|setgroups|initgroups|chroot)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(_priv_re, line, 1)
	count(m) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s() result is not checked; if the privilege change fails the process keeps running with its old privileges", [m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
