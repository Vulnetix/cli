# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_476

import rego.v1



metadata := {
	"id": "VNX-476",
	"name": "NULL Pointer Dereference",
	"description": "Reports a value that can be NULL being dereferenced before anything checks it. C/C++: the result of malloc, calloc, realloc, strdup, strndup, fopen or getenv assigned to a variable and then, within the next six code lines and with no NULL test in between, dereferenced (p->f, p[i], *p) or passed to a libc function that dereferences it (memcpy, memset, strcpy, strlen, strcmp, sprintf, fgets, fprintf, fread, fclose, atoi and similar). Java: the result of request.getParameter/getHeader, System.getenv or one-argument System.getProperty dereferenced by a chained method call, or assigned to a variable whose method is called within the next six code lines with no null test, plus a for-each over File.listFiles(). Not reported: an allocation made inside an if/while condition or checked on the same line, a variable tested against NULL/null (==, !=, !p, p &&, assert, a ternary, Objects/StringUtils helpers) before the use, wrapper allocators (xmalloc, zmalloc) that never return NULL, a constant-first comparison (\"x\".equals(v)), getProperty with a default, the system properties the JVM always defines (os.name, user.home, user.dir, java.*, the separators), and comments. Deeper flows (a NULL returned from the project's own functions, fields, across functions) are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-476/",
	"languages": ["c", "cpp", "java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [476],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["null-dereference", "cwe-476"],
}

# A whole-line comment. Unlike helpers.is_comment_line, `*p = 1;` (a
# dereference statement) is code: only `*` followed by space, `/` or the end
# of the line continues a block comment.
_is_comment(line) if startswith(trim_space(line), "//")

_is_comment(line) if startswith(trim_space(line), "/*")

_is_comment(line) if regex.match(`^\s*\*(?:\s|/|$)`, line)

_c_ext := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}

_is_c(path) if {
	some e in _c_ext
	endswith(path, e)
}

_c_gate := `\b(malloc|calloc|realloc|strn?dup|fopen|getenv)\s*\(`

# `p = malloc(n);`, `char *p = (char *) malloc(n);`, `s->buf = strdup(x);`
_c_assign := `^\s*(?:[A-Za-z_][\w\s\*]*?[\s\*])?([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*=\s*(?:\([^()]*\)\s*|(?:static|reinterpret)_cast\s*<[^>]*>\s*\(\s*)?(?:std::)?(?:malloc|calloc|realloc|strn?dup|fopen|getenv)\s*\(`

_libc_deref := `(?:memcpy|memmove|memset|memcmp|strcpy|strncpy|strcat|strncat|strlen|strcmp|strncmp|strcasecmp|strchr|strrchr|strstr|sprintf|snprintf|vsprintf|sscanf|fgets|fputs|fprintf|fscanf|fread|fwrite|fclose|fseek|ftell|rewind|fgetc|getc|fputc|fflush|atoi|atol|atof|strtol|strtoul)`

_esc(v) := regex.replace(v, `\.`, `\.`)

_c_use(line, ve) if regex.match(concat("", [`(?:^|[^\w.>])`, ve, `\s*(?:->|\[)`]), line)

_c_use(line, ve) if regex.match(concat("", [`(?:^\s*|[;(=,{]\s*|\breturn\s+)\*\s*`, ve, `\b`]), line)

_c_use(line, ve) if regex.match(concat("", [`\b`, _libc_deref, `\s*\((?:[^;]*,)?\s*`, ve, `\s*[,)]`]), line)

_c_guard(line, ve) if regex.match(concat("", [`\b`, ve, `\s*(?:!=|==|&&|\|\||\?)`]), line)

_c_guard(line, ve) if regex.match(concat("", [`(?:!=|==|!|&&|\|\|)\s*`, ve, `\b`]), line)

_c_guard(line, ve) if regex.match(concat("", [`\b(?:if|while)\s*\(\s*`, ve, `\s*\)`]), line)

_c_guard(line, ve) if regex.match(concat("", [`(?i:assert)\w*\s*\(\s*`, ve, `\b`]), line)

# A checking macro or helper given the pointer: RETURN_IF_NULL(p), CHECK_ALLOC(p).
_c_guard(line, ve) if regex.match(concat("", [`\b\w*(?i:null|check|alloc|ensure|guard|valid|oom)\w*\s*\(\s*`, ve, `\s*[,)]`]), line)

# Reassigned before the use: the value dereferenced is no longer the result.
_c_guard(line, ve) if regex.match(concat("", [`^\s*`, ve, `\s*=[^=]`]), line)

_window_end(lines, i) := min([count(lines) - 1, i + 10])

# The first line after i, within six code lines, that dereferences ve.
_first_use(lines, i, ve, kind) := j if {
	idx := [k |
		some k in numbers.range(i + 1, _window_end(lines, i))
		not _is_comment(lines[k])
		trim_space(lines[k]) != ""
	]
	code := array.slice(idx, 0, 6)
	uses := [k | some k in code; _use(kind, lines[k], ve)]
	count(uses) > 0
	j := uses[0]
}

_use("c", line, ve) if _c_use(line, ve)

_use("java", line, ve) if _j_use(line, ve)

_guarded(lines, i, j, ve, kind) if {
	some k in numbers.range(i + 1, j)
	not _is_comment(lines[k])
	_guard(kind, lines[k], ve)
}

_guard("c", line, ve) if _c_guard(line, ve)

_guard("java", line, ve) if _j_guard(line, ve)

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(_c_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_c_gate, line)
	not _is_comment(line)
	not regex.match(`\b(?:if|while)\s*\(|[!=]=|\?`, line)
	m := regex.find_all_string_submatch_n(_c_assign, line, 1)
	count(m) > 0
	ve := _esc(m[0][1])
	j := _first_use(lines, i, ve, "c")
	not _guarded(lines, i, j, ve, "c")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' can be NULL here (allocation, fopen or getenv result) and is dereferenced without a NULL check", [m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}

# ── Java ────────────────────────────────────────────────────────────────

_j_gate := `\b(getParameter|getHeader|getenv|getProperty|listFiles)\s*\(`

_j_src := `(?:\b(?:getParameter|getHeader)|\bSystem\.(?:getenv|getProperty))\(\s*(?:"[^"]*"|[\w.]+)\s*\)`

_j_chain := concat("", [_j_src, `\s*\.\s*\w+\s*\(`])

_j_assign := concat("", [`^\s*(?:final\s+)?(?:[\w.<>\[\]]+\s+)?([A-Za-z_]\w*)\s*=\s*[\w.]*?`, _j_src, `\s*;`])

_j_use(line, ve) if regex.match(concat("", [`(?:^|[^\w."])`, ve, `\s*\.\s*\w+\s*\(`]), line)

_j_guard(line, ve) if regex.match(concat("", [`\b`, ve, `\s*[!=]=\s*null\b|\bnull\s*[!=]=\s*`, ve, `\b`]), line)

_j_guard(line, ve) if regex.match(concat("", [`\b(?:Objects\.\w+|Optional\.ofNullable|is(?:Not)?(?:Empty|Blank)|hasText|hasLength|requireNonNull\w*|(?:\w+\.)?(?i:assert)\w*|notNull)\s*\(\s*`, ve, `\b`]), line)

# Reassigned (sort = StringUtils.defaultString(sort, "name")) before the use.
_j_guard(line, ve) if regex.match(concat("", [`^\s*`, ve, `\s*=[^=]`]), line)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(_j_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_j_gate, line)
	not _is_comment(line)
	_j_direct(line)
	finding := {
		"rule_id": metadata.id,
		"message": "A value that is null when the parameter, header, variable or directory is absent is dereferenced without a null check",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# Properties the JVM always defines (os.name, user.home, java.io.tmpdir, the
# separators...) are never null, so they are blanked before matching.
_j_std_prop := `\bSystem\.getProperty\(\s*"(?:java\.[\w.]+|os\.(?:name|arch|version)|(?:file|path|line)\.separator|user\.(?:name|home|dir))"\s*\)`

_jl(line) := regex.replace(line, _j_std_prop, "STD_PROPERTY")

_j_direct(line) if regex.match(_j_chain, _jl(line))

_j_direct(line) if regex.match(`\bfor\s*\([^:;]+:\s*[\w.()]*\.listFiles\(\s*[^)]*\)\s*\)`, line)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	regex.match(_j_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_j_gate, line)
	not _is_comment(line)
	m := regex.find_all_string_submatch_n(_j_assign, _jl(line), 1)
	count(m) > 0
	ve := m[0][1]
	j := _first_use(lines, i, ve, "java")
	not _guarded(lines, i, j, ve, "java")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'%s' is null when the parameter, header or variable is absent and is dereferenced without a null check", [ve]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}
