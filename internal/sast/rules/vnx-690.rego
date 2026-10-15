# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_690

import rego.v1

metadata := {
	"id": "VNX-690",
	"name": "Unchecked return value to NULL pointer dereference",
	"description": "A C/C++ function that returns NULL on failure has its result dereferenced without a NULL test, so an allocation failure, a missing file or an unset environment variable crashes the program. Reported: (1) the result of malloc, calloc, realloc, strdup, strndup, fopen or getenv assigned to a variable (also a cast result, s->field targets and std:: forms) that, within the next six code lines and with no NULL test in between, is dereferenced (p->f, p[i], *p) or passed to a libc function that dereferences it (strcpy, memcpy, memset, strlen, strcmp, sprintf, fprintf, fgets, fread, atoi and similar); (2) getenv(...) passed straight to such a function or indexed (strcpy(buf, getenv(\"HOME\")), strlen(getenv(\"X\")), atoi(getenv(\"X\")), getenv(\"X\")[0]), and a std::string or std::string_view constructed or assigned from getenv(...) (undefined behaviour on NULL). Not reported: an allocation inside an if/while condition or checked on the same line, a test of the variable (== NULL, != NULL, !p, if (p), p &&, a ternary, assert, or an upper-case checking macro such as RETURN_IF_NULL(p)/CHECK_ALLOC(p)) before the use, wrapper allocators that abort on failure (xmalloc, zmalloc), a getenv result guarded by a ternary, string literals and comments. The value is not followed across functions or through further assignments. The two-line form overlaps VNX-476.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-690/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [690],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["unchecked-return-to-null", "null-dereference", "cwe-690"],
}

# `*p = 1;` is code: only `*` followed by space, `/` or the end of the line
# continues a block comment.
_is_comment(line) if startswith(trim_space(line), "//")

_is_comment(line) if startswith(trim_space(line), "/*")

_is_comment(line) if regex.match(`^\s*\*(?:\s|/|$)`, line)

_c_ext := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}

_is_c(path) if {
	some e in _c_ext
	endswith(path, e)
}

_gate := `\b(malloc|calloc|realloc|strn?dup|fopen|getenv)\s*\(`

_assign := `^\s*(?:[A-Za-z_][\w\s\*]*?[\s\*])?([A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*=\s*(?:\([^()]*\)\s*|(?:static|reinterpret)_cast\s*<[^>]*>\s*\(\s*)?(?:std::)?(?:malloc|calloc|realloc|strn?dup|fopen|getenv)\s*\(`

_libc := `(?:memcpy|memmove|memset|memcmp|strcpy|strncpy|strcat|strncat|strlen|strcmp|strncmp|strcasecmp|strchr|strrchr|strstr|strdup|sprintf|snprintf|vsprintf|sscanf|fgets|fputs|fprintf|fscanf|fread|fwrite|fclose|fseek|ftell|rewind|fgetc|getc|fputc|fflush|atoi|atol|atof|strtol|strtoul)`

# getenv(...) passed directly as an argument of a dereferencing libc call, or indexed.
_inline_getenv := concat("", [`\b`, _libc, `\s*\((?:[^;"()]*,)?\s*(?:std::)?getenv\s*\(\s*(?:"[^"]*"|[\w.]+)\s*\)\s*[,)]`])

_inline_index := `\bgetenv\s*\(\s*(?:"[^"]*"|[\w.]+)\s*\)\s*\[`

# Text of a line with string literals blanked, so code inside "..." is not seen.
_code(line) := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)

_esc(v) := regex.replace(v, `\.`, `\.`)

_use(line, ve) if regex.match(concat("", [`(?:^|[^\w.>])`, ve, `\s*(?:->|\[)`]), line)

_use(line, ve) if regex.match(concat("", [`(?:^\s*|[;(=,{]\s*|\breturn\s+)\*\s*`, ve, `\b`]), line)

_use(line, ve) if regex.match(concat("", [`\b`, _libc, `\s*\((?:[^;]*,)?\s*`, ve, `\s*[,)]`]), line)

_guard(line, ve) if regex.match(concat("", [`\b`, ve, `\s*(?:!=|==|&&|\|\||\?)`]), line)

_guard(line, ve) if regex.match(concat("", [`(?:!=|==|!|&&|\|\|)\s*`, ve, `\b`]), line)

_guard(line, ve) if regex.match(concat("", [`\b(?:if|while)\s*\(\s*`, ve, `\s*\)`]), line)

_guard(line, ve) if regex.match(concat("", [`(?i:assert)\w*\s*\(\s*`, ve, `\b`]), line)

# A project macro that tests its argument: RETURN_IF_NULL(p), CHECK_ALLOC(p), ENSURE_NOT_NULL(p).
_guard(line, ve) if regex.match(concat("", [`\b[A-Z][A-Z0-9_]*(?:NULL|CHECK|ASSERT|NOMEM|OOM|ALLOC|VERIFY|ENSURE|EXPECT)[A-Z0-9_]*\s*\(\s*`, ve, `\s*[,)]`]), line)

_first_use(lines, i, ve) := j if {
	idx := [k |
		some k in numbers.range(i + 1, min([count(lines) - 1, i + 10]))
		not _is_comment(lines[k])
		trim_space(lines[k]) != ""
	]
	code := array.slice(idx, 0, 6)
	uses := [k | some k in code; _use(_code(lines[k]), ve)]
	count(uses) > 0
	j := uses[0]
}

_guarded(lines, i, j, ve) if {
	some k in numbers.range(i + 1, j)
	not _is_comment(lines[k])
	_guard(_code(lines[k]), ve)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	regex.match(_gate, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_gate, line)
	not _is_comment(line)
	not regex.match(`\b(?:if|while)\s*\(|[!=]=|\?`, line)
	m := regex.find_all_string_submatch_n(_assign, line, 1)
	count(m) > 0
	ve := _esc(m[0][1])
	j := _first_use(lines, i, ve)
	not _guarded(lines, i, j, ve)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("The return value of a function that returns NULL on failure is stored in '%s' and dereferenced without a NULL check", [m[0][1]]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": lines[j],
	}
}

findings contains finding if {
	some path, content in input.file_contents
	_is_c(path)
	contains(content, "getenv")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "getenv")
	not _is_comment(line)
	code := _code(line)
	not contains(code, "?")
	_inline(code)
	finding := {
		"rule_id": metadata.id,
		"message": "getenv() returns NULL when the variable is unset, and its result is dereferenced here without a check",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_inline(code) if regex.match(_inline_getenv, code)

_inline(code) if regex.match(_inline_index, code)

# std::string s(getenv("X")) / std::string s = getenv("X"): constructing a
# std::string from a null pointer is undefined behaviour.
_inline(code) if regex.match(`\bstd::(?:string|string_view)\s*(?:[A-Za-z_]\w*\s*)?(?:\(|\{|=)\s*(?:std::)?getenv\s*\(\s*(?:"[^"]*"|[\w.]+)\s*\)\s*[)};]`, code)
