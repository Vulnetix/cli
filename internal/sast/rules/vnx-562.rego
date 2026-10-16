# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_562

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-562",
	"name": "Return of Stack Variable Address",
	"description": "A C or C++ function returns the address of storage that lives on its own stack frame, so the caller receives a dangling pointer or reference the moment the function returns. Reported: in a function whose return type is a pointer, `return buf;`, `return (buf);`, `return (char *)buf;`, `return buf + n;` or `return &buf[0];` where buf is a local array declared in the function; in a function returning std::string_view or std::span, `return s;` where s is a local std::string, std::vector or std::array; `return &x;` where x is a local variable or a by-value parameter; `return s.c_str();` or `return v.data();` where s/v is a local std::string, std::vector or other local object; and, in a function returning a reference, `return x;` where x is a local object. Inline class methods are bounded by their own header, and old-style (K&R) definitions with the return type on the line above are read. Not reported: static, extern and thread_local locals, heap pointers (malloc/new) returned by value, globals and class members, references and pointers declared with & or * and returned by value, pointer parameters and array parameters (char buf[]), &p->field and &p[i] on a pointer, functions returning std::string or another value type (the returned array or c_str() is copied), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-562/",
	"languages": ["c", "cpp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [562],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["return-stack-address", "dangling-pointer", "cwe-562"],
}

_c_file(path) if {
	some ext in {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".inl", ".ipp"}
	endswith(lower(path), ext)
}

# return v; / return (v); / return &v; / return &v[0]; / return v.c_str();
# An optional pointer cast, (const unsigned char *)buf, and an offset into a
# local array, buf + 2, are read too.
_ret_re := `^\s*return\s*\(?\s*(?:\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+|struct\s+)?[A-Za-z_][\w:]*\s*\*+\s*\)\s*)?(&)?\s*([A-Za-z_]\w*)\s*(\[\s*0\s*\]|\.\s*(?:c_str|data)\s*\(\s*\)|\+\s*[\w\s\*]+?)?\s*\)?\s*;`

# A column-0 line that can open a definition (not a label, brace, directive).
_col0 := `^[A-Za-z_]`

_label := `^[A-Za-z_]\w*\s*:\s*(?://.*|/\*.*)?$`

_method_hdr := `^\s+(?:[\w:<>\*&~,]+\s+)*[\*&]*\s*~?[A-Za-z_][\w:]*\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:final\s*)?\{?\s*$`

_control := `^\s*(?:if|for|while|switch|catch|else|do|return|case|sizeof)\b`

_heads(lines) := [k |
	some k, l in lines
	l != ""
	not startswith(l, " ")
	not startswith(l, "\t")
	regex.match(_col0, l)
	not regex.match(_label, l)
]

_fn_start(heads, i) := max(array.concat([0], [k | some k in heads; k <= i]))

# The nearest indented method header between the column-0 line and i.
_method_start(lines, fs, i) := max(ks) if {
	ks := [k |
		some k in helpers.span(fs + 1, i - 1)
		contains(lines[k], "(")
		regex.match(_method_hdr, lines[k])
		not regex.match(_control, lines[k])
	]
	count(ks) > 0
}

_start(lines, fs, i) := _method_start(lines, fs, i)

_start(lines, fs, i) := fs if not _method_start(lines, fs, i)

# The text of the declaration up to the function name: the header line, plus
# a type-only line above it (K&R style `static char *` / `name(args)`).
_ret_type(lines, s) := t if {
	s > 0
	regex.match(`^[A-Za-z_][\w\s\*&:<>,]*$`, lines[s - 1])
	not regex.match(`[;{}]\s*$`, lines[s - 1])
	t := concat(" ", [lines[s - 1], _before_paren(lines[s])])
} else := _before_paren(lines[s])

_before_paren(line) := substring(line, 0, indexof(line, "(")) if indexof(line, "(") > 0

else := line

_ptr_return(lines, s) if contains(_ret_type(lines, s), "*")

_ref_return(lines, s) if {
	t := _ret_type(lines, s)
	contains(t, "&")
	not contains(t, "*")
}

_no_storage := `\b(?:static|extern|thread_local|typedef)\b`

# A local array declaration of v.
_local_array(lines, s, i, v) if {
	some k in helpers.span(s + 1, i - 1)
	l := lines[k]
	contains(l, v)
	regex.match(concat("", [`^\s+[A-Za-z_][\w:<>\s\*,]*?[\s,\*]`, v, `\s*\[[^\]]*\]\s*(?:=|;|,|\[)`]), l)
	not regex.match(_no_storage, l)
	not regex.match(_control, l)
}

# A local (non-reference) variable or object declaration of v.
_local_var(lines, s, i, v, allow_ptr) if {
	some k in helpers.span(s + 1, i - 1)
	l := lines[k]
	contains(l, v)
	not helpers.is_comment_line(l)
	regex.match(concat("", [`^\s+(?:const\s+|volatile\s+|unsigned\s+|signed\s+|struct\s+|enum\s+|union\s+|class\s+)*[A-Za-z_][\w:]*(?:<[^;]*>)?(?:\s+|\s*\*+\s*)`, v, `\s*(?:=|;|,|\[|\{|\()`]), l)
	not regex.match(_no_storage, l)
	not regex.match(`^\s*(?:return|delete|throw|goto|case|else|co_return|using|namespace|template|friend|typename)\b`, l)
	_ptr_ok(l, v, allow_ptr)
}

_ptr_ok(_, _, true)

_ptr_ok(l, v, false) if not regex.match(concat("", [`\*\s*`, v, `\b`]), l)

# A by-value parameter of the function (header lines up to the body).
_value_param(lines, s, i, v) if {
	hdr := concat(" ", [lines[k] | some k in numbers.range(s, min([i, s + 4]))])
	params := substring(hdr, indexof(hdr, "("), -1)
	regex.match(concat("", [`[\(,]\s*(?:const\s+)?[A-Za-z_][\w:<>]*(?:\s+|\s*\*+\s*)`, v, `\s*[,\)]`]), params)
}

_dangling(lines, s, i, "", v, "") if {
	_ptr_return(lines, s)
	_local_array(lines, s, i, v)
}

_dangling(lines, s, i, "", v, "") if {
	_ref_return(lines, s)
	_local_var(lines, s, i, v, false)
	not _local_array(lines, s, i, v)
}

_dangling(lines, s, i, "&", v, suffix) if {
	suffix == ""
	_ptr_return(lines, s)
	_local_var(lines, s, i, v, true)
}

_dangling(lines, s, i, "&", v, suffix) if {
	suffix == ""
	_ptr_return(lines, s)
	not _local_var(lines, s, i, v, true)
	_value_param(lines, s, i, v)
}

_dangling(lines, s, i, "&", v, suffix) if {
	startswith(suffix, "[")
	_ptr_return(lines, s)
	_local_array(lines, s, i, v)
}

_dangling(lines, s, i, "", v, suffix) if {
	startswith(suffix, "+")
	_ptr_return(lines, s)
	_local_array(lines, s, i, v)
}

# A std::string_view or std::span returned from a local owning container.
_view_return(lines, s) if regex.match(`\b(?:w?string_view|u(?:8|16|32)string_view|span\s*<)`, _ret_type(lines, s))

_owner_decl(lines, s, i, v) if {
	some k in helpers.span(s + 1, i - 1)
	l := lines[k]
	contains(l, v)
	regex.match(concat("", [`^\s+(?:const\s+)?(?:std::)?(?:w?string|u(?:8|16|32)string|vector\s*<[^;]*>|array\s*<[^;]*>|basic_string\s*<[^;]*>)\s+`, v, `\s*(?:=|;|\{|\()`]), l)
	not regex.match(_no_storage, l)
}

_dangling(lines, s, i, "", v, "") if {
	_view_return(lines, s)
	_owner_decl(lines, s, i, v)
}

_dangling(lines, s, i, "", v, suffix) if {
	startswith(suffix, ".")
	_ptr_return(lines, s)
	_local_var(lines, s, i, v, false)
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	contains(content, "return")
	regex.match(concat("", ["(?m)", _ret_re]), content)
	lines := split(content, "\n")
	heads := _heads(lines)
	some i, line in lines
	contains(line, "return")
	m := regex.find_all_string_submatch_n(_ret_re, line, 1)
	count(m) > 0
	v := m[0][2]
	not v in {"this", "nullptr", "NULL", "true", "false", "errno"}
	fs := _fn_start(heads, i)
	i - fs <= 300
	s := _start(lines, fs, i)
	_dangling(lines, s, i, m[0][1], v, m[0][3])
	finding := {
		"rule_id": metadata.id,
		"message": "Returns the address of a local (stack) variable; the storage is released when the function returns, so the caller gets a dangling pointer. Return by value, use static or heap storage, or take a caller-supplied buffer",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
