# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_822

import rego.v1


metadata := {
	"id": "VNX-822",
	"name": "Untrusted Pointer Dereference",
	"description": "A C/C++ pointer is built from data an attacker controls, so dereferencing it reads or writes an attacker-chosen address. Reported: (1) a cast to a pointer type (C-style, including function-pointer casts and (T *)(uintptr_t), or reinterpret_cast<T *>) applied directly to a text-to-integer conversion (strtoul, strtoull, strtol, strtoll, atoi, atol, atoll, std::stoul/stoull/stol/stoll/stoi); (2) the same cast, possibly through an integer cast ((T *)(uintptr_t)v) and including a dereferenced store (*(T *)v = x), applied to a variable assigned from such a conversion or filled by sscanf/fscanf/scanf (any conversion, such as %lx or SCNxPTR) in the ten lines above; (3) sscanf/fscanf/scanf reading a %p conversion; (4) a pointer read out of a buffer received from recv, recvfrom, read or fread in the 30 lines above through a pointer-to-pointer cast (*(T **)(buf + n)); (5) in a Linux ioctl handler (a function taking struct file * and unsigned long arg, the signature possibly spread over three lines), arg cast to a pointer type without __user, which dereferences a user-space address directly instead of copying it with copy_from_user. Not reported: integer conversions that stay integers, (void __user *)arg, an integer passed through a void * to pthread_create/thrd_create/g_idle_add-style callbacks, thread or callback arguments cast back to their context type, pointers to a validated table entry (&table[idx]), printf %p, and comments.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-822/",
	"languages": ["c", "cpp"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [822],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["untrusted-pointer", "cwe-822", "memory-safety"],
}

_exts := {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}

_c_file(path) if {
	some ext in _exts
	endswith(path, ext)
}

_conv := `(?:std::)?(?:strtoull|strtoul|strtoll|strtol|atoll|atol|atoi|stoull|stoul|stoll|stol|stoi)\s*\(`

# A cast to a pointer type: (T *), (T **), (const T *), (void (*)(...)),
# optionally followed by (uintptr_t)/(size_t)/(unsigned long), or
# reinterpret_cast<T *>(.
_ptr_cast := `(?:\(\s*(?:const\s+|volatile\s+|struct\s+|unsigned\s+)*[A-Za-z_][\w:]*\s*(?:\*\s*)+\)|\(\s*[A-Za-z_][\w:]*\s*\(\s*\*\s*\)\s*\([^()]*\)\s*\)|reinterpret_cast\s*<[^<>]*\*\s*>)\s*\(?\s*(?:\(\s*(?:uintptr_t|intptr_t|size_t|unsigned\s+long(?:\s+long)?|long(?:\s+long)?|std::uintptr_t)\s*\)\s*)?`

_msg := "Pointer built from attacker-controlled data: dereferencing it accesses an address the attacker chose. Look the object up by an index or handle you validate instead of accepting a raw address"

findings contains finding if {
	some f in _findings
	finding := {
		"rule_id": metadata.id,
		"message": _msg,
		"artifact_uri": f[0],
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": f[1] + 1,
		"snippet": f[2],
	}
}

# (1) cast applied directly to a conversion
_findings contains [path, i, line] if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(_conv, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_conv, line)
	not _is_comment(line)
	regex.match(concat("", [_ptr_cast, _conv]), line)
}

# (2) cast applied to a variable assigned from a conversion, or read by scanf
_findings contains [path, i, line] if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(concat("", [_conv, `|scanf\s*\(`]), content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "*")
	regex.match(`\*\s*\)|reinterpret_cast`, line)
	not _is_comment(line)
	m := regex.find_all_string_submatch_n(concat("", [_ptr_cast, `([A-Za-z_]\w*)\s*\)*\s*(?:[;,)]|=[^=])`]), _drop_int_casts(line), -1)
	some mm in m
	v := mm[1]
	_tainted_int(lines, i, v)
	not _thread_arg(lines, i)
}

_tainted_int(lines, i, v) if _from_conversion(lines, i, v)

_tainted_int(lines, i, v) if _from_scanf(lines, i, v)

# Integer casts between the pointer cast and the variable ((T *)(uintptr_t)v)
# removed, so the variable is what is captured.
_drop_int_casts(line) := regex.replace(line, `\(\s*(?:uintptr_t|intptr_t|std::uintptr_t|size_t|unsigned\s+long(?:\s+long)?|long(?:\s+long)?)\s*\)\s*`, "")

# The integer-in-a-pointer idiom for a thread or callback argument.
_thread_arg(lines, i) if regex.match(`\b(?:pthread_create|g_thread_new|g_thread_try_new|thrd_create|CreateThread|_beginthreadex?|g_idle_add|g_timeout_add|qsort_r|GINT_TO_POINTER|GUINT_TO_POINTER)\b`, concat(" ", array.slice(lines, max([0, i - 2]), i + 1)))

# The variable was filled by a scanf-family call in the ten lines above.
_from_scanf(lines, i, v) if {
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	contains(l, "scanf")
	not _is_comment(l)
	regex.match(`\b(?:sscanf|fscanf|scanf|vsscanf|vfscanf)\s*\(`, l)
	regex.match(concat("", [`&\s*`, v, `\b`]), l)
}

# (3) a %p conversion read from input
_findings contains [path, i, line] if {
	some path, content in input.file_contents
	_c_file(path)
	contains(content, "%p")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "%p")
	not _is_comment(line)
	regex.match(`\b(?:sscanf|fscanf|scanf|vsscanf|vfscanf)\s*\(\s*[^;]*"[^"]*%p`, line)
}

# (4) a pointer read out of received bytes
_findings contains [path, i, line] if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`\b(?:recv|recvfrom|read|fread)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "**")
	not _is_comment(line)
	m := regex.find_all_string_submatch_n(`\*\s*\(\s*(?:const\s+|struct\s+|unsigned\s+)*[A-Za-z_]\w*\s*\*\s*\*\s*\)\s*\(?\s*&?\s*([A-Za-z_]\w*)`, line, -1)
	some mm in m
	_received_into(lines, i, mm[1])
}

# (5) ioctl arg used as a kernel pointer
_findings contains [path, i, line] if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`struct\s+file\s*\*\s*\w*\s*,[^)]*unsigned\s+long\s+arg\s*\)`, content)
	lines := split(content, "\n")
	starts := [j | some j, l in lines; regex.match(`struct\s+file\s*\*`, l); regex.match(`struct\s+file\s*\*\s*\w*\s*,[^)]*unsigned\s+long\s+arg\s*\)`, concat(" ", array.slice(lines, j, j + 3)))]
	some i, line in lines
	contains(line, "arg")
	not _is_comment(line)
	not contains(line, "__user")
	regex.match(`\(\s*(?:const\s+)?(?:struct\s+)?[A-Za-z_]\w*\s*\*+\s*\)\s*arg\b`, line)
	some s in starts
	s < i
	i - s <= 60
	not _function_between(lines, s, i)
}

_from_conversion(lines, i, v) if {
	some j in numbers.range(max([0, i - 10]), i - 1)
	l := lines[j]
	regex.match(_conv, l)
	not _is_comment(l)
	m := regex.find_all_string_submatch_n(`^\s*(?:[\w:]+[\s*]+)*([A-Za-z_]\w*)\s*=[^=]`, l, 1)
	m[0][1] == v
}

_received_into(lines, i, buf) if {
	re := concat("", [`\b(?:recv|recvfrom|read)\s*\(\s*[^,]+,\s*&?\s*`, buf, `\b|\bfread\s*\(\s*&?\s*`, buf, `\b`])
	some j in numbers.range(max([0, i - 30]), i - 1)
	regex.match(re, lines[j])
}

# Another top-level function starts between the ioctl handler and line i.
_function_between(lines, s, i) if {
	some k in numbers.range(s + 1, i - 1)
	startswith(lines[k], "}")
}

# A comment-only line. Unlike helpers.is_comment_line, a line starting with a
# dereference (*(T *)p = v) is code: only "* ", "*/" and a lone "*" continue a
# block comment, as in the engine's own scope check.
_is_comment(line) if {
	t := trim_space(line)
	some p in ["//", "/*", "* ", "*/"]
	startswith(t, p)
}

_is_comment(line) if trim_space(line) == "*"
