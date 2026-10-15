# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_663

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-663",
	"name": "Use of a Non-reentrant Function in a Concurrent Context",
	"description": "State that is not safe for concurrent use is shared between threads (CWE-663). Java: a static field whose type is a mutable, non-thread-safe formatter or engine, SimpleDateFormat, DateFormat, DecimalFormat, NumberFormat, MessageFormat, ChoiceFormat, MessageDigest, Mac, Cipher, Signature or java.util.regex.Matcher, which every thread then shares (concurrent format/parse/digest calls corrupt each other's internal buffers and return wrong results). C/C++: a call to a libc function that returns a pointer to static storage, strtok, localtime, gmtime, ctime, asctime, getpwnam, getpwuid, getgrnam, getgrgid, gethostbyname, gethostbyaddr, getservbyname, getlogin, ttyname, strsignal, ecvt, fcvt, crypt or inet_ntoa (also as std::), in a file that starts threads (pthread_create, std::thread/jthread, std::async, CreateThread, _beginthreadex, #pragma omp). Not reported: ThreadLocal holders, the thread-safe java.time DateTimeFormatter and Pattern, local or instance formatters, a static formatter the same file locks with synchronized (NAME) or uses only inside synchronized methods, the _r variants (strtok_r, localtime_r), member calls and lookalike names, declarations and members that share a libc name (struct tm *localtime(...); obj->localtime()), files that start no threads (a thread marker in a comment or string does not count), comments and string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-663/",
	"languages": ["java", "c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [663],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["concurrency", "thread-safety", "reentrancy", "cwe-663"],
}

_strip(line) := regex.replace(line, "\"(?:[^\"\\\\]|\\\\.)*\"", `""`)

# ── Java: static non-thread-safe field ──────────────────────────────────

_java_types := `SimpleDateFormat|DateFormat|DecimalFormat|NumberFormat|MessageFormat|ChoiceFormat|MessageDigest|Mac|Cipher|Signature|Matcher`

_java_decl := concat("", [
	`^\s*(?:(?:private|public|protected|final|transient|volatile)\s+)*static\s+(?:(?:final|transient|volatile)\s+)*`,
	`(?:java\.(?:text|security|util\.regex)\.|javax\.crypto\.)?(?:`, _java_types, `)`,
	`(?:\s+([A-Za-z_]\w*))?\s*(?:[=;]|$)`,
])

_java_type_re := concat("", [`\b(?:`, _java_types, `)\b`])

_field_name(lines, i, m) := m[0][1] if m[0][1] != ""

_field_name(lines, i, m) := n if {
	m[0][1] == ""
	i + 1 < count(lines)
	nm := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*[=;]`, lines[i + 1], 1)
	count(nm) > 0
	n := nm[0][1]
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	contains(content, "static")
	regex.match(_java_type_re, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "static")
	regex.match(_java_type_re, line)
	m := regex.find_all_string_submatch_n(_java_decl, line, 1)
	count(m) > 0
	name := _field_name(lines, i, m)
	not regex.match(concat("", [`synchronized\s*\(\s*(?:\w+\.)?`, name, `\s*\)`]), content)
	not _sync_only(lines, name, i)
	finding := _finding(path, i, line, "Static field of a type that is not thread-safe (SimpleDateFormat, DecimalFormat, MessageDigest, Cipher, Mac, Matcher...) is shared by every thread. Use java.time DateTimeFormatter, a ThreadLocal, or a new instance per call")
}

# Every use of the field is inside a synchronized method: the class
# serialises access itself.
_method_sig := `^\s*(?:(?:public|private|protected|static|final|synchronized)\s+)+[\w<>\[\],.?\s]*\b[A-Za-z_]\w*\s*\([^;]*$`

_sync_only(lines, name, decl) if {
	pat := concat("", [`\b`, name, `\s*\.`])
	uses := [k | some k, l in lines; k != decl; regex.match(pat, l); not helpers.is_comment_line(l)]
	count(uses) > 0
	every k in uses {
		_in_sync_method(lines, k)
	}
}

_in_sync_method(lines, k) if {
	starts := [m | some m in numbers.range(max([0, k - 30]), k); regex.match(_method_sig, lines[m])]
	count(starts) > 0
	contains(lines[max(starts)], "synchronized")
}

# ── C/C++: static-buffer libc function in a threaded file ────────────────

_c_ext := {".c", ".cc", ".cpp", ".cxx", ".c++"}

_thread_markers := ["pthread_create", "std::thread", "std::jthread", "<thread>", "std::async", "CreateThread(", "_beginthreadex", "pragma omp"]

_c_names := ["strtok(", "localtime(", "gmtime(", "ctime(", "asctime(", "getpwnam(", "getpwuid(", "getgrnam(", "getgrgid(", "gethostbyname(", "gethostbyaddr(", "getservbyname(", "getlogin(", "ttyname(", "strsignal(", "ecvt(", "fcvt(", "crypt(", "inet_ntoa("]

_threaded(content) if {
	some t in _thread_markers
	contains(content, t)
}

# A thread is started in code, not only named in a comment or a string.
_threads_in_code(lines) if {
	some l in lines
	_threaded(l)
	not regex.match(`^\s*(?://|/\*|\*)`, l)
	code := regex.replace(regex.replace(_strip(l), `/\*.*?(?:\*/|$)`, ""), `//.*$`, "")
	_threaded(code)
}

_c_fn := `(?:strtok|localtime|gmtime|ctime|asctime|getpwnam|getpwuid|getgrnam|getgrgid|gethostbyname|gethostbyaddr|getservbyname|getlogin|ttyname|strsignal|ecvt|fcvt|crypt|inet_ntoa)`

_names_any(content) if regex.match(concat("", [`\b`, _c_fn, `\s*\(`]), content)

# A declaration of a function or member that happens to share the name.
_c_decl := concat("", [`^\s*(?:(?:static|extern|inline|const|struct|unsigned|signed|virtual)\s+)*[A-Za-z_][\w:<>]*[\s*&]+`, _c_fn, `\s*\(`])

_c_call := `(?:^|[^\w.>:]|std::|(?:^|[^\w:])::)(?:strtok|localtime|gmtime|ctime|asctime|getpwnam|getpwuid|getgrnam|getgrgid|gethostbyname|gethostbyaddr|getservbyname|getlogin|ttyname|strsignal|ecvt|fcvt|crypt|inet_ntoa)\s*\(`

findings contains finding if {
	some path, content in input.file_contents
	some ext in _c_ext
	endswith(path, ext)
	_threaded(content)
	_names_any(content)
	lines := split(content, "\n")
	_threads_in_code(lines)
	some i, line in lines
	contains(line, "(")
	regex.match(_c_call, line)
	not helpers.is_comment_line(line)
	not _is_decl(line)
	regex.match(_c_call, _strip(line))
	finding := _finding(path, i, line, "Non-reentrant libc function (static result buffer) called in a file that starts threads: concurrent calls overwrite each other's result. Use the _r variant (strtok_r, localtime_r, getpwuid_r, getaddrinfo)")
}

_is_decl(line) if {
	regex.match(_c_decl, line)
	not regex.match(`^\s*(?:return|else|case|do)\b`, line)
}

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}
