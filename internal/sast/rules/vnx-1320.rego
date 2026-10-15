# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1320

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1320",
	"name": "Fault or watchdog alert signal suppressed",
	"description": "CWE-1320 (Improper Protection for Outbound Error Messages and Alert Signals) is a hardware weakness: an untrusted agent can disable or mask the alerts a component raises on a fault. Its nearest statically recognisable form in C and C++ is reported: code that switches off the alert channel the kernel and hardware use to report a fault, so the fault goes unnoticed and execution continues in an undefined state. Reported: signal()/std::signal()/sigset()/bsd_signal()/sysv_signal() setting SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGSYS, SIGXCPU or SIGABRT to SIG_IGN; sigaction() installing one of those signals with a struct whose sa_handler was last set to SIG_IGN (an assignment or a designated initialiser in the 15 lines above); disabling a hardware watchdog with ioctl(WDIOC_SETOPTIONS) where WDIOS_DISABLECARD is on the line or in the 5 lines above; and the watchdog magic close, write(fd, \"V\", 1), in a file that opens /dev/watchdog. Not reported: ignoring SIGPIPE, SIGCHLD, SIGHUP, SIGINT and other non-fault signals, a real handler or SIG_DFL for a fault signal, ordinary ioctl calls (WDIOC_KEEPALIVE, WDIOC_SETTIMEOUT, terminal ioctls), comments and string literals. The original rule's 'any ioctl() call' heuristic is gone: an ioctl is not by itself an alert-protection issue.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1320/",
	"languages": ["c", "cpp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1320],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["alert-suppression", "signals", "watchdog", "cwe-1320"],
}

_lang(path) if endswith(path, ".c")

_lang(path) if endswith(path, ".h")

# C++ uses the same signal/sigaction/watchdog API (std::signal, ::sigaction).
_lang(path) if {
	some e in {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"}
	endswith(path, e)
}

_faults := `SIG(?:SEGV|BUS|FPE|ILL|SYS|XCPU|ABRT)`

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `/\*.*?\*/|//.*$`, "")

_finding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

_ign_msg := "A fault signal is set to SIG_IGN: the hardware/kernel alert for a crash is suppressed and execution continues in an undefined state. Handle it (log and exit) or leave the default"

# signal(FAULT, SIG_IGN)
findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "SIG_IGN")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "SIG_IGN")
	not helpers.is_comment_line(line)
	regex.match(concat("", [`\b(?:std::)?(?:signal|sigset|bsd_signal|sysv_signal)\s*\(\s*`, _faults, `\s*,\s*SIG_IGN\s*\)`]), _code(line))
	finding := _finding(path, i, line, _ign_msg)
}

# signal(FAULT,
#        SIG_IGN);  the call split after the signal number
findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "SIG_IGN")
	regex.match(concat("", [`(?m)\b(?:signal|sigset|bsd_signal|sysv_signal)\s*\(\s*`, _faults, `\s*,\s*$`]), content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "SIG")
	not helpers.is_comment_line(line)
	regex.match(concat("", [`\b(?:std::)?(?:signal|sigset|bsd_signal|sysv_signal)\s*\(\s*`, _faults, `\s*,\s*$`]), _code(line))
	i + 1 < count(lines)
	regex.match(`^\s*SIG_IGN\s*\)`, lines[i + 1])
	finding := _finding(path, i, line, _ign_msg)
}

# sigaction(FAULT, &sa, ...) where sa's handler is SIG_IGN
findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "SIG_IGN")
	contains(content, "sigaction")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "sigaction")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(concat("", [`\bsigaction\s*\(\s*`, _faults, `\s*,\s*&\s*(\w+)`]), _code(line), 1)
	count(m) > 0
	v := m[0][1]
	_handler_ignored(lines, i, v)
	finding := _finding(path, i, line, _ign_msg)
}

_handler_ignored(lines, i, v) if {
	sets := [j |
		some j in numbers.range(max([0, i - 15]), i - 1)
		regex.match(concat("", [`\b`, v, `\s*(?:\.|->)\s*sa_handler\s*=|\b`, v, `\s*=\s*\{[^}]*\.sa_handler\s*=`]), lines[j])
		not helpers.is_comment_line(lines[j])
	]
	count(sets) > 0
	last := lines[max(sets)]
	regex.match(`sa_handler\s*=\s*SIG_IGN\b`, last)
}

# ioctl(fd, WDIOC_SETOPTIONS, WDIOS_DISABLECARD)
findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "WDIOS_DISABLECARD")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "WDIOC_SETOPTIONS")
	not helpers.is_comment_line(line)
	regex.match(`\bioctl\s*\([^,]+,\s*WDIOC_SETOPTIONS\b`, _code(line))
	w := helpers.code_window(lines, i, 5, 0)
	regex.match(`(?m)^[^"/]*WDIOS_DISABLECARD`, w)
	finding := _finding(path, i, line, "The hardware watchdog is disabled (WDIOS_DISABLECARD): a hang no longer raises the watchdog's reset alert")
}

# watchdog magic close
findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	contains(content, "/dev/watchdog")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, `"V"`)
	not helpers.is_comment_line(line)
	regex.match(`\bwrite\s*\([^,]+,\s*"V"\s*,\s*1\s*\)`, line)
	finding := _finding(path, i, line, "Writing the magic 'V' to /dev/watchdog disarms the watchdog on close: a hang no longer raises the watchdog's reset alert")
}
