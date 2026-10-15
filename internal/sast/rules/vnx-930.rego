# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_930

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-930",
	"name": "Android app runs commands as root through su",
	"description": "CWE-930 is an OWASP Top Ten 2013 category (broken authentication and session management) with no code shape of its own; this rule reports the concrete device-level authorization signal it was generated for: Java or Kotlin code that launches the su binary to run commands as root, through Runtime.getRuntime().exec(\"su\"), exec(\"su -c ...\"), exec(new String[]{\"su\", ...}) or exec(arrayOf(\"su\", ...)), new ProcessBuilder(\"su\", ...), ProcessBuilder(listOf/Arrays.asList(\"su\", ...)) or processBuilder.command(\"su\", ...), with su named bare or by an absolute path (/system/xbin/su, /su/bin/su) and the argument list possibly starting on the next line; a command array whose first element is su assigned a few lines before the exec; and the libsuperuser Shell.SU.run(...) and early libsu Shell.su(...) root-shell helpers. Whatever the root shell runs bypasses the Android permission model. Not reported: root detection (which su, ls /system/xbin/su, File(\"/system/xbin/su\").exists(), Shell.SU.available(), Superuser.apk checks), non-root shells (Shell.SH.run), other commands, comments and strings, and test code (src/test, src/androidTest, *Test.java).",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-930/",
	"languages": ["java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [930],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["authorization-bypass-device", "android", "cwe-930"],
}

_ext(path) if endswith(path, ".java")

_ext(path) if endswith(path, ".kt")

_su_arg := `"((/[\w.-]+)*/)?su(\s[^"]*)?"`

_wrap := `(new\s+String\s*\[\s*\]\s*\{\s*|arrayOf\s*\(\s*|listOf\s*\(\s*|List\.of\s*\(\s*|Arrays\.asList\s*\(\s*)?`

_direct_re := concat("", [`(\.exec|\bProcessBuilder|\.command)\s*\(\s*`, _wrap, _su_arg])

# libsuperuser (eu.chainfire) and early libsu run their argument in a root shell.
_lib_re := `\bShell\s*\.\s*(SU\s*\.\s*run|su)\s*\(`

# The call joined with the next line when its argument list continues there.
_call_text(line, _) := line if not regex.match(`[({,]\s*$`, line)

_call_text(line, next) := concat(" ", [line, trim_space(next)]) if regex.match(`[({,]\s*$`, line)

_next(lines, i) := lines[i + 1] if i + 1 < count(lines)

_next(lines, i) := "" if i + 1 >= count(lines)

_test(path) if helpers.is_test_path(path)

_test(path) if regex.match(`(^|/)(androidTest|testDebug|testRelease)/`, path)

_array_re := concat("", [`\b([A-Za-z_]\w*)\s*(:\s*(Array|List)<String>\s*)?=\s*(new\s+String\s*\[\s*\]\s*)?(\{|arrayOf\s*\(|listOf\s*\(|List\.of\s*\(|Arrays\.asList\s*\()\s*`, _su_arg])

_hit(line, lines, i) if regex.match(_direct_re, _call_text(line, _next(lines, i)))

_hit(line, _, _) if regex.match(_lib_re, line)

_hit(line, lines, i) if {
	m := regex.find_all_string_submatch_n(`(\.exec|\bProcessBuilder|\.command)\s*\(\s*([A-Za-z_]\w*)\s*\)`, line, 1)
	count(m) > 0
	v := m[0][2]
	some j in numbers.range(max([0, i - 10]), i - 1)
	not helpers.is_comment_line(lines[j])
	am := regex.find_all_string_submatch_n(_array_re, lines[j], 1)
	count(am) > 0
	am[0][1] == v
}

findings contains finding if {
	some path, content in input.file_contents
	_ext(path)
	not _test(path)
	regex.match(`"((/[\w.-]+)*/)?su[\s"]|Shell\s*\.\s*(SU\s*\.\s*run|su)\s*\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\.exec\s*\(|ProcessBuilder|\.command\s*\(|Shell\s*\.`, line)
	not helpers.is_comment_line(line)
	regex.match(`\.exec\s*\(|ProcessBuilder|\.command\s*\(|Shell\s*\.`, regex.replace(line, `"(\\.|[^"\\])*"`, `""`))
	_hit(line, lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "The app runs a command as root through su, bypassing the Android permission model; a command built from input becomes root code execution. Use a platform API or a privileged system service instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
