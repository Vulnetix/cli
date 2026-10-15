# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_1100

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-1100",
	"name": "Insufficient Isolation of System-Dependent Functions",
	"description": "Java or Python code launches a process through a hard-coded, operating-system-specific shell or command (cmd, cmd.exe, cmd /c, powershell, pwsh, /bin/sh, /bin/bash, sh -c, bash -c, zsh, os.system(\"cls\"/\"clear\")) and the file never checks which platform it runs on (os.name, sys.platform, platform.system(), System.getProperty(\"os.name\"), SystemUtils.IS_OS_*, an isWindows flag). The system-dependent call is not isolated behind a platform check or adapter, so on another OS the command fails or a different interpreter parses it with different quoting and escaping rules. Reported: the line holding the shell literal when a process launch (Runtime.exec, ProcessBuilder, .command(), subprocess.run/call/Popen/check_output/check_call, os.system, os.popen, os.exec*/spawn*, asyncio.create_subprocess_exec) is on that line or within three lines of it. Not reported: files that branch on the platform anywhere, shell=True without a named shell, a SHELL environment value given to the child (env={\"SHELL\": \"/bin/bash\"}), shebang lines, the literal outside a process launch, test files and comments. Whether the launched command is itself injectable is judged by the command-injection rules, not this one.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-1100/",
	"languages": ["java", "python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [1100],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["portability", "process", "maintainability", "cwe-1100"],
}

# A quoted shell name as a whole argument, or a command string that starts with one.
# It must sit where a command goes: a list/array element, an assignment, or the
# first argument of a launch or list-building call (not shutil.which("bash")).
_shell_re := `(?:[\[{,=?:]|\b(?:of|asList|add|append|command|exec|run|call|Popen|check_output|check_call|system|popen|getoutput|getstatusoutput|ProcessBuilder|create_subprocess_exec|exec[lv]p?e?|spawn[lv]p?e?)\s*\()\s*["'](?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|/bin/(?:ba|z|k|da)?sh|/usr/bin/(?:env\s+)?(?:ba|z)?sh|bash|sh|zsh)(?:["']|\s+(?:/[cCkK]|-[cCl]+|-Command|-NoProfile)\b)`

_clear_re := `\bos\.system\s*\(\s*["'](?:cls|clear)["']`

_launch_re := `\bRuntime\.getRuntime\(\)\s*\.\s*exec\s*\(|\bnew\s+ProcessBuilder\s*\(|\.command\s*\(|\.exec\s*\(|\b(?:subprocess|sp)\.(?:run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(|\bos\.(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?)\s*\(|\bcreate_subprocess_exec\s*\(`

_guard_re := `(?i)\bos\.name\b|["']os\.name["']|\bsys\.platform\b|\bplatform\.system\s*\(|\bos\.uname\b|SystemUtils\.IS_OS|\bis_?windows\b|\bis_?win(32)?\b|\bOS\.isFamily|\bIS_WINDOWS\b|\bOsUtils?\.|\bPlatform\.is`

_lang(path) if endswith(path, ".java")

_lang(path) if endswith(path, ".py")

# A SHELL environment value (env={"SHELL": "/bin/bash"}, SHELL="/bin/bash") names
# the user's shell for the child; it is not the command being launched.
_platform_literal(line) if regex.match(_shell_re, regex.replace(line, `(?i)\bshell["']?\s*[:=]\s*["'][^"']*["']`, ""))

_platform_literal(line) if regex.match(_clear_re, line)

findings contains finding if {
	some path, content in input.file_contents
	_lang(path)
	regex.match(`(cmd|powershell|pwsh|/bin/|bash|["']sh|zsh|cls|clear)`, content)
	regex.match(_launch_re, content)
	not regex.match(_guard_re, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	not helpers.is_comment_line(line)
	not startswith(line, "#!")
	_platform_literal(line)
	regex.match(_launch_re, helpers.code_window(lines, i, 3, 3))
	finding := {
		"rule_id": metadata.id,
		"message": "Process launched through a hard-coded OS-specific shell with no platform check in this file; isolate the call behind a platform check or adapter, or run the program directly without a shell",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
