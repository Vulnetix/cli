# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_732

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-732",
	"name": "Incorrect permission assignment for a critical resource (Python)",
	"description": "Python code gives a file or directory permissions that let other local users change it or read a secret in it. Reported: os.chmod/os.lchmod/os.fchmod and Path/any object's .chmod() with a world-writable mode (an octal literal whose last digit is 2, 3, 6 or 7, in 0o777 or legacy 0777 form, or stat.S_IWOTH / stat.S_IRWXO), given directly, as mode=, or through a variable assigned such a mode up to ten lines above; os.umask() set to a value that leaves the others-write bit unmasked (os.umask(0), 0o000, 0o001, 0o004, 0o005, 0o010 ...), after which every file the process creates is world-writable, unless the next lines restore the saved mask (the read-the-umask idiom old = os.umask(0); os.umask(old)); and chmod of a path whose name says it holds a key or credential (key, secret, token, credential, password, .pem, id_rsa, id_ed25519, .ssh) to a mode readable by others (last digit 4-7). Not reported: owner-only or group modes (0o600, 0o640, 0o750, 0o755 on ordinary files), the sticky-bit shared directory mode 0o1777, umask values that mask others-write (0o022, 0o027, 0o077), modes passed to creation calls that the umask filters (os.open, os.makedirs, os.mkdir), test code, comments and string literals. Also reported: the chmod command run from Python (os.system('chmod 777 ...'), os.popen, subprocess.run(['chmod', '-R', '0666', path])) with a world-writable numeric or symbolic (o+w, a+w) mode. VNX-276 reports the same world-writable chmod across many languages.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-732/",
	"languages": ["python"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [732],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["insecure-permissions", "chmod", "umask", "cwe-732"],
}

# String literals blanked, so a log message naming chmod 777 is not a call.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

# The line, joined with up to four following lines when a call opened on it
# is not closed there (a call broken over several lines).
_joined(lines, i) := c if {
	c := _code(lines[i])
	not regex.match(`\(\s*$|,\s*$`, c)
} else := concat(" ", [_code(lines[k]) | some k in numbers.range(i, min([count(lines) - 1, i + 4]))])

# chmod call's argument list (one level of nested parentheses allowed).
_chmod_args(code) := a if {
	m := regex.find_all_string_submatch_n(`(?:\bos\.(?:l|f)?chmod|\.chmod|^\s*(?:l|f)?chmod)\s*\(((?:[^()]|\([^()]*\))*)\)`, code, 1)
	count(m) > 0
	a := m[0][1]
}

# The mode argument: mode=..., otherwise the last positional argument.
_mode_arg(args) := trim_space(m[0][1]) if {
	m := regex.find_all_string_submatch_n(`\bmode\s*=\s*([^,]+)`, args, 1)
	count(m) > 0
} else := trim_space(parts[count(parts) - 1]) if {
	# A trailing comma (a call broken one argument per line) is not an argument.
	parts := split(regex.replace(args, `,\s*$`, ""), ",")
}


_octal_last(mode) := d if {
	m := regex.find_all_string_submatch_n(`^0[oO]?[0-7]*([0-7])$`, mode, 1)
	count(m) > 0
	not regex.match(`^0[oO]?1[0-7]{3}$`, mode)
	d := m[0][1]
}

_world_writable_literal(mode) if {
	d := _octal_last(mode)
	d in {"2", "3", "6", "7"}
}

# A negated bit (st_mode & ~stat.S_IWOTH) removes the permission, so it is
# dropped before the test.
_world_writable_literal(mode) if {
	kept := regex.replace(mode, `~\s*(?:\([^)]*\)|[\w.]+)`, "")
	regex.match(`\bS_IWOTH\b|\bS_IRWXO\b`, kept)
}

_others_readable(mode) if {
	d := _octal_last(mode)
	d in {"4", "5", "6", "7"}
}

_mode_value(lines, i, mode) := mode if not regex.match(`^[A-Za-z_]\w*$`, mode)

# A bare name: the literal it was assigned up to ten lines above.
_mode_value(lines, i, mode) := v if {
	regex.match(`^[A-Za-z_]\w*$`, mode)
	vals := [trim_space(m[0][1]) |
		some j in numbers.range(max([0, i - 10]), i - 1)
		m := regex.find_all_string_submatch_n(concat("", [`^\s*`, mode, `\s*=\s*([^=#][^#]*)$`]), lines[j], 1)
		count(m) > 0
	]
	count(vals) > 0
	v := _open_paren_value(lines, vals[count(vals) - 1], i)
}

# A parenthesised multi-line assignment (`m = (` ... `)`) is read as the lines
# up to the closing parenthesis.
_open_paren_value(lines, val, i) := val if not regex.match(`^\(\s*$`, val)

_open_paren_value(lines, val, i) := v if {
	regex.match(`^\(\s*$`, val)
	opens := [j |
		some j in numbers.range(max([0, i - 10]), i - 1)
		regex.match(`^\s*[A-Za-z_]\w*\s*=\s*\(\s*$`, lines[j])
	]
	j0 := opens[count(opens) - 1]
	closes := [k | some k in numbers.range(j0 + 1, min([count(lines) - 1, j0 + 8])); contains(lines[k], ")")]
	count(closes) > 0
	v := concat(" ", [trim_space(lines[k]) | some k in numbers.range(j0 + 1, closes[0])])
}

_secret_path(arg) if regex.match(`(?i)(key|secret|token|cred|passw|\.pem\b|id_rsa|id_ed25519|id_ecdsa|\.ssh)`, arg)

_finding(lines, i, code) := "world" if {
	args := _chmod_args(code)
	mode := _mode_value(lines, i, _mode_arg(args))
	_world_writable_literal(mode)
}

_finding(lines, i, code) := "secret" if {
	args := _chmod_args(code)
	mode := _mode_value(lines, i, _mode_arg(args))
	not _world_writable_literal(mode)
	_others_readable(mode)
	_secret_path(regex.replace(lines[i], `\s#.*$`, ""))
}

_finding(lines, i, code) := "umask" if {
	m := regex.find_all_string_submatch_n(`\bos\.umask\s*\(\s*(0[oO]?[0-7]*|0)\s*\)`, code, 1)
	count(m) > 0
	v := m[0][1]
	last := substring(v, count(v) - 1, 1)
	last in {"0", "1", "4", "5"}
	not _restored(lines, i, code)
}

# The chmod binary run from Python: os.system("chmod 777 x"), os.popen(...),
# subprocess.run(["chmod", "-R", "0666", x]). The mode is read from the
# literal, so this runs on the raw line, not the string-blanked one.
_shell_call := `\b(?:os\.system|os\.popen|subprocess\.\w+|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(`

_shell_mode(line) := m[0][1] if {
	m := regex.find_all_string_submatch_n(`["'](?:sudo\s+)?chmod\s+(?:-[A-Za-z]+\s+)*([0-7]{3,4}|[ugoa]+[+=][rwxXst]+)\b`, line, 1)
	count(m) > 0
} else := m[0][1] if {
	m := regex.find_all_string_submatch_n(`["']chmod["']\s*,\s*(?:["']-[A-Za-z]+["']\s*,\s*)*["']([0-7]{3,4}|[ugoa]+[+=][rwxXst]+)["']`, line, 1)
	count(m) > 0
}

_shell_world_writable(mode) if {
	regex.match(`^[0-7]{3,4}$`, mode)
	not regex.match(`^1[0-7]{3}$`, mode)
	substring(mode, count(mode) - 1, 1) in {"2", "3", "6", "7"}
}

_shell_world_writable(mode) if regex.match(`^[ugo]*[ao][ugoa]*[+=][rxXst]*w`, mode)

_finding(lines, i, code) := "world" if {
	regex.match(_shell_call, code)
	_shell_world_writable(_shell_mode(lines[i]))
}

# old = os.umask(0) followed by os.umask(old): reading the current mask.
_restored(lines, i, code) if {
	v := helpers.assigned_first(code)
	end := min([count(lines) - 1, i + 4])
	i + 1 <= end
	some k in numbers.range(i + 1, end)
	regex.match(concat("", [`\bumask\s*\(\s*`, v, `\s*\)`]), lines[k])
}

_message := {
	"world": "chmod gives others write access: any local user can replace or modify this file. Use an owner-only mode such as 0o600/0o700, or 0o644/0o755 when it must be readable",
	"secret": "A key or credential file is made readable by every local user. Restrict it to its owner with 0o600",
	"umask": "os.umask() leaves the others-write bit unmasked, so every file and directory the process creates afterwards is world-writable. Keep at least 0o022 (or 0o077 for secrets)",
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`chmod|umask`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`chmod|umask`, line)
	not helpers.is_comment_line(line)
	code := _joined(lines, i)
	kind := _finding(lines, i, code)
	finding := {
		"rule_id": metadata.id,
		"message": _message[kind],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
