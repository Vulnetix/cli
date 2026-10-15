# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_515

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-515",
	"name": "Covert Storage Channel: secret placed in the process environment",
	"description": "A Python program stores a secret in its own process environment, a storage area every child process inherits and that other processes of the same user (and root) can read through /proc/<pid>/environ, ps e and crash dumps, so the value reaches parties it was never sent to. This is the one statically recognisable form of a covert storage channel that ordinary application code creates. Reported: os.environ[KEY] = value, os.putenv(KEY, value), os.environ.setdefault(KEY, value) and os.environ.update({KEY: value} | KEY=value) (also through 'from os import environ', and update calls broken across lines) where KEY names a password, secret, token, API key, private or access key or credential, or where the key is a variable and the value is a variable named as one. Not reported: a copy of the environment passed to one child (env = os.environ.copy(); env['PGPASSWORD'] = pw, dict(os.environ, ...)), a value re-exported from the environment itself (os.environ.get, os.getenv), constants and empty strings, keys naming a file, path or id (SECRET_KEY_FILE), reads, deletes and pops, comments, strings and test code. Channels through file metadata, timing or other shared state are not decidable line by line and are not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-515/",
	"languages": ["python"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [515],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["covert-storage-channel", "environment", "secrets", "cwe-515"],
}

_secret_key(k) if {
	regex.match(`(?i)passw(?:or)?d|\bpass$|_pass$|secret|token(?:$|[_-])|api_?key|private_?key|access_?key|credential`, k)
	not regex.match(`(?i)(?:_|^)(?:file|path|dir|name|id|url|uri|type|ttl|expiry|expires|mode|enabled?|disabled?|level|backend|provider|store|header|format|algorithm|length|region|version)$`, k)
}

_secret_var(v) if {
	regex.match(`^[A-Za-z_][\w.]*$`, v)
	regex.match(`(?i)(?:passw(?:or)?d|passphrase|secret|token|api_?key|private_?key|credentials?)$`, v)
}

_constant(v) if regex.match(`^\s*(?:[rbuRB]{0,2}"[^"]*"|[rbuRB]{0,2}'[^']*'|None|True|False|-?\d+)\s*$`, v)

_from_env(v) if regex.match(`\benviron\b|\bgetenv\(`, v)

# A (key, value) pair is a secret export.
_secret_pair(k, v) if {
	m := regex.find_all_string_submatch_n(`^\s*[rbuRB]?["']([^"']+)["']\s*$`, k, 1)
	count(m) > 0
	_secret_key(m[0][1])
	_dynamic(v)
}

_secret_pair(k, v) if {
	regex.match(`^\s*[A-Za-z_][\w.]*\s*$`, k)
	_secret_var(trim_space(v))
}

_dynamic(v) if {
	trim_space(v) != ""
	not _constant(v)
	not _from_env(v)
}

# Strip a trailing comment and closing punctuation from a value.
_val(v) := trim_space(regex.replace(regex.replace(v, `\s+#.*$`, ""), `[\s,)}]+$`, ""))


_pairs(line, call) := (_assign_pairs(line) | _call_pairs(line)) | _update_pairs(line, call)

_assign_pairs(line) := {[m[1], _val(m[2])] |
	some m in regex.find_all_string_submatch_n(`\benviron\[\s*([^\]]+?)\s*\]\s*=\s*([^=].*)$`, line, -1)
}

_call_pairs(line) := {[m[1], _val(m[2])] |
	some m in regex.find_all_string_submatch_n(`(?:\bos\.putenv|\benviron\.setdefault)\(\s*([^,]+?)\s*,\s*(.+)$`, line, -1)
}

# os.environ.update({...}) or update(K=v), read until the call closes.
_update_pairs(line, call) := {[m[1], _val(m[2])] |
	regex.match(`\benviron\.update\(`, line)
	some m in regex.find_all_string_submatch_n(`(["'][^"']+["'])\s*:\s*([^,}]+)`, call, -1)
} | {[sprintf("%q", [m[1]]), _val(m[2])] |
	regex.match(`\benviron\.update\(`, line)
	some m in regex.find_all_string_submatch_n(`(?:\(|,)\s*([A-Za-z_]\w*)\s*=\s*([^,)]+(?:\([^()]*\))?)`, call, -1)
}

_call(lines, i) := txt if {
	last := min([count(lines) - 1, i + 4])
	ends := [j | some j in numbers.range(i, last); regex.match(`\)\s*(#.*)?$`, lines[j])]
	end := min(array.concat([last], ends))
	txt := concat(" ", [lines[j] | some j in numbers.range(i, end)])
}

# Strings that themselves mention environ are prose or examples, not calls.
_unquote(line) := regex.replace(line, `"[^"]*(?:environ|putenv)[^"]*"|'[^']*(?:environ|putenv)[^']*'`, "''")

findings contains f if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`environ|putenv`, content)
	not helpers.is_test_path(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`environ|putenv`, line)
	not helpers.is_comment_line(line)
	c := _unquote(line)
	regex.match(`(?:^|[^\w.])(?:os\.)?environ(?:\[|\.update\(|\.setdefault\()|\bos\.putenv\(`, c)
	some p in _pairs(c, _call(lines, i))
	_secret_pair(p[0], p[1])
	f := {
		"rule_id": metadata.id,
		"message": "A secret is stored in the process environment, which every child process inherits and other processes of the same user can read (/proc/<pid>/environ). Pass it to the one process that needs it (an env= copy, stdin or a 0600 file) instead of exporting it",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
