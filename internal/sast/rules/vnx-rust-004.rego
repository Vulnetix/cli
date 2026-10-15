package vulnetix.rules.vnx_rust_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-RUST-004",
	"name": "Rust command injection via a shell or a request-controlled program in process::Command",
	"description": "Reports std::process::Command / tokio::process::Command in two shapes. (1) A shell interpreter (sh, bash, zsh, dash, ksh, /bin/sh, cmd, powershell, pwsh) is given its command-string flag (-c, -lc, /C, /K, -Command) followed by a non-literal command string: format!(...), a variable, a concatenation such as \"git checkout \".to_owned() + branch, whether chained on one line, split across builder lines, passed through .args([\"-c\", x]) / vec![...] (other literal options such as -NoProfile or -e may come first), or applied as separate cmd.arg(...) statements. The shell re-parses that string, so any ;, |, && or $(...) in interpolated input runs as a command. (2) Command::new(program) where the program name comes from an axum or actix-web request extractor (Query, Json, Form, Path, web::Query<...>) directly or through one assignment. Not reported: a shell given a constant command string (a literal, raw string, ALL_CAPS constant, include_str! or concat!), a command string whose interpolated value is shell-quoted with shlex, shell-escape or shell-words nearby, a shell running a script file with arguments, a non-shell program given format!(...) or user input as a separate .arg() (no shell parsing happens), Command::new(format!(...)) for a program path, and patterns inside comments or string literals. Command strings built further away than about eight lines from Command::new are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-rust-004/",
	"languages": ["rust"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [78],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["command-injection", "rust"],
}

_shell_new_re := `Command::new\s*\(\s*"(?:/usr)?(?:/bin/)?(?:sh|bash|zsh|dash|ksh|cmd|cmd\.exe|powershell|powershell\.exe|pwsh)"\s*\)`

_flag := `"(?:-c|-lc|-ec|-xc|/[cCkK]|-Command|-command|-EncodedCommand)"`

# A programmer-controlled command string: a literal, a raw string, an
# ALL_CAPS constant or include_str!/concat!.
_lit := `&?\s*(?:"(?:[^"\\]|\\.)*"|r#*"[^"]*"#*|[A-Z][A-Z0-9_]*\b|(?:include_str|concat)!\s*\([^()]*\))`

_arg_prefix := concat("", [`\.arg\s*\(\s*`, _flag, `\s*\)\s*(?:;\s*[A-Za-z_]\w*\s*)?\.arg\s*\(\s*`])

_arg_literal := concat("", [_arg_prefix, _lit, `\s*\)`])

# Other literal options may precede the command flag: ["-NoProfile", "-Command", x].
_args_prefix := concat("", [`\.args\s*\(\s*&?\s*(?:vec!\s*)?\[\s*(?:"-[^"]*"\s*,\s*)*`, _flag, `\s*,\s*`])

_args_literal := concat("", [_args_prefix, _lit, `\s*[\],]`])

# The code part of a line: string literals emptied, trailing // comment cut.
_code(line) := regex.replace(regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`), `//.*$`, "")

# The builder chain starting at line i: up to eight following code lines,
# stopping before the next Command::new.
_chain(lines, i) := concat("\n", [lines[k] |
	some k in numbers.range(i, min([count(lines) - 1, i + 8]))
	not helpers.is_comment_line(lines[k])
	not _later_command(lines, i, k)
])

_later_command(lines, i, k) if {
	k > i
	some m in numbers.range(i + 1, k)
	contains(lines[m], "Command::new")
}

_dynamic_shell(chain) if {
	regex.match(_arg_prefix, chain)
	not regex.match(_arg_literal, chain)
}

_dynamic_shell(chain) if {
	regex.match(_args_prefix, chain)
	not regex.match(_args_literal, chain)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rs")
	contains(content, "Command::new")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Command::new")
	not helpers.is_comment_line(line)
	regex.match(_shell_new_re, regex.replace(line, `//.*$`, ""))
	not regex.match(`"[^"]*Command::new`, line)
	_dynamic_shell(_chain(lines, i))
	# The interpolated value was shell-quoted (shlex, shell-escape, shell-words).
	not regex.match(`\b(?:shlex|shell_escape|shell_words)::`, helpers.code_window(lines, i, 6, 8))
	finding := {
		"rule_id": metadata.id,
		"message": "A shell is run with a command string built at runtime (sh -c / cmd /C with format!, a variable or concatenation); shell metacharacters in interpolated input execute as commands. Run the program directly with Command::new(\"prog\").arg(value) instead of going through a shell",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Program name taken from a web request ────────────────────────────────

_extractor_names(lines, i) := {v |
	some j in numbers.range(max([0, i - 30]), i)
	not helpers.is_comment_line(lines[j])
	some m in regex.find_all_string_submatch_n(`\b(?:Query|Json|Form|Path)\s*\(\s*([a-z_]\w*)\s*\)|\b([a-z_]\w*)\s*:\s*(?:actix_web::)?(?:web::)?(?:Query|Json|Form|Path)\s*<`, lines[j], -1)
	some v in array.slice(m, 1, 3)
	v != ""
}

_request_names(lines, i) := names if {
	base := _extractor_names(lines, i)
	derived := {v |
		some j in numbers.range(max([0, i - 30]), i - 1)
		not helpers.is_comment_line(lines[j])
		some b in base
		regex.match(concat("", [`=.*\b`, b, `\b`]), lines[j])
		v := helpers.assigned_first(lines[j])
	}
	names := base | derived
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".rs")
	contains(content, "Command::new")
	regex.match(`\b(?:Query|Json|Form|Path)\s*[<(]`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "Command::new")
	not helpers.is_comment_line(line)
	m := regex.find_all_string_submatch_n(`Command::new\s*\(\s*&?\s*([a-z_]\w*)\b\s*[^!\w]`, _code(line), 1)
	count(m) > 0
	m[0][1] in _request_names(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": "Command::new runs a program named by the HTTP request; an attacker chooses what executes. Map the request value to a fixed allow-list of programs instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
