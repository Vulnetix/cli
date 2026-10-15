# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_379

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-379",
	"name": "Creation of Temporary File in Directory with Insecure Permissions",
	"description": "Python code puts temporary files where other local users can see, replace or pre-create them. Reported: os.mkdir()/os.makedirs() with a mode that lets other users write (0o777, 0o1777, 0o773, 511 and the like, or stat.S_IRWXO/S_IWOTH), and os.chmod() granting other users write to a temporary directory (a /tmp/, /var/tmp/ or /dev/shm/ literal, or a variable assigned from tempfile.mkdtemp()/gettempdir() or such a literal in the 10 lines above); a fixed, predictable file name in a shared temporary directory opened for writing (open()/io.open() with a w, a or + mode and no x, given as a literal, an f-string, or a variable assigned one in the 10 lines above, and pathlib Path(...).write_text/write_bytes/touch), os.path.join(tempfile.gettempdir(), \"literal\") or os.path.join(\"/tmp\", \"literal\"), Path(tempfile.gettempdir()) / \"literal\", and logging.FileHandler (also Rotating/TimedRotating/Watched) given such a fixed path. Calls that span lines are joined (up to 5 lines for mkdir/makedirs). Not reported: owner-only or group-only modes (0o700, 0o750, 0o755), chmod of a path that is not a temporary directory, tempfile.mkstemp/NamedTemporaryFile/TemporaryDirectory (which create private, unpredictable entries even inside /tmp), reads, writes outside shared temporary directories, comments and the pattern inside a string literal. The fixed-name writes overlap VNX-59, which reports them as symlink attacks.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-379/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [379],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["tempfile-insecure-dir", "cwe-379"],
}

_tmp_lit := `[fFrRbB]{0,2}["']/(?:tmp|var/tmp|dev/shm)/[^"']*["']`

# A mode other users can write through: octal whose last digit has the 2 bit,
# the decimal spellings of 0o777/0o1777/0o776, or a symbolic other-write bit.
_wide_mode_re := `(?:\b0o?[0-7]{0,3}[2367]\b|\b(?:511|1023|510)\b|\bS_IRWXO\b|\bS_IWOTH\b)`

# The call is code, not text inside a string: the quotes before it balance.
_in_code(line, call_re) if {
	m := regex.find_all_string_submatch_n(concat("", [`^(.*?)`, call_re]), line, 1)
	count(m) > 0
	count(regex.find_n(`["']`, m[0][1], -1)) % 2 == 0
}

_finding(path, i, raw, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": raw,
}

# os.mkdir / os.makedirs with a world-writable mode (positional or mode=,
# possibly on the next line).
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)\bos\.(?:mkdir|makedirs)\s*\(`, content)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "os.m")
	not helpers.is_comment_line(raw)
	_in_code(raw, `\bos\.(?:mkdir|makedirs)\s*\(`)
	call := concat(" ", array.slice(lines, i, min([count(lines), i + 5])))
	m := regex.find_all_string_submatch_n(`\bos\.(?:mkdir|makedirs)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)`, call, 1)
	count(m) > 0
	args := split(m[0][1], ",")
	count(args) >= 2
	some k, a in args
	k >= 1
	regex.match(concat("", [`^\s*(?:mode\s*=\s*)?`, `[^=]*`, _wide_mode_re]), a)
	not regex.match(`^\s*exist_ok\s*=`, a)
	finding := _finding(path, i, raw, "Directory created with a mode that lets every local user write to it: files placed there can be replaced or pre-created. Create it 0o700 (tempfile.mkdtemp() does)")
}

# os.chmod opening a temporary directory to other users.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "chmod")
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "chmod")
	not helpers.is_comment_line(raw)
	_in_code(raw, `\bos\.chmod\s*\(`)
	m := regex.find_all_string_submatch_n(`\bos\.chmod\s*\(\s*([^,]+?)\s*,\s*([^)]*(?:\([^)]*\))?[^)]*)\)`, raw, 1)
	count(m) > 0
	regex.match(_wide_mode_re, m[0][2])
	_temp_dir(lines, i, m[0][1])
	finding := _finding(path, i, raw, "Temporary directory is made writable by every local user: keep it owner-only (0o700)")
}

_temp_dir(_, _, target) if regex.match(concat("", [`^`, _tmp_lit, `$`]), target)

_temp_dir(lines, i, target) if {
	regex.match(`^[A-Za-z_]\w*$`, target)
	i > 0
	some j in numbers.range(max([0, i - 10]), i - 1)
	regex.match(concat("", [`^\s*`, target, `\s*=\s*(?:tempfile\.(?:mkdtemp|gettempdir)\s*\(|`, _tmp_lit, `)`]), lines[j])
}

# open()/io.open() of a fixed temp-dir name for writing.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)["']/(?:tmp|var/tmp|dev/shm)/`, content)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "open")
	not helpers.is_comment_line(raw)
	_in_code(raw, `\bopen\s*\(`)
	m := regex.find_all_string_submatch_n(concat("", [`(?:^|[^\w.]|\bio\.)open\s*\(\s*(`, _tmp_lit, `|[A-Za-z_]\w*)\s*,\s*(?:mode\s*=\s*)?[rbRB]?["']([^"']*)["']`]), raw, 1)
	count(m) > 0
	regex.match(`[wa+]`, m[0][2])
	not contains(m[0][2], "x")
	_tmp_name(lines, i, m[0][1])
	finding := _finding(path, i, raw, "File with a fixed name in a shared temporary directory is opened for writing: another local user can pre-create or link it. Use tempfile.NamedTemporaryFile() or mkstemp()")
}

_tmp_name(_, _, arg) if regex.match(concat("", [`^`, _tmp_lit, `$`]), arg)

_tmp_name(lines, i, arg) if {
	regex.match(`^[A-Za-z_]\w*$`, arg)
	i > 0
	some j in numbers.range(max([0, i - 10]), i - 1)
	regex.match(concat("", [`^\s*`, arg, `\s*=\s*`, _tmp_lit, `\s*(?:#.*)?$`]), lines[j])
}

# Path("/tmp/x").write_text(...) / write_bytes / touch / open("w").
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "Path(")
	regex.match(`(?m)Path\(\s*[fFrR]?["']/(?:tmp|var/tmp|dev/shm)/`, content)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "Path(")
	not helpers.is_comment_line(raw)
	_in_code(raw, `\bPath\s*\(`)
	regex.match(concat("", [`\bPath\s*\(\s*`, _tmp_lit, `\s*\)\s*\.\s*(?:write_text|write_bytes|touch|open\s*\(\s*["'][^"'x]*[wa+])`]), raw)
	finding := _finding(path, i, raw, "File with a fixed name in a shared temporary directory is written: another local user can pre-create or link it. Use tempfile.NamedTemporaryFile() or mkstemp()")
}

# The shared temporary directory as an expression.
_tmp_dir_expr := `(?:(?:tempfile\.)?gettempdir\s*\(\s*\)|[fFrR]?["']/(?:tmp|var/tmp|dev/shm)/?["'])`

# os.path.join(tempfile.gettempdir(), "fixed-name"), os.path.join("/tmp", "x"),
# Path(gettempdir()) / "fixed-name".
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	regex.match(`(?m)gettempdir|["']/(?:tmp|var/tmp|dev/shm)/?["']`, content)
	lines := split(content, "\n")
	some i, raw in lines
	regex.match(`gettempdir|/(?:tmp|var/tmp|dev/shm)/?["']`, raw)
	not helpers.is_comment_line(raw)
	_fixed_join(raw)
	finding := _finding(path, i, raw, "Predictable file name in the shared temporary directory: another local user can pre-create or link it. Use tempfile.NamedTemporaryFile() or mkstemp()")
}

_fixed_join(raw) if {
	_in_code(raw, `\bos\.path\.join\s*\(`)
	regex.match(concat("", [`\bos\.path\.join\s*\(\s*`, _tmp_dir_expr, `\s*,\s*["'][^"'{}%]+["']\s*\)`]), raw)
}

_fixed_join(raw) if {
	_in_code(raw, `\bPath\s*\(`)
	regex.match(concat("", [`\bPath\s*\(\s*`, _tmp_dir_expr, `\s*\)\s*/\s*["'][^"'{}%]+["']`]), raw)
}

# logging.FileHandler("/tmp/app.log"): appends to a fixed name in /tmp.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "FileHandler")
	regex.match(`(?m)["']/(?:tmp|var/tmp|dev/shm)/`, content)
	lines := split(content, "\n")
	some i, raw in lines
	contains(raw, "FileHandler")
	not helpers.is_comment_line(raw)
	_in_code(raw, `\bFileHandler\s*\(`)
	m := regex.find_all_string_submatch_n(concat("", [`\b(?:Rotating|TimedRotating|Watched)?FileHandler\s*\(\s*(`, _tmp_lit, `|[A-Za-z_]\w*)`]), raw, 1)
	count(m) > 0
	_tmp_name(lines, i, m[0][1])
	finding := _finding(path, i, raw, "Log file with a fixed name in a shared temporary directory: another local user can pre-create or link it. Write logs to a private directory")
}
