# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_277

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-277",
	"name": "Insecure Inherited Permissions",
	"description": "The program defines a permission set that everything it creates afterwards inherits, and that set lets any user write. Reported: a process umask that leaves the others-write bit open (umask(0), umask(0000), umask(020), shell `umask 000`/`umask a=rwx`) in C, C++, Python (os.umask), Go (syscall.Umask/unix.Umask), PHP, Ruby (File.umask), Node.js (process.umask, numeric or string), shell scripts, Dockerfile RUN lines and systemd units (UMask=0000), which every file the process and its children create from then on inherits; a Windows security descriptor with a NULL DACL (SetSecurityDescriptorDacl(&sd, TRUE, NULL, ...)), which grants everyone full access to the objects created with it; an SDDL string with an inheritable (OI/CI) allow ACE that gives Everyone, Anonymous, Authenticated Users or Users write or full rights; and a .NET FileSystemAccessRule or RegistryAccessRule that allows Everyone/Users/Authenticated Users write, modify or full control with ContainerInherit/ObjectInherit. Not reported: a umask that masks others-write (022, 077, 002), the read-and-restore idiom (old = umask(0); umask(old)) and a zero umask restored within a few statements (around an explicit creation mode, in a finally), a umask taken from a variable, a real DACL, deny rules, rules without inheritance, test code, and the calls in comments or strings.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-277/",
	"languages": ["c", "cpp", "python", "go", "php", "ruby", "javascript", "bash", "docker", "csharp"],
	"severity": "low",
	"level": "note",
	"kind": "sast",
	"cwe": [277],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["inherited-permissions", "umask", "acl", "file-permissions", "cwe-277"],
}

_umask_msg := "The umask is cleared so others may write: every file and directory this process and its children create from now on inherits world-writable permissions wherever the code asks for 0666/0777. Keep a umask of at least 022 (077 for private data), or restore the previous value immediately"

_acl_msg := "This security descriptor lets Everyone write to, or fully control, the objects created with it and everything that inherits from them. Grant access to specific principals (the service account, Administrators) instead of Everyone/Users, and drop the inheritance flags unless children need the ACE"

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# Test code is not the surface: the shared test-path convention, plus shell
# test scripts (test.sh, run_test.sh, *.bats) that live beside the code.
_is_test(path) if helpers.is_test_path(path)

_is_test(path) if regex.match(`(^|/)tests?([_.-][^/]*)?\.(sh|bash)$|_tests?\.(sh|bash)$|\.bats$`, path)

# ── Languages ────────────────────────────────────────────────────────────

_lang(path) := "c" if {
	some ext in {".c", ".cc", ".cpp", ".cxx"}
	endswith(path, ext)
}

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "php" if endswith(path, ".php")

_lang(path) := "ruby" if {
	some ext in {".rb", ".rake"}
	endswith(path, ext)
}

_lang(path) := "js" if {
	some ext in {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"}
	endswith(path, ext)
}

_shell(path) if {
	some ext in {".sh", ".bash", ".zsh", ".ksh", ".bats"}
	endswith(path, ext)
}

# A Dockerfile RUN line is a shell command: `RUN umask 0000 && pip install`
# bakes world-writable files into the image.
_shell(path) if {
	lp := lower(path)
	_has_any(lp, {"dockerfile", "containerfile"})
	base := regex.replace(lp, `^.*/`, "")
	regex.match(`^(dockerfile|containerfile)([._-].*)?$|\.(dockerfile|containerfile)$`, base)
}

# systemd units set the umask of the service and everything it starts.
_unit_ext := {".service", ".socket", ".mount", ".swap", ".path", ".timer"}

_systemd(path) if {
	some ext in _unit_ext
	endswith(path, ext)
}

_systemd(path) if regex.match(`(^|/)systemd/.*\.conf$|\.service\.d/[^/]*\.conf$`, path)

# ── umask in a program ───────────────────────────────────────────────────

# The call and its literal argument.
_umask_re := {
	"c": `(?:^|[^\w.>])(?:::)?umask\s*\(\s*([0-9a-fA-FxXoO]+)\s*\)`,
	"py": `\bos\.umask\s*\(\s*([0-9a-fA-FxXoO]+)\s*\)`,
	"go": `\b(?:syscall|unix)\.Umask\s*\(\s*([0-9a-fA-FxXoO]+)\s*\)`,
	"php": `(?:^|[^\w>:$])@?umask\s*\(\s*([0-9a-fA-FxXoO]+)\s*\)`,
	"ruby": `\bFile\.umask[\s(]\s*([0-9a-fA-FxXoO]+)\s*\)?`,
	"js": `\bprocess\.umask\s*\(\s*["']?([0-9a-fA-FxXoO]+)["']?\s*\)`,
}

_umask_gate := {
	"c": "umask",
	"py": "os.umask",
	"go": "Umask",
	"php": "umask",
	"ruby": "File.umask",
	"js": "process.umask",
}

# A mask that leaves others-write open: zero, or an octal value whose last
# digit lacks the 2 bit.
_open_mask(v) if regex.match(`^(0+|0[oO]?[0-7]*[0145])$`, v)

# String literals are blanked, except a umask value written as a string
# (Node's process.umask("0000")), which is unquoted first.
_strip(line) := regex.replace(
	regex.replace(line, `(umask\s*\(\s*)["']([0-7]+)["']`, "${1}${2}"),
	`"(\\.|[^"\\])*"|'(\\.|[^'\\])*'`, `""`,
)

# `old = umask(0); umask(old);` reads the umask, and a zero umask held for a
# few statements around an explicit creation mode (restored in a finally) sets
# that exact mode on purpose. Neither leaves an inherited setting behind.
_assigned(line) := v if {
	m := regex.find_all_string_submatch_n(`^\s*(?:(?:var|let|const|final|my|local|auto)\s+|[A-Za-z_][\w<>\[\]\*\.:]*\s+)?\$?([A-Za-z_]\w*)\s*:?=[^=]`, line, 1)
	count(m) > 0
	v := m[0][1]
}

_restored(lines, i) if {
	v := _assigned(lines[i])
	end := min([count(lines) - 1, i + 12])
	end >= i + 1
	nxt := [k | some k in numbers.range(i + 1, end); trim_space(lines[k]) != ""; not helpers.is_comment_line(lines[k])]
	some n, k in nxt
	n < 8
	regex.match(concat("", [`(?i)umask[\s(]\s*\$?`, v, `\s*\)?`]), lines[k])
}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(content, _umask_gate[lang])
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, _umask_gate[lang])
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(_umask_re[lang], _strip(line), -1)
	_open_mask(m[1])
	not _restored(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": _umask_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── umask in a shell script ──────────────────────────────────────────────

_open_shell_mask(tok) if regex.match(`^[0-7]*[0145]$`, tok)

# Symbolic umask names what is allowed: o=rwx / a=rwx lets others write.
_open_shell_mask(tok) if {
	some clause in split(tok, ",")
	regex.match(`^[ugoa]*[oa][ugoa]*[=+][rwxX]*w`, clause)
}

findings contains finding if {
	some path, content in input.file_contents
	_shell(path)
	contains(content, "umask")
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "umask")
	not helpers.is_comment_line(line)
	some m in regex.find_all_string_submatch_n(`(?:^|[\s;&|(])umask\s+(?:-S\s+)?([^\s;&|)]+)`, regex.replace(line, `"(\\.|[^"\\])*"|'[^']*'`, "Q"), -1)
	_open_shell_mask(m[1])
	not _restored(lines, i)
	finding := {
		"rule_id": metadata.id,
		"message": _umask_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── umask in a systemd unit ──────────────────────────────────────────────

findings contains finding if {
	some path, content in input.file_contents
	_systemd(path)
	contains(content, "UMask")
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "UMask")
	some m in regex.find_all_string_submatch_n(`^\s*UMask\s*=\s*([0-7]+)\s*$`, line, 1)
	_open_shell_mask(m[1])
	finding := {
		"rule_id": metadata.id,
		"message": _umask_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── Windows security descriptors ─────────────────────────────────────────

_null_dacl := `\bSetSecurityDescriptorDacl\s*\([^,]*,\s*(TRUE|true|1)\s*,\s*(NULL|nullptr|0|\(\s*PACL\s*\)\s*(NULL|0))\s*,`

# An allow ACE inherited by children (OI/CI) that gives a broad group write or
# full rights.
_open_sddl := `\(A;[A-Z]*(OI|CI)[A-Z]*;[A-Z0-9x]*(GA|GW|FA|FW|KA|KW|WD|WO|0x1[fF]01[fF]{2})[A-Z0-9x]*;[^;()]*;[^;()]*;(WD|AN|AU|BU|BG|IU|NU)\)`

_sd_ext(path) if {
	some ext in {".c", ".cc", ".cpp", ".cxx", ".cs"}
	endswith(path, ext)
}

_sd_finding(line) if regex.match(_null_dacl, _strip(line))

_sd_finding(line) if regex.match(_open_sddl, line)

findings contains finding if {
	some path, content in input.file_contents
	_sd_ext(path)
	_has_any(content, {"SetSecurityDescriptorDacl", "(A;"})
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	_has_any(line, {"SetSecurityDescriptorDacl", "(A;"})
	not helpers.is_comment_line(line)
	_sd_finding(line)
	finding := {
		"rule_id": metadata.id,
		"message": _acl_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# ── .NET access rules ────────────────────────────────────────────────────

_everyone := `"Everyone"|"(BUILTIN\\\\)?Users"|"Authenticated Users"|"S-1-1-0"|WellKnownSidType\.(WorldSid|AuthenticatedUserSid|BuiltinUsersSid|AnonymousSid)`

_write_rights := `FileSystemRights\.(FullControl|Modify|Write\w*|ChangePermissions|TakeOwnership|CreateFiles|AppendData)|RegistryRights\.(FullControl|WriteKey|SetValue|ChangePermissions|TakeOwnership)`

_rule_stmt(lines, i) := s if {
	end := min([count(lines) - 1, i + 8])
	ends := [j | some j in numbers.range(i, end); contains(lines[j], ";")]
	count(ends) > 0
	s := concat(" ", array.slice(lines, i, ends[0] + 1))
}

_names_everyone(lines, i, stmt) if regex.match(_everyone, stmt)

_names_everyone(lines, i, stmt) if {
	some v in helpers.tainted_names(lines, i, 12, _everyone)
	regex.match(concat("", [`\(\s*`, v, `\s*,`]), stmt)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	_has_any(content, {"FileSystemAccessRule", "RegistryAccessRule"})
	not _is_test(path)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`\bnew\s+(FileSystemAccessRule|RegistryAccessRule)\s*\(`, line)
	not helpers.is_comment_line(line)
	stmt := _rule_stmt(lines, i)
	regex.match(_write_rights, stmt)
	regex.match(`InheritanceFlags\.(ContainerInherit|ObjectInherit)`, stmt)
	not contains(stmt, "AccessControlType.Deny")
	_names_everyone(lines, i, stmt)
	finding := {
		"rule_id": metadata.id,
		"message": _acl_msg,
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
