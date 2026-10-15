# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_243

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-243",
	"name": "Creation of chroot Jail Without Changing Working Directory",
	"description": "A chroot() call is not followed, in the same function and within 20 lines, by a change of working directory, so the process keeps a working directory outside the jail and can reach the real file system through relative paths ('../../etc/shadow'). Reported: C/C++ chroot(), Python os.chroot() (or chroot imported from os), Go syscall.Chroot()/unix.Chroot(), Rust fs::chroot()/nix::unistd::chroot() and Ruby Dir.chroot(), with no chdir()/fchdir() (os.chdir, syscall/unix/os.Chdir, std::env::set_current_dir, Dir.chdir) after it. Not reported: a chdir after the chroot, the chdir(dir); chroot(\".\") idiom and chdir(dir); chroot(dir) with the same argument, method calls and wrappers (o->chroot(), my_chroot()), prototypes, comments and string literals. A chdir before the chroot to a different directory does not count, nor does a chdir after it to a relative literal path (chdir(\"work\") moves relative to the old directory, still outside the jail). A Go SysProcAttr Chroot field for a child process is not judged.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-243/",
	"languages": ["c", "cpp", "go", "python", "ruby", "rust"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [243],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["chroot", "cwe-243", "sandbox"],
}

_lang(path) := "c" if regex.match(`\.(?:c|h|cc|cpp|cxx|hpp|hh)$`, path)

_lang(path) := "py" if endswith(path, ".py")

_lang(path) := "go" if endswith(path, ".go")

_lang(path) := "rs" if endswith(path, ".rs")

_lang(path) := "rb" if endswith(path, ".rb")

_chroot_re := {
	"c": `(?:^|[^\w.>:])chroot\s*\(`,
	"py": `(?:\bos\.|(?:^|[^\w.]))chroot\s*\(`,
	"go": `\b(?:syscall|unix)\.Chroot\s*\(`,
	"rs": `(?:\b(?:fs|unistd)::|(?:^|[^\w:.]))chroot\s*\(`,
	"rb": `\bDir\.chroot\b`,
}

_chdir_re := {
	"c": `(?:^|[^\w.>:])f?chdir\s*\(`,
	"py": `(?:\bos\.|(?:^|[^\w.]))f?chdir\s*\(`,
	"go": `\b(?:syscall|unix|os)\.F?[Cc]hdir\s*\(`,
	"rs": `\bset_current_dir\s*\(|(?:^|[^\w.])f?chdir\s*\(`,
	"rb": `\bDir\.chdir\b`,
}

# Start of the next top-level definition: the window stops there.
_boundary := `^(?:\}|def\s|class\s|func\s|fn\s|pub\s+fn\s|end\b|static\s|int\s|void\s)`

_code(line) := c if {
	a := regex.replace(line, `"(?:[^"\\]|\\.)*"`, `""`)
	c := regex.replace(a, `'(?:[^'\\]|\\.)*'`, `''`)
}

_is_comment(line) if helpers.is_comment_line(line)

_end(lines, i) := e if {
	last := min([count(lines) - 1, i + 20])
	stops := [k |
		some k in numbers.range(i + 1, last)
		k > i
		regex.match(_boundary, lines[k])
	]
	e := min(array.concat([last], stops))
}

_start(lines, i) := s if {
	first := max([0, i - 10])
	stops := [k |
		some k in numbers.range(first, i - 1)
		k < i
		regex.match(_boundary, lines[k])
	]
	s := max(array.concat([first], stops))
}

_chdir_after(lines, i, lang) if {
	rest := substring(lines[i], indexof(lower(lines[i]), "chroot"), -1)
	regex.match(_chdir_re[lang], _code(rest))
	not _relative_chdir(rest)
}

# chdir("work") after the chroot moves relative to the old working
# directory, which is still outside the jail: it is not the fix.
_relative_chdir(line) if regex.match(`(?i)(?:chdir|set_current_dir)\s*\(\s*(?:"[^/"][^"]*"|'[^/'][^']*')\s*\)`, line)

_chdir_after(lines, i, lang) if {
	e := _end(lines, i)
	some k in numbers.range(i + 1, e)
	k > i
	not _is_comment(lines[k])
	regex.match(_chdir_re[lang], _code(lines[k]))
	not _relative_chdir(lines[k])
}

_arg(re, line) := a if {
	m := regex.find_all_string_submatch_n(re, line, 1)
	count(m) == 1
	a := trim_space(m[0][1])
}

_chroot_arg(line) := _arg(`(?i)chroot\s*\(\s*([^()]*?)\s*\)`, line)

# chdir(dir) then chroot(".") or chroot(dir): the working directory is
# already the new root.
_chdir_before(lines, i, lang) if {
	ca := _chroot_arg(lines[i])
	s := _start(lines, i)
	some k in numbers.range(s, i - 1)
	k < i
	not _is_comment(lines[k])
	regex.match(_chdir_re[lang], _code(lines[k]))
	da := _arg(`(?i)(?:chdir|set_current_dir)\s*\(\s*([^()]*?)\s*\)`, lines[k])
	_same_root(ca, da)
}

_same_root(ca, da) if ca == da

_same_root(ca, _) if ca in {`"."`, `'.'`}

_c_prototype(code) if regex.match(`\b(?:int|extern\s+int)\s+chroot\s*\(`, code)

_py_bare_ok(lines, code) if regex.match(`\bos\.chroot\s*\(`, code)

_py_bare_ok(lines, _) if {
	some l in lines
	regex.match(`^\s*from\s+os\s+import\s+[^#]*\bchroot\b`, l)
}

_lang_ok("py", lines, code) if _py_bare_ok(lines, code)

_lang_ok("c", _, code) if not _c_prototype(code)

_lang_ok(lang, _, _) if lang in {"go", "rs", "rb"}

findings contains finding if {
	some path, content in input.file_contents
	lang := _lang(path)
	contains(lower(content), "chroot")
	lines := split(content, "\n")
	some i, line in lines
	contains(lower(line), "chroot")
	not _is_comment(line)
	code := _code(line)
	regex.match(_chroot_re[lang], code)
	_lang_ok(lang, lines, code)
	not _chdir_after(lines, i, lang)
	not _chdir_before(lines, i, lang)
	finding := {
		"rule_id": metadata.id,
		"message": "chroot() without a following chdir(\"/\"): the working directory stays outside the jail, so relative paths still reach the real file system. Call chdir(\"/\") right after chroot()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
