# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_267

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-267",
	"name": "Privilege Defined With Unsafe Actions",
	"description": "A Linux capability that is equivalent to root is granted: CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_PTRACE, CAP_SYS_RAWIO, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_SETFCAP or CAP_BPF, or every capability at once. Each one lets its holder do far more than the task it was given for (mount filesystems, load kernel modules, read any process's memory, bypass every file permission), so the privilege is defined with unsafe actions. Reported in C and C++: libcap cap_set_flag(..., CAP_SET) (also broken across lines) whose capability list names one (inline, or in a cap_value_t array or scalar initialised in the 40 lines above), cap_from_text(\"cap_sys_admin+ep\") and other text forms that add one (or \"all=eip\" / \"=ep\"), libcap-ng capng_update/capng_updatev(CAPNG_ADD, ...) and prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, ...); in shell scripts and Dockerfiles: setcap granting one to a file (cap_x+ep, cap_x=+ep, comma lists, quoted) and capsh --caps=/--addamb=/--inh= naming one; in systemd .service units: AmbientCapabilities= naming one. Not reported: setcap or capsh text printed by echo or printf, capsh --drop, CapabilityBoundingSet= (a limit, not a grant), checks (capable(), ns_capable(), cap_get_flag), drops (CAP_CLEAR, CAPNG_DROP, PR_CAP_AMBIENT_LOWER, PR_CAPBSET_DROP, setcap -r), narrow capabilities (CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_NET_ADMIN), and the calls in comments or string literals. Container capability grants (--cap-add, securityContext) are left to the IaC rules.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-267/",
	"languages": ["c", "cpp", "bash", "docker", "generic"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [267],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["privilege-unsafe", "capabilities", "cwe-267"],
}

_caps := `SYS_ADMIN|SYS_MODULE|SYS_PTRACE|SYS_RAWIO|DAC_OVERRIDE|DAC_READ_SEARCH|SETFCAP|BPF`

_cap_const_re := concat("", [`\bCAP_(?:`, _caps, `)\b`])

# Text form (cap_from_text, setcap): a root-equivalent name, or "all", in a
# clause that adds the capability (+e, +p, =eip ...), or a bare "=ep" (all).
_cap_text_re := concat("", [`(?i)(?:\bcap_(?:`, _caps, `)\b|(?:^|[\s,'"])all\b)[\w,\s]*[+=]\+?\s*[eip]*[ep]|(?:^|['"\s])=\s*[eip]*[ep]\b`])

_c_file(path) if {
	some ext in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"}
	endswith(path, ext)
}

_shell_file(path) if regex.match(`(?i)(\.(sh|bash|zsh)$|dockerfile|containerfile)`, path)

# String literals blanked, so a quoted example is not a call.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `'(\\.|[^'\\])*'`, `''`)

_finding(path, i, line) := {
	"rule_id": metadata.id,
	"message": "Root-equivalent Linux capability granted (CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_PTRACE, CAP_SYS_RAWIO, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_SETFCAP, CAP_BPF or all): its holder can do far more than this task needs. Grant the narrowest capability that covers the operation, or move the operation into a small privileged helper",
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# cap_set_flag(caps, which, n, list, CAP_SET): the list names a dangerous cap.
_grants(lines, i, c) if {
	regex.match(`\bcap_set_flag\s*\(.*\bCAP_SET\s*\)`, c)
	regex.match(_cap_const_re, c)
}

_grants(lines, i, c) if {
	m := regex.find_all_string_submatch_n(`\bcap_set_flag\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*&?\s*([A-Za-z_]\w*)\s*,\s*CAP_SET\s*\)`, c, 1)
	count(m) > 0
	name := m[0][1]
	decl_re := concat("", [`\b`, name, `\s*\[[^\]]*\]\s*=\s*\{`])
	some j in numbers.range(max([0, i - 40]), i - 1)
	regex.match(decl_re, lines[j])
	init := concat("\n", array.slice(lines, j, min([i, j + 8])))
	body := regex.find_n(`(?s)^[^}]*`, init, 1)
	regex.match(_cap_const_re, body[0])
}

# cap_set_flag(caps, which, 1, &v, CAP_SET) with cap_value_t v = CAP_SYS_ADMIN; above.
_grants(lines, i, c) if {
	m := regex.find_all_string_submatch_n(`\bcap_set_flag\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*&\s*([A-Za-z_]\w*)\s*,\s*CAP_SET\s*\)`, c, 1)
	count(m) > 0
	decl_re := concat("", [`\b`, m[0][1], `\s*=\s*CAP_(?:`, _caps, `)\b`])
	some j in numbers.range(max([0, i - 40]), i - 1)
	regex.match(decl_re, lines[j])
}

_grants(_, _, c) if {
	regex.match(`\bcapng_updatev?\s*\(\s*CAPNG_ADD\b`, c)
	regex.match(_cap_const_re, c)
}

_grants(_, _, c) if {
	regex.match(`\bPR_CAP_AMBIENT_RAISE\b`, c)
	regex.match(_cap_const_re, c)
}

# A call broken after its opening parenthesis or a comma continues on the next two lines.
_joined(_, _, c) := c if not regex.match(`[(,|]\s*$`, c)

_joined(lines, i, c) := concat(" ", array.concat([trim_space(c)], [trim_space(_code(l)) | some l in array.slice(lines, i + 1, i + 3)])) if {
	regex.match(`[(,|]\s*$`, c)
}

findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	regex.match(`cap_set_flag|capng_update|PR_CAP_AMBIENT_RAISE`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`cap_set_flag|capng_update|PR_CAP_AMBIENT_RAISE`, line)
	not helpers.is_comment_line(line)
	_grants(lines, i, _joined(lines, i, _code(line)))
	finding := _finding(path, i, line)
}

# cap_from_text("cap_sys_admin+ep"): the call is code, the capability text is its argument.
findings contains finding if {
	some path, content in input.file_contents
	_c_file(path)
	contains(content, "cap_from_text")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "cap_from_text")
	not helpers.is_comment_line(line)
	regex.match(`\bcap_from_text\s*\(\s*""`, _code(line))
	m := regex.find_all_string_submatch_n(`\bcap_from_text\s*\(\s*"([^"]*)"`, line, 1)
	count(m) > 0
	regex.match(_cap_text_re, m[0][1])
	finding := _finding(path, i, line)
}

# setcap <caps> <file> in a shell script or a Dockerfile RUN.
findings contains finding if {
	some path, content in input.file_contents
	_shell_file(path)
	contains(content, "setcap")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "setcap")
	not helpers.is_comment_line(line)
	not regex.match(`(?:^|[\s;&|(])(?:echo|printf|log|info|warn)\b[^;&|]*\bsetcap\b`, line)
	m := regex.find_all_string_submatch_n(`(?:^|[\s;&|(])setcap\s+((?:-[nqv]\s+\S+\s+|-[qv]\s+)*)(['"]?[^\s'"]+['"]?)`, line, 1)
	count(m) > 0
	not startswith(m[0][2], "-")
	regex.match(_cap_text_re, m[0][2])
	finding := _finding(path, i, line)
}

# capsh --caps="cap_sys_ptrace+eip" / --addamb=cap_sys_admin / --inh=... in a
# shell script or Dockerfile. --drop is a removal.
findings contains finding if {
	some path, content in input.file_contents
	_shell_file(path)
	contains(content, "capsh")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "capsh")
	not helpers.is_comment_line(line)
	regex.match(`(?:^|[\s;&|(])capsh\s`, line)
	not regex.match(`(?:^|[\s;&|(])(?:echo|printf|log|info|warn)\b[^;&|]*\bcapsh\b`, line)
	_capsh_grants(line)
	finding := _finding(path, i, line)
}

_capsh_grants(line) if {
	some m in regex.find_all_string_submatch_n(`--caps=["']?([^"'\s]+)`, line, -1)
	regex.match(_cap_text_re, m[1])
}

_capsh_grants(line) if {
	some m in regex.find_all_string_submatch_n(`--(?:addamb|inh)=["']?([^"'\s]+)`, line, -1)
	regex.match(concat("", [`(?i)\bcap_(?:`, _caps, `)\b`]), m[1])
}

# systemd AmbientCapabilities= granting a root-equivalent capability to the
# service's (non-root) user. CapabilityBoundingSet= only limits, so it is not judged.
findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".service")
	contains(content, "AmbientCapabilities")
	lines := split(content, "\n")
	some i, line in lines
	m := regex.find_all_string_submatch_n(`^\s*AmbientCapabilities\s*=\s*([^~\s].*)$`, line, 1)
	count(m) > 0
	regex.match(concat("", [`(?i)\bCAP_(?:`, _caps, `)\b`]), m[0][1])
	finding := _finding(path, i, line)
}
