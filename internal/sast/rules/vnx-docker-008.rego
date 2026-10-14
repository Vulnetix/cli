package vulnetix.rules.vnx_docker_008

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-DOCKER-008",
	"name": "Dockerfile OS package install without version pinning",
	"description": "A RUN step installs operating-system packages without pinning their versions, so each build silently takes whatever the mirror serves that day: builds are not reproducible and a changed or compromised package version enters the image unreviewed. Reported per install command, wherever it sits in the RUN (after &&, after DEBIAN_FRONTEND=..., inside if/then, on a continuation line, inside a RUN heredoc, ONBUILD RUN), when at least one named package has no version: apt-get/apt/aptitude install (pin pkg=version), apk add (pkg=, pkg~, pkg>, pkg<), yum/dnf/microdnf/tdnf install (pkg-1.2.3 or pkg=), and zypper install/in (pkg=, pkg>=). Options are understood, including those that take a value (-o Dpkg::Options::=..., -t release, --virtual name, --setopt, --enablerepo), so an = inside an option is not mistaken for a pin. Not reported: commands whose every package is pinned, local package files (./x.deb, /tmp/x.rpm), package lists held in a variable or produced by $(...)/xargs, apt-get update/upgrade/remove and install -f, yum localinstall and rpm -i, language package managers (pip, npm, gem; other rules), install text in comments, labels and COPY heredocs, test and .devcontainer images, and files that only mention Dockerfiles.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-008/",
	"languages": ["docker"],
	"severity": "low",
	"level": "warning",
	"kind": "oci",
	"cwe": [1357],
	"capec": ["CAPEC-538"],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["docker", "supply-chain", "reproducibility", "container"],
}

# ── Dockerfile detection ────────────────────────────────────────────────
_base(path) := lower(b) if {
	parts := split(path, "/")
	b := parts[count(parts) - 1]
}

# cheap substring test first: most paths are not Dockerfiles
_df_word(path) if contains(path, "ockerfile")

_df_word(path) if contains(path, "ontainerfile")

_df_word(path) if contains(path, "OCKERFILE")

_df_word(path) if contains(path, "ONTAINERFILE")

_is_dockerfile(path) if {
	_df_word(path)
	b := _base(path)
	regex.match(`^(dockerfile|containerfile)([._-][a-z0-9_.-]*)?$|[._-](dockerfile|containerfile)$`, b)
	not regex.match(`\.(go|py|pyc|js|mjs|cjs|ts|tsx|jsx|rs|java|kt|kts|rb|php|cs|c|h|cc|cpp|hpp|swift|scala|json|ya?ml|toml|ini|cfg|md|rst|txt|sh|bash|ps1|bat|dockerignore|bak|orig|rej|lock|xml|html?|tf|hcl|rego|snap|golden|diff|patch|log)$`, b)
}

_skip_path(path) if helpers.is_test_path(path)

_skip_path(path) if contains(path, ".devcontainer/")

# ── Instruction structure ───────────────────────────────────────────────
_ends_bs(l) if endswith(trim_right(l, " \t\r"), "\\")

_continued(lines, i) if {
	i > 0
	_ends_bs(lines[i - 1])
}

_start(lines, i) := s if {
	cands := [j | some j in numbers.range(max([0, i - 40]), i); not _continued(lines, j)]
	count(cands) > 0
	s := max(cands)
}

_run_re := `(?i)^\s*(?:ONBUILD\s+)?RUN\b`

# line i is part of a RUN instruction (its first line or a continuation)
_in_run(lines, i) if {
	s := _start(lines, i)
	regex.match(_run_re, lines[s])
	not _in_heredoc(lines, s)
}

# ... or a line of a RUN heredoc script
_in_run(lines, i) if {
	i > 0
	some j in numbers.range(max([0, i - 60]), i - 1)
	contains(lines[j], "<<")
	regex.match(_run_re, lines[j])
	some m in regex.find_all_string_submatch_n(`<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?`, lines[j], -1)
	not _heredoc_closed(lines, j, i, m[1])
}

_in_heredoc(lines, i) if {
	i > 0
	some j in numbers.range(max([0, i - 60]), i - 1)
	contains(lines[j], "<<")
	some m in regex.find_all_string_submatch_n(`<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?`, lines[j], -1)
	not _heredoc_closed(lines, j, i, m[1])
}

_heredoc_closed(lines, j, i, delim) if {
	some k in numbers.range(j + 1, i)
	trim_space(lines[k]) == delim
}

# the continuation lines after i, comment lines dropped, joined
_tail(lines, i) := "" if not _ends_bs(lines[i])

_tail(lines, i) := concat(" ", parts) if {
	_ends_bs(lines[i])
	last := min([count(lines) - 1, i + 60])
	i + 1 <= last
	ends := [k |
		some k in numbers.range(i + 1, last)
		not helpers.is_comment_line(lines[k])
		not _ends_bs(lines[k])
	]
	e := _first(ends, last)
	parts := [regex.replace(lines[k], `\\\s*$`, "") |
		some k in numbers.range(i + 1, e)
		not helpers.is_comment_line(lines[k])
	]
}

_first(ends, _) := min(ends) if count(ends) > 0

_first(ends, last) := last if count(ends) == 0

# ── Install commands ────────────────────────────────────────────────────
_opt := `(?:-o\s+\S+|--?[A-Za-z][-\w]*(?:=\S+)?)`

_cmd_res := {
	"apt": concat("", [`\b(?:apt-get|apt|aptitude)\s+(?:`, _opt, `\s+)*install\b([^&;|]*)([&;|]?)`]),
	"apk": concat("", [`\bapk\s+(?:`, _opt, `\s+)*add\b([^&;|]*)([&;|]?)`]),
	"rpm": concat("", [`\b(?:yum|dnf|microdnf|tdnf)\s+(?:`, _opt, `\s+)*install\b([^&;|]*)([&;|]?)`]),
	"zypper": concat("", [`\bzypper\s+(?:`, _opt, `\s+)*(?:install|in)\b([^&;|]*)([&;|]?)`]),
}

# options whose value is the next word
_arg_opts := {
	"-o", "-t", "-c", "--target-release", "--option", "--config-file", "--virtual", "--repository", "-X",
	"--root", "-p", "--arch", "--keys-dir", "--cache-dir", "--repositories-file", "--enablerepo",
	"--disablerepo", "--setopt", "--installroot", "--releasever", "--repo", "--repofrompath", "--config",
	"--exclude", "-x", "-r", "--from", "--type",
}

# the segment of the command after the subcommand, through continuation lines
_segment(lines, i, m) := m[1] if m[2] != ""

_segment(lines, i, m) := m[1] if {
	m[2] == ""
	not _ends_bs(lines[i])
}

_segment(lines, i, m) := concat(" ", [regex.replace(m[1], `\\\s*$`, ""), t[0][1]]) if {
	m[2] == ""
	_ends_bs(lines[i])
	t := regex.find_all_string_submatch_n(`^([^&;|]*)`, _tail(lines, i), 1)
}

_clean(t) := trim(t, "\"'()\\")

# the package operands of an install segment
_packages(seg) := [p |
	cut := regex.split(`\s\d?[<>]`, concat("", [" ", seg]))[0]
	toks := [t | some t in regex.split(`\s+`, trim_space(cut)); t != ""]
	some k, raw in toks
	not startswith(raw, "-")
	not _after_arg_opt(toks, k)
	p := _clean(raw)
	p != ""
	not contains(p, "$")
	not regex.match(`^(\.|/|~)|\.(deb|rpm|apk)$|^[a-z]+://`, p)
]

_after_arg_opt(toks, k) if {
	k > 0
	toks[k - 1] in _arg_opts
}

_pinned("apt", p) if contains(p, "=")

_pinned("apk", p) if regex.match(`[=~<>]`, p)

_pinned("rpm", p) if contains(p, "=")

_pinned("rpm", p) if regex.match(`-(\d+:)?\d+(\.\d+)+`, p)

_pinned("zypper", p) if regex.match(`[=<>]`, p)

_mgr_word := `(?i)\b(apt-get|apt|aptitude|apk|yum|dnf|microdnf|tdnf|zypper)\s`

findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	not _skip_path(path)
	regex.match(`(?m)\b(apt-get|apt|aptitude|apk|yum|dnf|microdnf|tdnf|zypper)\s`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(_mgr_word, line)
	not helpers.is_comment_line(line)
	_in_run(lines, i)
	some mgr, re in _cmd_res
	some m in regex.find_all_string_submatch_n(re, line, -1)
	seg := _segment(lines, i, m)
	not contains(seg, "$(")
	not contains(seg, "`")
	pkgs := _packages(seg)
	loose := [p | some p in pkgs; not _pinned(mgr, p)]
	count(loose) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Packages installed without a pinned version (%s): every build takes whatever the mirror serves that day. Pin each package (apt: pkg=1.2.3-1, apk: pkg=1.2.3-r0, yum/dnf: pkg-1.2.3) and refresh the pins deliberately", [concat(", ", loose)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
