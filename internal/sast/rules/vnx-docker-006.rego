package vulnetix.rules.vnx_docker_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-DOCKER-006",
	"name": "Dockerfile uses ADD instead of COPY for local files",
	"description": "An ADD instruction copies local files or directories that are not archives (ADD . /app, ADD Gemfile Gemfile.lock /app/, ADD --chown=app:app src/ /srv/, the JSON exec form, globs, a source on a continuation line, ONBUILD ADD). For local sources ADD differs from COPY only by its hidden behaviour: any source it recognises as a tar archive (by content, not name) is unpacked into the destination. Use COPY so the instruction does exactly what it says. Not reported: ADD whose local sources are all archives meant to be unpacked (.tar, .tar.gz, .tgz, .tar.bz2, .tar.xz, .tar.zst and similar), remote URL and git sources (VNX-DOCKER-004), a source held in a variable, heredoc sources, COPY, ADD text in comments, labels, strings and heredocs, test and .devcontainer images, and files that only mention Dockerfiles.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-006/",
	"languages": ["docker"],
	"severity": "low",
	"level": "warning",
	"kind": "oci",
	"cwe": [829],
	"capec": ["CAPEC-185"],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["docker", "best-practice", "container"],
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
_continued(lines, i) if {
	i > 0
	endswith(trim_right(lines[i - 1], " \t\r"), "\\")
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

_not_in_heredoc(_, _, false) := true

_not_in_heredoc(lines, i, true) if not _in_heredoc(lines, i)

_instr(lines, i, hd) if {
	not _continued(lines, i)
	_not_in_heredoc(lines, i, hd)
}

_logical(lines, s) := concat(" ", parts) if {
	last := min([count(lines) - 1, s + 8])
	ends := [k | some k in numbers.range(s, last); not endswith(trim_right(lines[k], " \t\r"), "\\")]
	e := _end(ends, last)
	parts := [regex.replace(lines[k], `\\\s*$`, "") |
		some k in numbers.range(s, e)
		not _comment_after_start(lines, s, k)
	]
}

_end(ends, _) := min(ends) if count(ends) > 0

_end(ends, last) := last if count(ends) == 0

_comment_after_start(lines, s, k) if {
	k > s
	startswith(trim_space(lines[k]), "#")
}

_add_re := `(?i)^\s*(?:ONBUILD\s+)?ADD\s+`

_sources(args) := srcs if {
	regex.match(`^\s*\[`, args)
	ops := [m[1] | some m in regex.find_all_string_submatch_n(`"([^"]*)"`, args, -1)]
	count(ops) >= 2
	srcs := array.slice(ops, 0, count(ops) - 1)
}

_sources(args) := srcs if {
	not regex.match(`^\s*\[`, args)
	ops := [t | some t in regex.split(`\s+`, trim_space(args)); t != ""]
	count(ops) >= 2
	srcs := array.slice(ops, 0, count(ops) - 1)
}

_remote(src) if regex.match(`(?i)^(https?|git|ssh)://`, src)

_remote(src) if regex.match(`^git@[A-Za-z0-9.-]+:`, src)

_archive(src) if regex.match(`(?i)\.(tar|tar\.gz|tgz|tar\.bz2|tbz2?|tar\.xz|txz|tar\.zst|tzst|tar\.lz|tar\.lzma|tlz|gz|bz2|xz)$`, src)

# a plain local file or directory: ADD adds nothing but archive extraction
_plain_local(src) if {
	not _remote(src)
	not contains(src, "$")
	not startswith(src, "<<")
	not _archive(src)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	not _skip_path(path)
	regex.match(`(?im)^\s*(ONBUILD\s+)?ADD\s`, content)
	lines := split(content, "\n")
	hd := contains(content, "<<")
	some i, line in lines
	regex.match(_add_re, line)
	_instr(lines, i, hd)
	txt := _logical(lines, i)
	rest := regex.replace(txt, _add_re, "")
	parts := regex.find_all_string_submatch_n(`^((?:\s*--\S+)*)\s*(.*)$`, rest, 1)[0]
	srcs := _sources(parts[2])
	not _any_remote(srcs)
	locals := [s | some s in srcs; _plain_local(s)]
	count(locals) > 0
	src := locals[0]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ADD is used for the local source %s: for local files ADD only adds implicit tar extraction, so a source that turns out to be an archive is unpacked silently. Use COPY for files and directories; keep ADD for archives you mean to extract", [src]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_any_remote(srcs) if {
	some s in srcs
	_remote(s)
}
