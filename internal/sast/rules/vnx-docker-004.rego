package vulnetix.rules.vnx_docker_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-DOCKER-004",
	"name": "Dockerfile ADD downloads a remote source without a checksum",
	"description": "An ADD instruction fetches a remote source (an http:// or https:// URL, or a git repository given as https://...git, git://, ssh:// or git@host:) with no --checksum, so whatever the server returns at build time, or a tampered response over plain http, goes into the image unverified. Reported in every ADD form: flags before the source (--chown, --chmod, --link, --keep-git-dir), lowercase instructions, the JSON exec form, a source on a continuation line, and ONBUILD ADD. Not reported: ADD --checksum=sha256:... (BuildKit verifies the download), a git source pinned to a 40-character commit, local sources (VNX-DOCKER-006), a source held in a variable, RUN curl/wget downloads, ADD text inside comments, labels, strings and heredocs, test and .devcontainer images, and files that only mention Dockerfiles.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-004/",
	"languages": ["docker"],
	"severity": "medium",
	"level": "warning",
	"kind": "oci",
	"cwe": [829, 494],
	"capec": ["CAPEC-185"],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["docker", "supply-chain", "integrity", "container"],
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

# the instruction starting at line s, continuation lines joined (comment
# lines inside a continuation are dropped, as the Dockerfile parser does)
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

# the source operands of an ADD instruction (every operand but the last)
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

# a git source pinned to a full commit id
_commit_pinned(src) if regex.match(`#[0-9a-fA-F]{40}(:\S*)?$`, src)

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
	flags := regex.find_all_string_submatch_n(`^((?:\s*--\S+)*)\s*(.*)$`, rest, 1)[0]
	not contains(flags[1], "--checksum=")
	some src in _sources(flags[2])
	_remote(src)
	not _commit_pinned(src)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ADD downloads %s with no integrity check: whatever the server (or anyone on the path, for http) returns at build time goes into the image. Add --checksum=sha256:<digest> (BuildKit), pin a git source to a commit, or download in RUN and verify with sha256sum -c", [src]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
