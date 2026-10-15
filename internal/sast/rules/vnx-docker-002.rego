package vulnetix.rules.vnx_docker_002

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-DOCKER-002",
	"name": "Dockerfile base image not pinned (:latest or no tag)",
	"description": "A FROM instruction, or a COPY --from that pulls an external image, names an image by :latest or by no tag at all and without an @sha256 digest, so every build can silently receive a different (possibly broken or compromised) image. Reported: FROM node:latest, FROM ubuntu, FROM --platform=... python AS deps, FROM registry:5000/team/base (a port is not a tag), lowercase instructions, FROM ${BASE} when BASE resolves through its ARG default (or ${BASE:-default}) to such an image, COPY --from=composer:latest / --from=vendor/tool, and RUN --mount=from=ghcr.io/astral-sh/uv,... (a bind mount from an external image). Not reported: a tag other than latest (including a variable tag such as node:${NODE_VERSION}), any image pinned by digest (even :latest@sha256:...), scratch, a reference to an earlier stage (FROM build, COPY --from=build, COPY --from=0, RUN --mount=from=build), an image held in an ARG with no default (supplied at build time), FROM/COPY text inside comments, strings and heredocs, test and .devcontainer images, and files that only mention Dockerfiles.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-002/",
	"languages": ["docker"],
	"severity": "medium",
	"level": "warning",
	"kind": "oci",
	"cwe": [829],
	"capec": ["CAPEC-185"],
	"attack_technique": ["T1195.002"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["docker", "supply-chain", "pinning"],
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

_from_re := `(?i)^\s*FROM\s+(?:--[a-z-]+=\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?\s*$`

_copy_from_re := `(?i)^\s*(?:ONBUILD\s+)?COPY\s+(?:--\S+\s+)*?--from=(\S+)`

# ── Image references ────────────────────────────────────────────────────
_strip(s) := trim(s, "\"'")

# the tag of an image reference, "" when it has none
_tag(ref) := t if {
	parts := split(ref, "/")
	last := parts[count(parts) - 1]
	contains(last, ":")
	segs := split(last, ":")
	t := segs[count(segs) - 1]
}

_tag(ref) := "" if {
	parts := split(ref, "/")
	not contains(parts[count(parts) - 1], ":")
}

# tags that name no version and move with every release: latest, lts, stable,
# alpine, slim, ... and their combinations (lts-alpine, alpine-slim)
_floating_word := `(latest|lts|stable|current|edge|rolling|mainline|nightly|alpine|slim|master|main|develop|dev)`

_floating(tag) if regex.match(concat("", [`(?i)^`, _floating_word, `([-.]`, _floating_word, `)*$`]), tag)

# unpinned: no digest, and either no tag or a floating tag. A reference whose
# name part is a variable with no visible tag is unknown, not unpinned.
_unpinned(ref) if {
	not contains(ref, "@")
	_floating(_tag(ref))
}

_unpinned(ref) if {
	not contains(ref, "@")
	_tag(ref) == ""
	parts := split(ref, "/")
	not contains(parts[count(parts) - 1], "$")
	ref != ""
}

_var_re := `^\$\{?([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}?$`

# the value a FROM ${VAR} resolves to through an inline default
_resolve(lines, i, ref) := v if {
	m := regex.find_all_string_submatch_n(_var_re, ref, 1)
	count(m) > 0
	m[0][2] != ""
	v := _strip(m[0][2])
}

# ... or through the ARG default declared above it
_resolve(lines, i, ref) := v if {
	m := regex.find_all_string_submatch_n(_var_re, ref, 1)
	count(m) > 0
	m[0][2] == ""
	name := m[0][1]
	defaults := [d |
		some j in numbers.range(0, i - 1)
		contains(lines[j], name)
		dm := regex.find_all_string_submatch_n(concat("", [`(?i)^\s*ARG\s+`, name, `=(\S+)\s*$`]), lines[j], 1)
		count(dm) > 0
		d := _strip(dm[0][1])
	]
	count(defaults) > 0
	v := defaults[count(defaults) - 1]
}

_effective(lines, i, ref) := ref if not regex.match(_var_re, ref)

_effective(lines, i, ref) := v if {
	regex.match(_var_re, ref)
	v := _resolve(lines, i, ref)
	not contains(v, "$")
}

_aliases(lines) := {lower(m[0][2]) |
	some l in lines
	regex.match(`(?i)\sAS\s`, l)
	m := regex.find_all_string_submatch_n(_from_re, l, 1)
	count(m) > 0
	m[0][2] != ""
}

_msg := "The base image is not pinned: :latest, a floating tag (alpine, slim, lts, stable) or a missing tag pulls whatever the registry serves at build time, so builds are not reproducible and a compromised or breaking image is picked up silently. Pin a version tag and, ideally, the @sha256 digest"

findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	not _skip_path(path)
	regex.match(`(?im)^\s*FROM\s`, content)
	lines := split(content, "\n")
	hd := contains(content, "<<")
	stages := _aliases(lines)
	some i, line in lines
	m := regex.find_all_string_submatch_n(_from_re, line, 1)
	count(m) > 0
	_instr(lines, i, hd)
	ref := _strip(m[0][1])
	lower(ref) != "scratch"
	not lower(ref) in stages
	eff := _effective(lines, i, ref)
	lower(eff) != "scratch"
	_unpinned(eff)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s (image %s)", [_msg, eff]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# RUN --mount=...,from=<external image>,...: the image is pulled to mount it
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	not _skip_path(path)
	contains(content, "--mount=")
	lines := split(content, "\n")
	hd := contains(content, "<<")
	stages := _aliases(lines)
	some i, line in lines
	contains(line, "from=")
	regex.match(`(?i)^\s*(?:ONBUILD\s+)?RUN\s+--`, line)
	_instr(lines, i, hd)
	some mm in regex.find_all_string_submatch_n(`--mount=(\S+)`, line, -1)
	some opt in split(mm[1], ",")
	startswith(lower(opt), "from=")
	ref := _strip(substring(opt, 5, -1))
	not regex.match(`^\d+$`, ref)
	not contains(ref, "$")
	not lower(ref) in stages
	_unpinned(ref)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RUN --mount pulls an external image that is not pinned (%s): :latest, a floating tag or a missing tag changes underneath the build. Pin a version tag and, ideally, the @sha256 digest", [ref]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

# COPY --from=<external image>
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	not _skip_path(path)
	contains(content, "--from=")
	lines := split(content, "\n")
	hd := contains(content, "<<")
	stages := _aliases(lines)
	some i, line in lines
	contains(line, "--from=")
	m := regex.find_all_string_submatch_n(_copy_from_re, line, 1)
	count(m) > 0
	_instr(lines, i, hd)
	ref := _strip(m[0][1])
	not regex.match(`^\d+$`, ref)
	not contains(ref, "$")
	not lower(ref) in stages
	_unpinned(ref)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("COPY --from pulls an external image that is not pinned (%s): :latest, a floating tag or a missing tag changes underneath the build. Pin a version tag and, ideally, the @sha256 digest", [ref]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
