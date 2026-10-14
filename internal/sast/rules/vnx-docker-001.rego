package vulnetix.rules.vnx_docker_001

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-DOCKER-001",
	"name": "Dockerfile final stage runs as root",
	"description": "The stage that becomes the image (the last FROM) runs as root: it has no USER instruction, or its last USER is root (USER root, USER 0, USER 0:0, the Windows ContainerAdministrator, case-insensitive), or it is built FROM an earlier stage whose last USER is root. USER does not carry across FROM, so a USER set only in a builder stage leaves the runtime stage as root; the finding is on the last FROM line, or on the USER root line. Not reported: a final stage whose last USER is any other name, uid or variable; a final stage built FROM an earlier stage (up to two levels) that set a non-root USER; base images that are non-root by default (a nonroot or rootless tag such as gcr.io/distroless/*:nonroot, cgr.dev/chainguard images other than -dev, bitnami images); USER text inside comments and heredocs; .devcontainer and test images; and files that only mention Dockerfiles (dockerfile.go, render_dockerfile.py). A USER set at deploy time (compose user:, Kubernetes runAsUser) is not visible here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-001/",
	"languages": ["docker"],
	"severity": "medium",
	"level": "warning",
	"kind": "oci",
	"cwe": [250],
	"capec": ["CAPEC-69"],
	"attack_technique": ["T1611"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["docker", "least-privilege", "container"],
}

# ── Dockerfile detection ────────────────────────────────────────────────
# Dockerfile, Dockerfile.prod, Dockerfile-dev, api.dockerfile, Containerfile;
# not source or data files whose name merely contains the word.
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

_image(lines, froms, k) := lower(m[0][1]) if {
	m := regex.find_all_string_submatch_n(_from_re, lines[froms[k]], 1)
}

_alias(lines, froms, k) := lower(m[0][2]) if {
	m := regex.find_all_string_submatch_n(_from_re, lines[froms[k]], 1)
	m[0][2] != ""
}

_stage_end(lines, froms, k) := froms[k + 1] - 1 if k + 1 < count(froms)

_stage_end(lines, froms, k) := count(lines) - 1 if k + 1 == count(froms)

_users(lines, froms, k, hd) := [j |
	e := _stage_end(lines, froms, k)
	froms[k] + 1 <= e
	some j in numbers.range(froms[k] + 1, e)
	regex.match(`(?i)^\s*USER\s+\S`, lines[j])
	_instr(lines, j, hd)
]

_user_value(line) := v if {
	m := regex.find_all_string_submatch_n(`(?i)^\s*USER\s+(\S+)`, line, 1)
	v := m[0][1]
}

# root, uid 0, and the Windows container administrator account
_is_root(v) if regex.match(`(?i)^(root|0|containeradministrator)(:\S*)?$`, v)

# own state of a stage: "nonroot", "root" or "unset"
_own(lines, froms, k, hd) := "unset" if count(_users(lines, froms, k, hd)) == 0

_own(lines, froms, k, hd) := s if {
	us := _users(lines, froms, k, hd)
	count(us) > 0
	last := us[count(us) - 1]
	s := _root_state(_user_value(lines[last]))
}

_root_state(v) := "root" if _is_root(v)

_root_state(v) := "nonroot" if not _is_root(v)

# images whose default user is not root
_nonroot_image(img) if regex.match(`(nonroot|rootless)`, img)

_nonroot_image(img) if {
	regex.match(`^cgr\.dev/chainguard/`, img)
	not regex.match(`-dev(@|$)`, img)
}

_nonroot_image(img) if regex.match(`^(docker\.io/)?bitnami/`, img)

# the earlier stage this stage is built FROM, if any
_parent(lines, froms, k) := p if {
	k > 0
	img := _image(lines, froms, k)
	cands := [q | some q in numbers.range(0, k - 1); _alias(lines, froms, q) == img]
	count(cands) > 0
	p := max(cands)
}

# the stage resolves to a non-root user through its own USER, its base image,
# or up to two earlier stages it is built from
_ok(lines, froms, k, hd) if _own(lines, froms, k, hd) == "nonroot"

_ok(lines, froms, k, hd) if {
	_own(lines, froms, k, hd) == "unset"
	_nonroot_image(_image(lines, froms, k))
}

_ok(lines, froms, k, hd) if {
	_own(lines, froms, k, hd) == "unset"
	p := _parent(lines, froms, k)
	_ok1(lines, froms, p, hd)
}

_ok1(lines, froms, k, hd) if _own(lines, froms, k, hd) == "nonroot"

_ok1(lines, froms, k, hd) if {
	_own(lines, froms, k, hd) == "unset"
	_nonroot_image(_image(lines, froms, k))
}

_ok1(lines, froms, k, hd) if {
	_own(lines, froms, k, hd) == "unset"
	p := _parent(lines, froms, k)
	_own(lines, froms, p, hd) == "nonroot"
}

_ok1(lines, froms, k, hd) if {
	_own(lines, froms, k, hd) == "unset"
	p := _parent(lines, froms, k)
	_own(lines, froms, p, hd) == "unset"
	_nonroot_image(_image(lines, froms, p))
}

_froms(lines, hd) := [j |
	some j, l in lines
	regex.match(_from_re, l)
	_instr(lines, j, hd)
]

# the last USER of the final stage is root
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	not _skip_path(path)
	regex.match(`(?im)^\s*USER\s+(root|0|containeradministrator)\b`, content)
	lines := split(content, "\n")
	hd := contains(content, "<<")
	froms := _froms(lines, hd)
	count(froms) > 0
	k := count(froms) - 1
	_own(lines, froms, k, hd) == "root"
	us := _users(lines, froms, k, hd)
	i := us[count(us) - 1]
	finding := {
		"rule_id": metadata.id,
		"message": "The last USER of the image's final stage is root, so the container runs as root. Switch to an unprivileged user (USER 10001 or a named user) after the steps that need root",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}

# the final stage never sets a user and inherits none
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	not _skip_path(path)
	regex.match(`(?im)^\s*FROM\s`, content)
	lines := split(content, "\n")
	hd := contains(content, "<<")
	froms := _froms(lines, hd)
	count(froms) > 0
	k := count(froms) - 1
	_own(lines, froms, k, hd) == "unset"
	not _ok(lines, froms, k, hd)
	i := froms[k]
	finding := {
		"rule_id": metadata.id,
		"message": "The image's final stage has no USER instruction (a USER in an earlier stage does not carry over), so the container runs as root. Create an unprivileged user and add USER <uid> before CMD/ENTRYPOINT",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}
