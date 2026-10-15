package vulnetix.rules.vnx_docker_005

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-DOCKER-005",
	"name": "Privileged container in a Dockerfile, Compose file or Kubernetes manifest",
	"description": "A container is configured to run privileged, which removes the seccomp, AppArmor/SELinux, capability and device isolation between it and the host. Reported: privileged: true (also True or \"true\") on a Compose service (docker-compose*.yml, compose*.yaml, podman-compose); privileged: true directly under a Kubernetes securityContext (containers, initContainers, ephemeral containers, any YAML manifest, Helm template or values file, block or flow style securityContext: {privileged: true}); and in Dockerfiles, a RUN --security=insecure build step, a LABEL RUN= or INSTALL= run command (the podman container runlabel convention) that passes --privileged, and a RUN, CMD or ENTRYPOINT that starts a container with docker/podman/nerdctl run or create --privileged. Not reported: privileged: false or a variable, a privileged key under any other parent (environment, labels, a ConfigMap payload, a PodSecurityPolicy, which permits rather than runs), --privileged=false, --privileged mentioned in comments, echo strings or free-text labels, test and .devcontainer configuration, and documentation. JSON manifests are not scanned.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-005/",
	"languages": ["docker", "kubernetes"],
	"severity": "critical",
	"level": "error",
	"kind": "oci",
	"cwe": [250],
	"capec": ["CAPEC-122"],
	"attack_technique": ["T1611"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["docker", "privilege-escalation", "container-escape"],
}

# ── File kinds ──────────────────────────────────────────────────────────
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

_is_compose(path) if {
	contains(path, "ompose")
	regex.match(`^(docker-|podman-)?compose([._-][a-z0-9_.-]+)?\.ya?ml$`, _base(path))
}

_is_yaml(path) if endswith(path, ".yaml")

_is_yaml(path) if endswith(path, ".yml")

_skip_path(path) if helpers.is_test_path(path)

_skip_path(path) if contains(path, ".devcontainer/")

# ── Dockerfile instruction structure ────────────────────────────────────
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

_start(lines, i) := s if {
	cands := [j | some j in numbers.range(max([0, i - 20]), i); not _continued(lines, j)]
	count(cands) > 0
	s := max(cands)
}

_text(lines, s, i) := concat(" ", [lines[k] | some k in numbers.range(s, i)])

_privileged_flag(line) if {
	regex.match(`--privileged(\s|"|'|,|\\|=true|$)`, line)
	not startswith(trim_space(line), "#")
}

_dfinding(path, i, line, msg) := {
	"rule_id": metadata.id,
	"message": msg,
	"artifact_uri": path,
	"severity": metadata.severity,
	"level": metadata.level,
	"start_line": i + 1,
	"snippet": line,
}

# RUN --security=insecure: the build step runs with full host privileges
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	not _skip_path(path)
	contains(content, "insecure")
	lines := split(content, "\n")
	hd := contains(content, "<<")
	some i, line in lines
	regex.match(`(?i)^\s*(?:ONBUILD\s+)?RUN\s+(?:--\S+\s+)*--security[= ]insecure(\s|$)`, line)
	_instr(lines, i, hd)
	finding := _dfinding(path, i, line, "RUN --security=insecure runs this build step as a privileged container (the security.insecure entitlement): it can reach host devices and kernel interfaces. Remove it, or grant the single capability the step needs")
}

# LABEL RUN="... --privileged ..." / INSTALL=: the image's declared run command
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	not _skip_path(path)
	contains(content, "--privileged")
	lines := split(content, "\n")
	hd := contains(content, "<<")
	some i, line in lines
	_privileged_flag(line)
	s := _start(lines, i)
	regex.match(`(?i)^\s*(?:ONBUILD\s+)?LABEL\s`, lines[s])
	_not_in_heredoc(lines, s, hd)
	regex.match(`(?i)(^|\s)(RUN|INSTALL)\s*=\s*["']?[^"']*--privileged`, line)
	finding := _dfinding(path, i, line, "The image's LABEL run command (podman container runlabel / atomic convention) starts it with --privileged, which disables every container isolation boundary. Declare only the capabilities and devices it needs (--cap-add, --device)")
}

# RUN/CMD/ENTRYPOINT that starts a privileged container
findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	not _skip_path(path)
	contains(content, "--privileged")
	lines := split(content, "\n")
	hd := contains(content, "<<")
	some i, line in lines
	_privileged_flag(line)
	s := _start(lines, i)
	regex.match(`(?i)^\s*(?:ONBUILD\s+)?(RUN|CMD|ENTRYPOINT)\b`, lines[s])
	_not_in_heredoc(lines, s, hd)
	regex.match(`(?i)\b(docker|podman|nerdctl)\b["',\s]+(container["',\s]+)?(run|create)\b`, _text(lines, s, i))
	finding := _dfinding(path, i, line, "This instruction starts a container with --privileged, which disables every isolation boundary between that container and the host. Grant only the capabilities and devices it needs (--cap-add, --device)")
}

# ── YAML ────────────────────────────────────────────────────────────────
_priv_true := `^\s*privileged\s*:\s*("true"|'true'|true|True|TRUE)\s*(#.*)?$`

_indent(l) := count(l) - count(trim_left(l, " "))

# the nearest line above i that is less indented: the key line i is under
_parent(lines, i) := p if {
	i > 0
	ind := _indent(lines[i])
	cands := [j |
		some j in numbers.range(max([0, i - 40]), i - 1)
		t := trim_space(lines[j])
		t != ""
		not startswith(t, "#")
		_indent(lines[j]) < ind
	]
	count(cands) > 0
	p := max(cands)
}

# privileged: true on a Compose service (or a top-level x- extension merged into services)
findings contains finding if {
	some path, content in input.file_contents
	_is_compose(path)
	not _skip_path(path)
	contains(content, "privileged")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "privileged")
	regex.match(_priv_true, line)
	p := _parent(lines, i)
	_service_key(lines, p)
	finding := _dfinding(path, i, line, "privileged: true gives this Compose service every capability and the host's devices, with seccomp and AppArmor/SELinux confinement removed: a compromise of the service is a compromise of the host. Remove it and grant only the cap_add capabilities and devices it needs")
}

_service_key(lines, p) if {
	g := _parent(lines, p)
	regex.match(`^services\s*:\s*$`, trim_right(lines[g], " \t\r"))
}

_service_key(lines, p) if regex.match(`^x-[A-Za-z0-9_-]+\s*:`, lines[p])

# privileged: true directly under a Kubernetes securityContext
findings contains finding if {
	some path, content in input.file_contents
	_is_yaml(path)
	not _skip_path(path)
	contains(content, "securityContext")
	contains(content, "privileged")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "privileged")
	regex.match(_priv_true, line)
	p := _parent(lines, i)
	regex.match(`^\s*(-\s+)?securityContext\s*:\s*$`, lines[p])
	finding := _dfinding(path, i, line, "securityContext.privileged: true runs this container with every capability and the host's devices, with seccomp and AppArmor/SELinux confinement removed: a compromise of the pod is a compromise of the node. Remove it and add only the capabilities it needs under capabilities.add")
}

# securityContext: { privileged: true } written as a YAML flow mapping
findings contains finding if {
	some path, content in input.file_contents
	_is_yaml(path)
	not _skip_path(path)
	regex.match(`securityContext\s*:\s*\{[^}\n]*\bprivileged\s*:`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "privileged")
	regex.match(`^\s*(-\s+)?securityContext\s*:\s*\{(?:[^}]*,)?\s*privileged\s*:\s*("true"|'true'|true|True|TRUE)\s*(,|\})`, line)
	finding := _dfinding(path, i, line, "securityContext.privileged: true runs this container with every capability and the host's devices, with seccomp and AppArmor/SELinux confinement removed: a compromise of the pod is a compromise of the node. Remove it and add only the capabilities it needs under capabilities.add")
}
