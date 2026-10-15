package vulnetix.rules.vnx_docker_007

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-DOCKER-007",
	"name": "Service image without a HEALTHCHECK",
	"description": "The image's final stage runs a long-lived service but declares no HEALTHCHECK, so Docker, Compose and Swarm can only tell whether the process exists, not whether it still answers: a deadlocked or wedged service stays in rotation. A stage counts as a service when it, or an earlier stage it is built FROM, has an EXPOSE instruction or a CMD/ENTRYPOINT that starts a server (nginx, httpd/apache2, php-fpm, gunicorn, uvicorn, uwsgi, hypercorn, daphne, runserver, flask run, rails server, puma, unicorn, node, npm/yarn/pnpm start, java, catalina.sh, dotnet, redis-server, mongod, postgres, mysqld, caddy, traefik, haproxy, envoy, supervisord and similar). The finding is on the final FROM line. Not reported: a final stage with a HEALTHCHECK (HEALTHCHECK NONE is an explicit decision, for example when Kubernetes probes are used), one that inherits a HEALTHCHECK from an earlier stage (up to two levels), base and toolchain images with no service, one-shot CLI and job images (including node/java/dotnet started on a cli, migrate, seed, job, cron, backup or scripts/ entry point with no EXPOSE), a HEALTHCHECK only in a builder stage (it does not carry over, so that is reported), HEALTHCHECK text in comments or heredocs, test and .devcontainer images, and files that only mention Dockerfiles. A HEALTHCHECK defined by an external base image is not visible here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-docker-007/",
	"languages": ["docker"],
	"severity": "low",
	"level": "warning",
	"kind": "oci",
	"cwe": [754],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:L/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:L/DI:H/EX:L/EC:N/P:L",
	"tags": ["docker", "best-practice", "availability", "container"],
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

_froms(lines, hd) := [j |
	some j, l in lines
	regex.match(_from_re, l)
	_instr(lines, j, hd)
]

_image(lines, froms, k) := lower(m[0][1]) if {
	m := regex.find_all_string_submatch_n(_from_re, lines[froms[k]], 1)
}

_alias(lines, froms, k) := lower(m[0][2]) if {
	m := regex.find_all_string_submatch_n(_from_re, lines[froms[k]], 1)
	m[0][2] != ""
}

_stage_end(lines, froms, k) := froms[k + 1] - 1 if k + 1 < count(froms)

_stage_end(lines, froms, k) := count(lines) - 1 if k + 1 == count(froms)

# an instruction matching re inside stage k
_stage_has(lines, froms, k, hd, re) if {
	e := _stage_end(lines, froms, k)
	froms[k] + 1 <= e
	some j in numbers.range(froms[k] + 1, e)
	regex.match(re, lines[j])
	_instr(lines, j, hd)
}

_parent(lines, froms, k) := p if {
	k > 0
	img := _image(lines, froms, k)
	cands := [q | some q in numbers.range(0, k - 1); _alias(lines, froms, q) == img]
	count(cands) > 0
	p := max(cands)
}

# stage k and up to two stages it is built from
_chain(lines, froms, k) := {k} | {p | p := _parent(lines, froms, k)} | {g |
	p := _parent(lines, froms, k)
	g := _parent(lines, froms, p)
}

_hc_re := `(?i)^\s*HEALTHCHECK\s+\S`

_expose_re := `(?i)^\s*EXPOSE\s+\S`

_server_re := `(?i)^\s*(CMD|ENTRYPOINT)\s.*\b(nginx|httpd|apache2(-foreground|ctl)?|php-fpm[0-9.]*|gunicorn|uvicorn|uwsgi|hypercorn|daphne|waitress-serve|runserver|flask["',\s]+run|rails["',\s]+(s|server)|puma|unicorn|rackup|node|nodemon|pm2(-runtime)?|(npm|yarn|pnpm)["',\s]+(run["',\s]+)?(start|serve)|next["',\s]+start|java|catalina\.sh|dotnet|redis-server|mongod|postgres|mysqld|mariadbd|caddy|traefik|haproxy|envoy|supervisord|http-server|serve|streamlit|grafana-server|prometheus|nats-server|rabbitmq-server|memcached|(app|server|wsgi|asgi)\.(py|js|mjs|rb))\b`

_service(lines, froms, k, hd) if {
	some q in _chain(lines, froms, k)
	_stage_has(lines, froms, q, hd, _expose_re)
}

_service(lines, froms, k, hd) if {
	some q in _chain(lines, froms, k)
	e := _stage_end(lines, froms, q)
	froms[q] + 1 <= e
	some j in numbers.range(froms[q] + 1, e)
	regex.match(_server_re, lines[j])
	_instr(lines, j, hd)
	not _one_shot(lines[j])
}

# a generic runtime (node, java, dotnet, python) started on a CLI, migration,
# seed, backup or cron entry point is a job, not a service
_one_shot(line) if {
	not regex.match(`(?i)\b(nginx|httpd|apache2|php-fpm|gunicorn|uvicorn|uwsgi|hypercorn|daphne|runserver|puma|unicorn|caddy|traefik|haproxy|envoy|supervisord|server|serve|start)\b`, line)
	regex.match(`(?i)(\bcli\b|\bmigrat|\bseed|\bjobs?\b|\bcron|\bbackup|\bscripts/)`, line)
}

_has_healthcheck(lines, froms, k, hd) if {
	some q in _chain(lines, froms, k)
	_stage_has(lines, froms, q, hd, _hc_re)
}

findings contains finding if {
	some path, content in input.file_contents
	_is_dockerfile(path)
	not _skip_path(path)
	regex.match(`(?im)^\s*(EXPOSE|CMD|ENTRYPOINT)\s`, content)
	lines := split(content, "\n")
	hd := contains(content, "<<")
	froms := _froms(lines, hd)
	count(froms) > 0
	k := count(froms) - 1
	_service(lines, froms, k, hd)
	not _has_healthcheck(lines, froms, k, hd)
	i := froms[k]
	finding := {
		"rule_id": metadata.id,
		"message": "The image runs a service (EXPOSE or a server CMD/ENTRYPOINT) but its final stage has no HEALTHCHECK, so the container is reported healthy while the process merely exists. Add a HEALTHCHECK that probes the service (or HEALTHCHECK NONE if an orchestrator's probes replace it)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": lines[i],
	}
}
