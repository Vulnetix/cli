package vulnetix.rules.vnx_sec_023

import rego.v1

metadata := {
	"id": "VNX-SEC-023",
	"name": "GitHub Actions expression injection via event data",
	"description": "Reports a GitHub Actions workflow (.github/workflows/*.yml) or composite action (action.yml) that expands attacker-controlled event data with ${{ }} inside a run: script, on the run: line itself or anywhere in its | or > block, or inside a script: block (actions/github-script, appleboy/ssh-action), on the script: line or in its block. The expression is substituted into the script text before the shell or JavaScript runs, so a crafted value runs commands with the job's token and secrets. Attacker-controlled contexts: github.head_ref; github.event.issue.title/body, pull_request.title/body/head.ref/head.label/head.repo.default_branch, comment.body, review.body, review_comment.body, discussion.title/body, head_commit.message/author/committer name and email, commits[*].message/author/committer, pages[*].page_name, workflow_run.head_branch/head_commit.message/display_title, and toJSON() of the whole event or of an issue, pull request, comment, review, discussion or commit. Not reported: the same expression passed through env: and read as $VAR or process.env (the fix), with: inputs to other actions, if: conditions and concurrency groups, safe contexts (pull_request.number, head.sha, github.sha, github.repository, base.ref), comment lines, and YAML outside a workflow or action file.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-sec-023/",
	"languages": [],
	"severity": "critical",
	"level": "error",
	"kind": "sast",
	"cwe": [77],
	"capec": ["CAPEC-88"],
	"attack_technique": ["T1195.001"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:C/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:C/DI:H/EX:H/EC:N/P:W",
	"tags": ["ci-cd", "github-actions", "supply-chain", "command-injection"],
}

_yaml(path) if endswith(path, ".yml")

_yaml(path) if endswith(path, ".yaml")

_workflow(path) if {
	contains(path, ".github/workflows/")
	_yaml(path)
}

_workflow(path) if regex.match(`(^|/)action\.ya?ml$`, path)

_ctx := `(?:github\.(?:head_ref|event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|head_commit\.(?:message|(?:author|committer)\.(?:name|email))|commits(?:\[\d+\]|\.\*)\.(?:message|(?:author|committer)\.(?:name|email))|pages(?:\[\d+\]|\.\*)\.page_name|workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|(?:author|committer)\.(?:name|email)))))\b|toJSON\(\s*github\.event(?:\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits))?\s*\))`

_expr_re := concat("", [`(?i)\$\{\{[^}]*?\b`, _ctx])

_key_re := `^\s*(?:-\s+)?[A-Za-z_][\w-]*\s*:(?:\s|$)`

_indent(line) := count(line) - count(trim_left(line, " "))

# The expression sits on the run: line itself.
_in_script(_, _, line) if regex.match(`^\s*(?:-\s+)?(?:run|script)\s*:\s*[^|>\s]`, line)

# The expression sits in a block scalar: the nearest less-indented key above
# is run: | (or script: | of actions/github-script).
_in_script(lines, i, line) if {
	i > 0
	ind := _indent(line)
	ks := [k |
		some k in numbers.range(max([0, i - 120]), i - 1)
		l := lines[k]
		trim_space(l) != ""
		_indent(l) < ind
		regex.match(_key_re, l)
	]
	count(ks) > 0
	regex.match(`^\s*(?:-\s+)?(?:run|script)\s*:\s*[|>][-+0-9]*\s*(?:#.*)?$`, lines[max(ks)])
}

findings contains finding if {
	some path, content in input.file_contents
	_workflow(path)
	contains(content, "${{")
	regex.match(concat("", [`(?m)`, _expr_re]), content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "${{")
	regex.match(_expr_re, line)
	not startswith(trim_space(line), "#")
	_in_script(lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "Attacker-controlled github.event data is expanded with ${{ }} inside a run: or github-script block; pass it through env: (TITLE: ${{ github.event.pull_request.title }}) and read \"$TITLE\" instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
