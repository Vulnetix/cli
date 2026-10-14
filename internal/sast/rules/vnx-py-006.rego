package vulnetix.rules.vnx_py_006

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-PY-006",
	"name": "Django DEBUG=True",
	"description": "A Django settings module turns DEBUG on for the deployment it configures: a top-level DEBUG = True, or DEBUG read from the environment with True as the default when the variable is unset (os.environ.get(\"DEBUG\", True), os.getenv(\"DEBUG\", \"True\") == \"True\", env.bool(\"DEBUG\", default=True), config(\"DEBUG\", default=True)). DEBUG pages expose tracebacks, local variables, settings and SQL to any visitor. A settings module is settings.py, settings_<name>.py / <name>_settings.py, or any module of a settings/ package; settings.py must look like Django (INSTALLED_APPS, ROOT_URLCONF, MIDDLEWARE, SECRET_KEY, ALLOWED_HOSTS, DATABASES or a django import). Not reported: development, local, test and CI settings modules (dev.py, local.py, settings_test.py), a base/common module of a settings package whose sibling module sets DEBUG to something other than True, DEBUG = True inside an if block, environment reads defaulting to False, other names such as DEBUG_TOOLBAR or TEMPLATE_DEBUG, test paths, and non-Django settings.py files.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-py-006/",
	"languages": ["python"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [489],
	"capec": ["CAPEC-116"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["django", "config", "debug"],
}

_base(path) := parts[count(parts) - 1] if parts := split(path, "/")

_parent(path) := parts[count(parts) - 2] if {
	parts := split(path, "/")
	count(parts) > 1
}

_dir(path) := concat("/", array.slice(parts, 0, count(parts) - 1)) if {
	parts := split(path, "/")
	count(parts) > 1
}

_dir(path) := "." if not contains(path, "/")

_in_settings_pkg(path) if _parent(path) == "settings"

_settings_module(path, _) if {
	_in_settings_pkg(path)
	_base(path) != "__init__.py"
}

_settings_module(path, content) if {
	regex.match(`^(?:settings|settings_\w+|\w+_settings)\.py$`, _base(path))
	_django(content)
}

_settings_module(path, content) if {
	_base(path) == "__init__.py"
	_in_settings_pkg(path)
	_django(content)
}

_django(content) if regex.match(`(?m)^\s*(?:INSTALLED_APPS|ROOT_URLCONF|MIDDLEWARE|SECRET_KEY|ALLOWED_HOSTS|DATABASES)\s*=|\bdjango\b`, content)

# Modules meant for a developer's machine, tests or CI.
_dev_module(path) if regex.match(`(?i)^(?:settings_|.*_)?(?:dev|devel|develop|development|local|test|tests|testing|ci|debug|sandbox)(?:_\w+)?(?:_settings)?\.py$`, _base(path))

# A sibling module of the settings package sets DEBUG to something else: a
# base module's default is overridden for deployment.
_overridden(path) if {
	_in_settings_pkg(path)
	dir := _dir(path)
	some other, c in input.file_contents
	other != path
	endswith(other, ".py")
	_dir(other) == dir
	not _dev_module(other)
	regex.match(`(?m)^DEBUG\s*=`, c)
	not _debug_on_text(c)
}

_debug_on_text(c) if regex.match(`(?m)^DEBUG\s*=\s*True\b`, c)

_debug_on_text(c) if regex.match(concat("", ["(?m)", _env_true]), c)

_env_true := `^DEBUG\s*(?::\s*bool\s*)?=.*\b(?:get|getenv|bool|config|env)\s*\(\s*["']\w+["']\s*,\s*(?:default\s*=\s*)?(?:True|["'](?:1|[Tt]rue|TRUE|[Yy]es|on)["'])\s*[,)]`

_debug_on(line) if regex.match(`^DEBUG\s*(?::\s*bool\s*)?=\s*True\b`, line)

_debug_on(line) if regex.match(_env_true, line)

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".py")
	contains(content, "DEBUG")
	regex.match(`(?m)^DEBUG\s*(?::\s*bool\s*)?=`, content)
	_settings_module(path, content)
	not _dev_module(path)
	not helpers.is_test_path(path)
	not _overridden(path)
	lines := split(content, "\n")
	some i, line in lines
	startswith(line, "DEBUG")
	_debug_on(line)
	finding := {
		"rule_id": metadata.id,
		"message": "Django DEBUG is enabled (or defaults to on) in a deployment settings module; set DEBUG = False and read it from the environment with a False default",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
