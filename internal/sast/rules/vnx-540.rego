# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_540

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-540",
	"name": "Inclusion of Sensitive Information in Source Code",
	"description": "A production front-end build is configured to publish its source maps, so the original, unminified source (comments, internal API routes, feature flags and any value an author left in it) is served to every visitor beside the bundle. Reported: webpack devtool set to a source-map variant that embeds or links the source ('source-map', 'inline-source-map', 'eval-source-map', 'cheap-module-source-map'...) in a config whose mode is 'production' (also inside webpack-merge or a ternary) or whose file name says prod, including devtool: isProduction ? 'source-map' : ... where the production branch publishes maps; Vue CLI productionSourceMap: true; Vite build.sourcemap: true or 'inline' (nested or in a one-line build object); Next.js productionBrowserSourceMaps: true; an Angular angular.json production configuration with \"sourceMap\": true; and GENERATE_SOURCEMAP=true in .env.production. Not reported: hidden-source-map and nosources-source-map (no link or no source shipped), devtool false, development configs, sourcemap: 'hidden', CSS dev source maps, values computed at run time, comments and string literals. Secrets written directly into source code are reported by the secrets rules, not here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-540/",
	"languages": ["node"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [540],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["source-maps", "source-code-exposure", "cwe-540"],
}

_base(path) := b if {
	parts := split(path, "/")
	b := lower(parts[count(parts) - 1])
}

_kind(path) := "webpack" if regex.match(`^webpack[\w.-]*\.(c|m)?(js|ts)$`, _base(path))

_kind(path) := "vue" if regex.match(`^vue\.config\.(c|m)?(js|ts)$`, _base(path))

_kind(path) := "vite" if regex.match(`^vite\.config\.[\w.]*(js|ts)$`, _base(path))

_kind(path) := "next" if regex.match(`^next\.config\.(c|m)?(js|ts)$`, _base(path))

_kind(path) := "angular" if _base(path) == "angular.json"

_kind(path) := "env" if regex.match(`^\.env\.(production|prod)(\.local)?$`, _base(path))

_needle := {
	"webpack": "devtool",
	"vue": "productionSourceMap",
	"vite": "sourcemap",
	"next": "productionBrowserSourceMaps",
	"angular": "sourceMap",
	"env": "GENERATE_SOURCEMAP",
}

# The webpack config builds for production.
_webpack_production(path, content) if regex.match(`\bmode\s*:[^,\n}]*['"]production['"]`, content)

_webpack_production(path, content) if {
	contains(_base(path), "prod")
	not regex.match(`\bmode\s*:\s*['"]development['"]`, content)
}

# A key in code (not inside a string literal): everything before it is code
# or a complete quoted string, and the key starts the line or follows { , or
# whitespace.
_key(k) := concat("", [`^(?:[^'"\x60]|'[^']*'|"[^"]*")*?(?:^|[{,\s])`, k, `\s*:\s*`])

_leaky_devtool(v) if {
	contains(v, "source-map")
	not contains(v, "hidden")
	not contains(v, "nosources")
}

_exposes("webpack", lines, i, line) if {
	m := regex.find_all_string_submatch_n(concat("", [_key("devtool"), `['"]([^'"]+)['"]`]), line, 1)
	count(m) > 0
	_leaky_devtool(m[0][1])
}

# devtool: isProduction ? 'source-map' : 'eval-...' (the branch taken in
# production is the first for a prod flag and the second for a dev flag).
_exposes("webpack", lines, i, line) if {
	m := regex.find_all_string_submatch_n(concat("", [_key("devtool"), `!?\s*([\w.]+)\s*\?\s*('[^']*'|"[^"]*"|\w+)\s*:\s*('[^']*'|"[^"]*"|\w+)`]), line, 1)
	count(m) > 0
	v := _prod_branch(m[0][1], m[0][2], m[0][3], line)
	_leaky_devtool(v)
}

_prod_branch(cond, a, _, line) := a if {
	regex.match(`(?i)prod`, cond)
	not regex.match(`devtool\s*:\s*!`, line)
}

_prod_branch(cond, _, b, _) := b if {
	regex.match(`(?i)dev`, cond)
	not regex.match(`(?i)prod`, cond)
}

_exposes("vue", lines, i, line) if regex.match(concat("", [_key("productionSourceMap"), `true\b`]), line)

_exposes("next", lines, i, line) if regex.match(concat("", [_key("productionBrowserSourceMaps"), `true\b`]), line)

_exposes("env", lines, i, line) if regex.match(`^\s*GENERATE_SOURCEMAP\s*=\s*['"]?true\b`, line)

# Vite: `sourcemap: true` whose nearest enclosing object key is `build`.
_exposes("vite", lines, i, line) if {
	regex.match(`^\s*sourcemap\s*:\s*(true\b|['"]inline['"])`, line)
	_enclosing_key(lines, i, `^\s*(\w+)\s*:\s*\{\s*$`) == "build"
}

# Vite, inline: build: { outDir: 'dist', sourcemap: true }
_exposes("vite", lines, i, line) if {
	regex.match(concat("", [_key("build"), `\{[^}]*\bsourcemap\s*:\s*(true\b|['"]inline['"])`]), line)
}

# Angular: `"sourceMap": true` inside the "production" configuration.
_exposes("angular", lines, i, line) if {
	regex.match(`^\s*"sourceMap"\s*:\s*true\b`, line)
	_enclosing_key(lines, i, `^\s*"(\w+)"\s*:\s*\{\s*$`) == "production"
}

# The key of the nearest object opened above line i (within 20 lines) at a
# smaller indent than line i.
_enclosing_key(lines, i, key_re) := k if {
	ind := count(lines[i]) - count(trim_left(lines[i], " \t"))
	opens := [j |
		some j in numbers.range(max([0, i - 20]), i - 1)
		regex.match(key_re, lines[j])
		count(lines[j]) - count(trim_left(lines[j], " \t")) < ind
	]
	count(opens) > 0
	m := regex.find_all_string_submatch_n(key_re, lines[opens[count(opens) - 1]], 1)
	k := m[0][1]
}

findings contains finding if {
	some path, content in input.file_contents
	kind := _kind(path)
	contains(content, _needle[kind])
	not helpers.is_test_path(path)
	_production_ok(kind, path, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, _needle[kind])
	not helpers.is_comment_line(line)
	_exposes(kind, lines, i, line)
	finding := {
		"rule_id": metadata.id,
		"message": "The production build publishes source maps, so the original front-end source, with its comments, internal routes and any value left in it, is downloadable by every visitor. Disable public source maps for production (devtool: false or 'hidden-source-map' with the maps uploaded privately to your error tracker)",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}

_production_ok("webpack", path, content) if _webpack_production(path, content)

_production_ok(kind, _, _) if kind != "webpack"
