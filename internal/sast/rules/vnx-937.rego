# SPDX-License-Identifier: Apache-2.0
package vulnetix.rules.vnx_937

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-937",
	"name": "Build file pins a Java library release with a known remote-code-execution vulnerability",
	"description": "CWE-937 is the OWASP Top Ten 2013 category 'Using Components with Known Vulnerabilities'; dependency scanning (vulnetix sca) is the complete check. This rule reports the handful of Java components whose vulnerable releases are exploited for remote code execution, when a Maven pom.xml, a Gradle build.gradle / build.gradle.kts or a Gradle version catalog (*.versions.toml) pins one: org.apache.logging.log4j:log4j-core 2.x before the release that fixes CVE-2021-44228 and CVE-2021-45046 (2.16.0, or 2.12.2+ / 2.3.1+ on the Java 7 / Java 6 branches); log4j:log4j 1.x (end of life, CVE-2019-17571, CVE-2022-23305); commons-collections:commons-collections 3.0 to 3.2.1 and org.apache.commons:commons-collections4 4.0 (deserialization gadget chains, CVE-2015-7501); and org.apache.commons:commons-text 1.5 to 1.9 (CVE-2022-42889). Maven versions are read from a <version> element in the same <dependency> block, directly or through a ${property} declared in the same pom; Gradle versions from a 'group:name:version' string or group/name/version arguments, or a \"group:name:${var}\" / \"$var\" string whose variable is assigned in the same build file (ext, def, val) or in a gradle.properties; catalog versions from a module/version entry, a coordinate string, or a version.ref resolved against the catalog's own [versions] entry. Not reported: fixed releases, unaffected artifacts of the same project (log4j-api, log4j-to-slf4j, log4j-over-slf4j), the same artifactId under another groupId, exclusions and dependencies whose version is managed elsewhere (a parent pom, a BOM, a plugin or a variable defined in another build script), coordinates in source code, comments and documentation.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-937/",
	"languages": ["java", "kotlin"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [937],
	"capec": ["CAPEC-66"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["known-vulnerable-component", "dependency", "cwe-937"],
}

# artifactId -> groupId of each tracked component.
_group := {
	"log4j-core": "org.apache.logging.log4j",
	"log4j": "log4j",
	"commons-collections": "commons-collections",
	"commons-collections4": "org.apache.commons",
	"commons-text": "org.apache.commons",
}

_advice := {
	"log4j-core": "log4j-core before 2.16.0 is exploitable for remote code execution (Log4Shell, CVE-2021-44228 / CVE-2021-45046); upgrade to 2.17.1 or later",
	"log4j": "log4j 1.x is end of life with unfixed vulnerabilities (CVE-2019-17571, CVE-2022-23305); migrate to log4j-core 2.17.1+ or another backend",
	"commons-collections": "commons-collections 3.2.1 and earlier ship the InvokerTransformer deserialization gadget chain (CVE-2015-7501); upgrade to 3.2.2",
	"commons-collections4": "commons-collections4 4.0 ships the InvokerTransformer deserialization gadget chain; upgrade to 4.1 or later",
	"commons-text": "commons-text 1.5 to 1.9 evaluate script/dns/url interpolation in StringSubstitutor (Text4Shell, CVE-2022-42889); upgrade to 1.10.0",
}

_build_file(path) if endswith(path, "pom.xml")

_build_file(path) if endswith(path, ".gradle")

_build_file(path) if endswith(path, ".gradle.kts")

_build_file(path) if endswith(path, ".versions.toml")

_num(s) := 0 if s == ""

_num(s) := to_number(s) if s != ""

_vulnerable("log4j-core", ver) if {
	m := regex.find_all_string_submatch_n(`^2\.(\d+)(?:\.(\d+))?`, ver, 1)
	count(m) > 0
	minor := _num(m[0][1])
	patch := _num(m[0][2])
	minor < 16
	not _branch_fixed(minor, patch)
}

_vulnerable("log4j", ver) if regex.match(`^1\.\d`, ver)

_vulnerable("commons-collections", ver) if regex.match(`^3\.(0|1|2|2\.1)$`, ver)

_vulnerable("commons-collections4", ver) if regex.match(`^4\.0(\.0)?$`, ver)

_vulnerable("commons-text", ver) if regex.match(`^1\.[5-9](\.\d+)?$`, ver)

_branch_fixed(12, patch) if patch >= 2

_branch_fixed(3, patch) if patch >= 1

_is_comment(line) if startswith(trim_space(line), "//")

_is_comment(line) if startswith(trim_space(line), "#")

_is_comment(line) if startswith(trim_space(line), "<!--")

_is_comment(line) if startswith(trim_space(line), "*")

_is_comment(line) if startswith(trim_space(line), "/*")

# ── Maven ─────────────────────────────────────────────────────────────────

_block_edge := `</?(dependency|exclusion|exclusions|plugin|parent|extension|dependencies)\b`

# No block boundary between lines a and b (exclusive).
_same_block(lines, a, b) if a == b

_same_block(lines, a, b) if {
	a != b
	lo := min([a, b])
	hi := max([a, b])
	not _edge_between(lines, lo, hi)
}

_edge_between(lines, lo, hi) if {
	lo + 1 <= hi - 1
	some k in helpers.span(lo + 1, hi - 1)
	regex.match(_block_edge, lines[k])
}

_tag_value(line, tag) := v if {
	m := regex.find_all_string_submatch_n(concat("", [`<`, tag, `>\s*([^<\s]+)\s*</`, tag, `>`]), line, 1)
	count(m) > 0
	v := m[0][1]
}

_resolve(_, v) := v if not startswith(v, "${")

_resolve(content, v) := r if {
	startswith(v, "${")
	prop := trim_suffix(trim_prefix(v, "${"), "}")
	m := regex.find_all_string_submatch_n(concat("", [`<`, regex.replace(prop, `\.`, `\.`), `>\s*([^<\s]+)\s*</`]), content, 1)
	count(m) > 0
	r := m[0][1]
}

_maven(path, content) := {[k, art] |
	endswith(path, "pom.xml")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "<artifactId>")
	art := _tag_value(line, "artifactId")
	grp := _group[art]
	some g in numbers.range(max([0, i - 4]), min([count(lines) - 1, i + 4]))
	_tag_value(lines[g], "groupId") == grp
	_same_block(lines, g, i)
	some k in numbers.range(max([0, i - 4]), min([count(lines) - 1, i + 4]))
	raw := _tag_value(lines[k], "version")
	_same_block(lines, k, i)
	not _is_comment(lines[k])
	_vulnerable(art, _resolve(content, raw))
}

# ── Gradle and version catalogs ───────────────────────────────────────────

_coord_re := `["']([\w.\-]+):([\w.\-]+):([\w.\-]+)(?:@\w+)?["']`

_map_re := `\bgroup\s*[:=]\s*["']([\w.\-]+)["']\s*,\s*name\s*[:=]\s*["']([\w.\-]+)["']\s*,\s*version\s*[:=]\s*["']([\w.\-]+)["']`

_toml_re := `\bmodule\s*=\s*["']([\w.\-]+):([\w.\-]+)["']\s*,\s*version\s*=\s*["']([\w.\-]+)["']`

_gradle(path, content) := {[i, art] |
	not endswith(path, "pom.xml")
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`log4j|commons-`, line)
	not _is_comment(line)
	some re in [_coord_re, _map_re, _toml_re]
	some m in regex.find_all_string_submatch_n(re, line, -1)
	art := m[2]
	_group[art] == m[1]
	_vulnerable(art, m[3])
}

# A version held in a variable: "g:a:${log4jVersion}" / "g:a:$v" in Gradle,
# version.ref = "log4j" in a catalog. The variable is resolved from an
# assignment in the same file, or (Gradle) from any gradle.properties.
_coord_var_re := `["']([\w.\-]+):([\w.\-]+):\$\{?([A-Za-z_][\w.]*)\}?["']`

_toml_ref_re := `\bmodule\s*=\s*["']([\w.\-]+):([\w.\-]+)["']\s*,\s*version\.ref\s*=\s*["']([\w.\-]+)["']`

_toml_ref_map_re := `\bgroup\s*=\s*["']([\w.\-]+)["']\s*,\s*name\s*=\s*["']([\w.\-]+)["']\s*,\s*version\.ref\s*=\s*["']([\w.\-]+)["']`

_esc(n) := regex.replace(n, `([.\-])`, `\$1`)

_last_segment(n) := s if {
	parts := split(n, ".")
	s := parts[count(parts) - 1]
}

_var_value(content, n) := v if {
	m := regex.find_all_string_submatch_n(concat("", [`(?m)(?:^|[\s.(,])`, _esc(_last_segment(n)), `\s*=\s*["']([\w.\-]+)["']`]), content, 1)
	count(m) > 0
	v := m[0][1]
}

_var_value(content, n) := v if {
	not regex.match(concat("", [`(?m)(?:^|[\s.(,])`, _esc(_last_segment(n)), `\s*=\s*["']`]), content)
	vs := [m[0][1] |
		some p, c in input.file_contents
		endswith(p, "gradle.properties")
		m := regex.find_all_string_submatch_n(concat("", [`(?m)^\s*`, _esc(_last_segment(n)), `\s*[=:]\s*([\w.\-]+)\s*$`]), c, 1)
		count(m) > 0
	]
	count(vs) > 0
	v := vs[0]
}

_gradle_var(path, content) := {[i, art] |
	not endswith(path, "pom.xml")
	regex.match(`\$|version\.ref`, content)
	lines := split(content, "\n")
	some i, line in lines
	regex.match(`(log4j|commons-)[\w.\-]*:\$|version\.ref`, line)
	not _is_comment(line)
	some re in [_coord_var_re, _toml_ref_re, _toml_ref_map_re]
	some m in regex.find_all_string_submatch_n(re, line, -1)
	art := m[2]
	_group[art] == m[1]
	_vulnerable(art, _var_value(content, m[3]))
}

findings contains finding if {
	some path, content in input.file_contents
	_build_file(path)
	regex.match(`log4j|commons-collections|commons-text`, content)
	some [k, art] in (_maven(path, content) | _gradle(path, content)) | _gradle_var(path, content)
	lines := split(content, "\n")
	finding := {
		"rule_id": metadata.id,
		"message": _advice[art],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": k + 1,
		"snippet": lines[k],
	}
}
