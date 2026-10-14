package vulnetix.rules.vnx_java_027

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-JAVA-027",
	"name": "Java Spring security headers disabled or absent (clickjacking, CSP)",
	"description": "Spring Security configuration switches off its default protective response headers: headers().disable() (every header), frameOptions().disable() (X-Frame-Options, clickjacking), httpStrictTransportSecurity().disable() (HSTS) or contentTypeOptions().disable() (X-Content-Type-Options: nosniff), in the chained DSL (including a chain split over several lines), the lambda DSL (headers(h -> h.disable()), frameOptions(f -> { f.disable(); })) and the method-reference form (headers(AbstractHttpConfigurer::disable), frameOptions(FrameOptionsConfig::disable)). Not reported: frameOptions().sameOrigin()/deny(), xssProtection().disable() (the X-XSS-Protection header is deprecated and turning it off is current advice), csrf/cors/httpBasic/formLogin disable() calls, headers().defaultsDisabled() followed by explicit headers, test code, comments and string literals. Missing headers in frameworks other than Spring Security are not judged here.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-027/",
	"languages": ["java"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [693],
	"capec": ["CAPEC-103"],
	"attack_technique": ["T1185"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:RU/AL:S/IC:N/FC:LT/RP:RU/RL:S/AV:L/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["security-headers", "clickjacking", "spring", "java"],
}

# Matched against code with string literals blanked and all whitespace removed.
_dis_re := `(headers|frameOptions|httpStrictTransportSecurity|contentTypeOptions)\((?:\)\.disable\(\)|\w+->\{?\w+\.disable\(\);?\}?\)|[\w.]+::disable\))`

_str_re := `"(?:[^"\\\n]|\\.)*"`

_compact(l) := regex.replace(regex.replace(l, _str_re, `""`), `\s+`, "")

_what("headers") := "all Spring Security response headers are disabled (X-Frame-Options, HSTS, nosniff, cache control)"

_what("frameOptions") := "X-Frame-Options is disabled, so any site can frame the application (clickjacking)"

_what("httpStrictTransportSecurity") := "Strict-Transport-Security (HSTS) is disabled, allowing HTTPS downgrade"

_what("contentTypeOptions") := "X-Content-Type-Options: nosniff is disabled, allowing MIME sniffing"

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".java")
	not helpers.is_test_path(path)
	contains(content, "disable")
	regex.match(`(?m)(headers|frameOptions|httpStrictTransportSecurity|contentTypeOptions)\(`, content)
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "disable")
	not helpers.is_comment_line(line)
	prefix := concat("", [_compact(lines[k]) |
		some k in numbers.range(max([0, i - 4]), i - 1)
		i > 0
		not helpers.is_comment_line(lines[k])
	])
	text := concat("", [prefix, _compact(line)])
	ms := regex.find_all_string_submatch_n(_dis_re, text, -1)
	count(ms) > count(regex.find_n(_dis_re, prefix, -1))
	kind := ms[count(ms) - 1][1]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Spring Security: %s; remove the disable() call or configure the header explicitly (frameOptions().deny()/sameOrigin())", [_what(kind)]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
