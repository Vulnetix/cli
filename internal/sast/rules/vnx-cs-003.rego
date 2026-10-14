package vulnetix.rules.vnx_cs_003

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CS-003",
	"name": "C# XXE: XML parser resolves external entities",
	"description": "An XML parser is configured, or left at a default, that resolves external entities, so a document can read local files or make the server fetch URLs (XXE). Reported: an XmlResolver set to an XmlUrlResolver (inline, or a variable holding one) on XmlDocument, XmlTextReader or any other parser, and on XmlReaderSettings when that settings object also enables DTDs; DtdProcessing = DtdProcessing.Parse and ProhibitDtd = false with no XmlResolver = null beside them, unless every project file in the scan targets .NET Framework 4.5.2+ or .NET Core/.NET (where the default resolver is null and only the URL resolver line is a finding); and, when a project file targets .NET Framework 4.5.1 or older (TargetFrameworkVersion v2.0-v4.5.1, or net20-net451), XmlDocument.Load/LoadXml and new XmlTextReader(...) on non-constant input without XmlResolver = null or DtdProcessing.Prohibit/Ignore, because those parsers resolve external entities by default there. Not reported: XmlResolver = null, DtdProcessing.Prohibit or Ignore, ProhibitDtd = true, an XmlUrlResolver on XmlReaderSettings whose DTD processing stays prohibited, documents loaded from string constants, comparisons, and the names in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-003/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [611],
	"capec": ["CAPEC-221"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["xxe", "xml", "csharp"],
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

# String contents and trailing comments are removed before matching.
_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `//.*$`, "")

# ── Target framework ─────────────────────────────────────────────────────

_project_file(p) if regex.match(`\.(cs|vb|fs)proj$|(^|/)Directory\.Build\.props$`, p)

_legacy_re := `<TargetFrameworkVersion>\s*v(1\.|2\.|3\.|4\.0|4\.5(\.1)?\s*<)|<TargetFrameworks?>[^<]*\bnet(11|20|35|40|403|45|451)\b`

_modern_re := `<TargetFrameworkVersion>\s*v4\.(5\.[2-9]|[6-9])|<TargetFrameworks?>[^<]*\b(net(452|46\d?|47\d?|48\d?)|netcoreapp\d|netstandard\d|net\d+\.\d)`

# Some project in the scan builds for a framework whose parsers resolve
# external entities by default.
_legacy_fx if {
	some p, c in input.file_contents
	_project_file(p)
	regex.match(_legacy_re, c)
}

_modern_only if {
	some p, c in input.file_contents
	_project_file(p)
	regex.match(_modern_re, c)
	not _legacy_fx
}

# ── Parser objects ───────────────────────────────────────────────────────

_settings_vars(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*new\s+(?:System\.Xml\.)?XmlReaderSettings\b`, content, -1)
} | {m[1] |
	some m in regex.find_all_string_submatch_n(`\bXmlReaderSettings\s+([A-Za-z_]\w*)\b`, content, -1)
}

_resolver_vars(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*new\s+(?:System\.Xml\.)?XmlUrlResolver\s*\(`, content, -1)
}

_doc_vars(content) := {m[1] |
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*new\s+(?:System\.Xml\.)?XmlDocument\s*[({]`, content, -1)
}

_in_settings_initializer(lines, i) if {
	some k in numbers.range(max([0, i - 8]), i)
	regex.match(`\bnew\s+(?:System\.Xml\.)?XmlReaderSettings\b(?:\s*\(\s*\))?\s*(\{|$)`, lines[k])
	not _closed_between(lines, k, i)
}

_closed_between(lines, k, i) if {
	k + 1 <= i - 1
	some j in numbers.range(k + 1, i - 1)
	regex.match(`^\s*\}`, lines[j])
}

_dtd_on_re := `\bDtdProcessing\s*=\s*(?:System\.Xml\.)?DtdProcessing\.Parse\b|\bProhibitDtd\s*=\s*false\b`

_resolver_null_re := `\bXmlResolver\s*=\s*null\b`

_resolver_url_re := `\bXmlResolver\s*=\s*new\s+(?:System\.Xml\.)?XmlUrlResolver\s*\(`

# ── XmlUrlResolver assigned ──────────────────────────────────────────────

_resolver_assign := `(?:^|[^\w.])(?:([A-Za-z_][\w.]*)\.)?XmlResolver\s*=\s*([^=;,}]*)`

_url_resolver(rhs, _) if regex.match(`^\s*new\s+(?:System\.Xml\.)?XmlUrlResolver\s*\(`, rhs)

_url_resolver(rhs, rvars) if {
	v := trim_space(rhs)
	v in rvars
}

_settings_receiver(lines, i, recv, svars) if {
	recv != ""
	recv in svars
}

_settings_receiver(lines, i, "", _) if _in_settings_initializer(lines, i)

_unsafe_resolver(lines, i, code, svars, rvars) if {
	m := regex.find_all_string_submatch_n(_resolver_assign, code, 1)[0]
	_url_resolver(m[2], rvars)
	not _settings_receiver(lines, i, m[1], svars)
}

# On XmlReaderSettings the resolver only matters once DTDs are parsed.
_unsafe_resolver(lines, i, code, svars, rvars) if {
	m := regex.find_all_string_submatch_n(_resolver_assign, code, 1)[0]
	_url_resolver(m[2], rvars)
	_settings_receiver(lines, i, m[1], svars)
	regex.match(_dtd_on_re, helpers.code_window(lines, i, 10, 10))
}

# ── DTD processing enabled ───────────────────────────────────────────────

_dtd_enabled(lines, i, code) if {
	regex.match(_dtd_on_re, code)
	not _modern_only
	w := helpers.code_window(lines, i, 10, 10)
	not regex.match(_resolver_null_re, w)
	not regex.match(_resolver_url_re, w) # that line is the finding
}

# ── Unsafe defaults on old frameworks ────────────────────────────────────

_literal_var(content, v) if regex.match(concat("", [`\b(string|var|const\s+string)\s+`, v, `\s*=\s*@?"`]), content)

_non_literal(content, arg) if {
	a := trim_space(arg)
	a != ""
	not startswith(a, `"`)
	not startswith(a, `@"`)
	not _literal_var(content, a)
}

_legacy_default(lines, content, i, code, dvars) if {
	_legacy_fx
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\.Load(?:Xml)?\s*\(([^)]*)\)`, code, 1)[0]
	m[1] in dvars
	_non_literal(content, regex.replace(lines[i], `^.*?\.Load(?:Xml)?\s*\(\s*([^)]*)\).*$`, "$1"))
	not regex.match(concat("", [`\b`, m[1], `\s*\.\s*XmlResolver\s*=\s*null\b|\b`, m[1], `\s*=\s*new\s+(?:System\.Xml\.)?XmlDocument\s*\{[^}]*XmlResolver\s*=\s*null`]), helpers.code_window(lines, i, 10, 0))
}

_legacy_default(lines, content, i, code, _) if {
	_legacy_fx
	regex.match(`\bnew\s+(?:System\.Xml\.)?XmlTextReader\s*\(\s*[^)\s]`, code)
	_non_literal(content, regex.replace(lines[i], `^.*?XmlTextReader\s*\(\s*([^,)]*).*$`, "$1"))
	not regex.match(`\bDtdProcessing\s*=\s*(?:System\.Xml\.)?DtdProcessing\.(Prohibit|Ignore)\b|\bProhibitDtd\s*=\s*true\b|\bXmlResolver\s*=\s*null\b`, helpers.code_window(lines, i, 0, 10))
}

_kind(lines, content, i, code, svars, rvars, _) := "resolver" if _unsafe_resolver(lines, i, code, svars, rvars)

_kind(lines, content, i, code, svars, rvars, _) := "dtd" if {
	not _unsafe_resolver(lines, i, code, svars, rvars)
	_dtd_enabled(lines, i, code)
}

_kind(lines, content, i, code, svars, rvars, dvars) := "default" if {
	not _unsafe_resolver(lines, i, code, svars, rvars)
	not _dtd_enabled(lines, i, code)
	_legacy_default(lines, content, i, code, dvars)
}

_messages := {
	"resolver": "An XmlUrlResolver lets this parser fetch external entities and DTDs, so a document can read local files or reach internal URLs (XXE). Set XmlResolver = null (or leave it unset on .NET Framework 4.5.2+ and .NET)",
	"dtd": "DTD processing is enabled with no XmlResolver = null beside it; on .NET Framework before 4.5.2 the default resolver then expands external entities (XXE). Use DtdProcessing.Prohibit, or set XmlResolver = null if the DTD is needed",
	"default": "This project targets .NET Framework 4.5.1 or older, where XmlDocument and XmlTextReader resolve external entities by default: this parse is open to XXE. Set XmlResolver = null and DtdProcessing = DtdProcessing.Prohibit before loading, or move to .NET Framework 4.5.2+",
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	_has_any(content, {"XmlResolver", "DtdProcessing", "ProhibitDtd", "XmlDocument", "XmlTextReader"})
	lines := split(content, "\n")
	svars := _settings_vars(content)
	rvars := _resolver_vars(content)
	dvars := _doc_vars(content)
	some i, line in lines
	_has_any(line, {"XmlResolver", "DtdProcessing", "ProhibitDtd", "Load", "XmlTextReader"})
	not helpers.is_comment_line(line)
	code := _code(line)
	kind := _kind(lines, content, i, code, svars, rvars, dvars)
	finding := {
		"rule_id": metadata.id,
		"message": _messages[kind],
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
