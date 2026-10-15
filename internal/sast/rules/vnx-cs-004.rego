package vulnetix.rules.vnx_cs_004

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-CS-004",
	"name": "C# insecure deserialization: type-embedding formatter or serializer setting",
	"description": "Data is deserialised by an API that lets the payload choose which .NET types to instantiate, which a crafted payload turns into code execution through known gadget chains. Reported: Deserialize/UnsafeDeserialize/UnsafeDeserializeMethodResponse/ReadObject called on a BinaryFormatter, SoapFormatter, NetDataContractSerializer, LosFormatter or ObjectStateFormatter (an inline new, or a variable, field or parameter of that type, including one declared as IFormatter or built with an object initializer that sets a Binder, also when the call is chained onto the next line); Json.NET TypeNameHandling or ItemTypeNameHandling set to All, Auto, Objects or Arrays without a SerializationBinder beside it, when the settings are global (MVC SerializerSettings, JsonConvert.DefaultSettings), the file deserialises, or it is a [JsonProperty]/[JsonObject] attribute on a contract member; new JavaScriptSerializer(resolver) with a type resolver such as SimpleTypeResolver; MessagePackSerializer.Typeless.Deserialize and the TypelessContractlessStandardResolver/TypelessObjectResolver; and XmlSerializer/DataContractSerializer/DataContractJsonSerializer constructed from Type.GetType(non-constant). Not reported: these formatters used only to Serialize, JavaScriptSerializer without a resolver, TypeNameHandling.None or settings only used to serialise (a named settings object that reaches only Serialize/SerializeObject calls, even in a file that deserialises with other settings), TypeNameHandling restricted by a SerializationBinder, System.Text.Json, XmlSerializer/DataContractSerializer over typeof(T) or a constant type name, and the names in comments or string literals.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-cs-004/",
	"languages": ["csharp"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1059"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
	"tags": ["deserialization", "csharp"],
}

_has_any(s, needles) if {
	some n in needles
	contains(s, n)
}

_code(line) := regex.replace(regex.replace(line, `"(\\.|[^"\\])*"`, `""`), `//.*$`, "")

_formatters := `(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter)`

_read_call := `\s*\.\s*(?:Deserialize|UnsafeDeserialize|UnsafeDeserializeMethodResponse|ReadObject)\s*\(`

# Names that hold one of the formatters: `x = new BinaryFormatter()`,
# `BinaryFormatter x`, and `IFormatter x = new SoapFormatter()`.
_formatter_vars(code_lines) := {m[1] |
	some l in code_lines
	contains(l, "Formatter")
	some m in regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)\s*=\s*new\s+(?:[\w]+\.)*`, _formatters, `\s*[({]`]), l, -1)
} | {m[1] |
	some l in code_lines
	some m in regex.find_all_string_submatch_n(concat("", [`\b`, _formatters, `\s+([A-Za-z_]\w*)\s*[=;,)]`]), l, -1)
} | {m[1] |
	some l in code_lines
	contains(l, "NetDataContractSerializer")
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*new\s+(?:[\w]+\.)*NetDataContractSerializer\s*\(`, l, -1)
}

_formatter_read(code, _) if regex.match(concat("", [`\bnew\s+(?:[\w]+\.)*`, _formatters, `\s*\(\s*\)\s*\)?`, _read_call]), code)

_formatter_read(code, fvars) if {
	some m in regex.find_all_string_submatch_n(concat("", [`\b([A-Za-z_]\w*)`, _read_call]), code, -1)
	m[1] in fvars
}

# A call chained onto the line above: `new BinaryFormatter()` / `.Deserialize(s)`.
_chained_read(lines, i, code, fvars) if {
	regex.match(concat("", [`^`, _read_call]), code)
	i > 0
	prev := _code(lines[i - 1])
	_chain_head(prev, fvars)
}

_chain_head(prev, _) if regex.match(concat("", [`\bnew\s+(?:[\w]+\.)*`, _formatters, `\s*\(\s*\)\s*\)?\s*$`]), prev)

_chain_head(prev, fvars) if {
	some m in regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*$`, prev, 1)
	m[1] in fvars
}

# ── Json.NET TypeNameHandling ────────────────────────────────────────────

_tnh_re := `\b(?:Item)?TypeNameHandling\s*=\s*(?:Newtonsoft\.Json\.)?TypeNameHandling\.(All|Auto|Objects|Arrays)\b`

# [JsonProperty(TypeNameHandling = ...)] / [JsonObject(ItemTypeNameHandling = ...)]
# on a contract type: whoever deserialises the contract honours $type for
# that member, wherever that happens.
_tnh_reaches_reader(_, _, _, code) if regex.match(`\[\s*(?:Newtonsoft\.Json\.)?Json(?:Property|Object|Array|Dictionary)(?:Attribute)?\s*\([^\]]*TypeNameHandling\s*=`, code)

_binder_re := `\b(SerializationBinder|Binder)\s*=\s*[^=]`

_deserialises(content) if regex.match(`\bDeserializeObject\b|\.Deserialize\s*[<(]|\bPopulateObject\s*\(|\.ToObject\s*[<(]|\bJsonSerializer\.Create(Default)?\s*\(`, content)

_global_settings(_, _, code) if regex.match(`(?:^|[^\w])SerializerSettings\b`, code)

_global_settings(lines, i, _) if regex.match(`\bDefaultSettings\s*=|\bAddNewtonsoftJson\s*\(|\bSerializerSettings\b`, helpers.code_window(lines, i, 6, 0))

_type_name_handling(lines, content, i, code) if {
	regex.match(_tnh_re, code)
	not regex.match(_binder_re, helpers.code_window(lines, i, 10, 10))
	_tnh_reaches_reader(lines, content, i, code)
}

_tnh_reaches_reader(lines, _, i, code) if _global_settings(lines, i, code)

_tnh_reaches_reader(lines, content, i, _) if {
	_deserialises(content)
	not _write_only(lines, content, i)
}

# The settings object (or JsonSerializer) the TypeNameHandling line configures:
# the nearest `name = new JsonSerializerSettings`/`new JsonSerializer` up to
# six lines above.
_settings_name(lines, i) := name if {
	ks := [k |
		some k in numbers.range(max([0, i - 6]), i)
		regex.match(`\b[A-Za-z_]\w*\s*=\s*new\s+(?:Newtonsoft\.Json\.)?JsonSerializer(?:Settings)?\b`, lines[k])
	]
	count(ks) > 0
	m := regex.find_all_string_submatch_n(`\b([A-Za-z_]\w*)\s*=\s*new\s+(?:Newtonsoft\.Json\.)?JsonSerializer(?:Settings)?\b`, lines[max(ks)], 1)
	name := m[0][1]
}

# Settings that only ever reach a Serialize call never read a $type.
_write_only(lines, content, i) if {
	name := _settings_name(lines, i)
	regex.match(concat("", [`\bSerializ\w*\s*\([^;]*\b`, name, `\b|\b`, name, `\s*\.\s*Serialize\s*\(`]), content)
	not regex.match(concat("", [`(Deserializ\w*|PopulateObject|ToObject\w*|Create\w*)\s*(<[^>]*>)?\s*\([^;]*\b`, name, `\b|\b`, name, `\s*\.\s*(Deserialize|Populate)\w*\s*[<(]`]), content)
}

# Settings written inline into a SerializeObject call.
_write_only(lines, _, i) if {
	not _settings_name(lines, i)
	w := helpers.code_window(lines, i, 3, 0)
	regex.match(`\bSerializeObject\s*\(`, w)
	not regex.match(`Deserializ|PopulateObject`, w)
}

# ── Type resolvers ───────────────────────────────────────────────────────

_type_resolver(code) if regex.match(`\bnew\s+(?:[\w]+\.)*JavaScriptSerializer\s*\(\s*[^)\s]`, code)

_type_resolver_ok(code) if regex.match(`\bnew\s+(?:[\w]+\.)*JavaScriptSerializer\s*\(\s*null\s*\)`, code)

_runtime_type(line) if regex.match(`\bnew\s+(?:[\w]+\.)*(XmlSerializer|DataContractSerializer|DataContractJsonSerializer)\s*\(\s*Type\.GetType\s*\(\s*[^")\s]`, line)

_kind(lines, content, i, line, code, fvars) := "formatter" if _formatter_read(code, fvars)

_kind(lines, content, i, line, code, fvars) := "formatter" if {
	not _formatter_read(code, fvars)
	_chained_read(lines, i, code, fvars)
}

_kind(lines, content, i, line, code, fvars) := "typename" if {
	not _formatter_read(code, fvars)
	_type_name_handling(lines, content, i, code)
}

_kind(lines, content, i, line, code, fvars) := "resolver" if {
	not _formatter_read(code, fvars)
	not _type_name_handling(lines, content, i, code)
	_type_resolver(code)
	not _type_resolver_ok(code)
}

# MessagePack's typeless API and resolvers embed and honour .NET type names.
_typeless(code) if regex.match(`\bMessagePackSerializer\s*\.\s*Typeless\s*\.\s*Deserialize(?:Async)?\s*\(|\b(?:TypelessContractlessStandardResolver|TypelessObjectResolver)\s*\.\s*(?:Instance|Options)\b`, code)

_kind(lines, content, i, line, code, fvars) := "typeless" if {
	not _formatter_read(code, fvars)
	not _type_name_handling(lines, content, i, code)
	_typeless(code)
}

_kind(lines, content, i, line, code, fvars) := "runtime" if {
	not _formatter_read(code, fvars)
	not _type_name_handling(lines, content, i, code)
	not _type_resolver(code)
	_runtime_type(line)
}

_messages := {
	"formatter": "Deserialising with BinaryFormatter, SoapFormatter, NetDataContractSerializer, LosFormatter or ObjectStateFormatter lets the payload choose the types it instantiates, and a crafted payload executes code. These formatters cannot be made safe: use System.Text.Json or DataContractSerializer with a fixed type",
	"typename": "Json.NET TypeNameHandling other than None reads the $type property from the payload and instantiates it, a known code-execution path. Use TypeNameHandling.None, or restrict the types with a SerializationBinder that allows only known types",
	"resolver": "A JavaScriptSerializer with a type resolver honours __type in the payload and instantiates arbitrary types. Construct JavaScriptSerializer without a resolver, or move to System.Text.Json",
	"typeless": "MessagePack typeless deserialisation reads a .NET type name from the payload and instantiates it, a known code-execution path. Deserialize into a fixed type with a contract resolver that does not embed type names",
	"runtime": "The serializer's root type comes from data (Type.GetType with a non-constant name), so the payload chooses what is instantiated. Use typeof(T) or map the name through an allowlist of known types",
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".cs")
	_has_any(content, {"Formatter", "NetDataContractSerializer", "TypeNameHandling", "JavaScriptSerializer", "Type.GetType", "Typeless"})
	lines := split(content, "\n")
	code_lines := [_code(l) | some l in lines; not helpers.is_comment_line(l)]
	fvars := _formatter_vars(code_lines)
	some i, line in lines
	_has_any(line, {"Deserialize", "ReadObject", "TypeNameHandling", "JavaScriptSerializer", "Type.GetType", "Typeless"})
	not helpers.is_comment_line(line)
	code := _code(line)
	kind := _kind(lines, content, i, line, code, fvars)
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
