package vulnetix.rules.vnx_java_029

import rego.v1

import data.vulnetix.helpers

metadata := {
    "id": "VNX-JAVA-029",
    "name": "XML External Entity (XXE) via DocumentBuilderFactory",
    "description": "A DOM or SAX parser factory is created (DocumentBuilderFactory.newInstance/newDefaultInstance/newNSInstance, SAXParserFactory.newInstance/newDefaultInstance, XMLReaderFactory.createXMLReader) and the file never hardens that factory: no setFeature(disallow-doctype-decl, true), setFeature(external-general-entities, false), setFeature(FEATURE_SECURE_PROCESSING, true) or setAttribute/setProperty(ACCESS_EXTERNAL_DTD, \"\") on the same variable, no such call on any parser or reader within the 30 lines that follow (a SAXParser's XMLReader hardened instead of its factory), and no harden/secure helper given the factory. A factory created and used in one chained expression is reported. Also reported: setFeature(external-general-entities or external-parameter-entities, true) on a factory or reader that does not also restrict ACCESS_EXTERNAL_DTD or turn on secure processing. Not reported: hardened factories (including a feature URI held in a named constant), setExpandEntityReferences(false) is not accepted as hardening, imports, field declarations of the type, comments and string literals. StAX (XMLInputFactory), TransformerFactory and SchemaFactory are covered by VNX-JAVA-004, not here.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-029/",
    "languages": ["java"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [611],
    "capec": ["CAPEC-183"],
    "attack_technique": ["T1195.002"],
    "cvssv4": "",
    "cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
    "tags": ["xxe", "xml", "parsing"],
}

_create_re := `\b(?:DocumentBuilderFactory\.new(?:Default)?(?:NS)?Instance|SAXParserFactory\.new(?:Default)?(?:NS)?Instance|XMLReaderFactory\.createXMLReader)\s*\(`

_str_re := `"(?:[^"\\\n]|\\.)*"`

_strip(text) := regex.replace(text, _str_re, `""`)

# The variable the factory is assigned to: on the creation line, or on the line
# above when the initialiser is wrapped (`X f =` / `    DocumentBuilderFactory.newInstance();`).
_var(lines, i) := v if {
    m := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*=\s*(?:[\w.]+\.)?(?:DocumentBuilderFactory|SAXParserFactory|XMLReaderFactory)\.`, lines[i], 1)
    count(m) > 0
    v := m[0][1]
}

_var(lines, i) := v if {
    not regex.match(`=\s*(?:[\w.]+\.)?(?:DocumentBuilderFactory|SAXParserFactory|XMLReaderFactory)\.`, lines[i])
    regex.match(`^\s*(?:[\w.]+\.)?(?:DocumentBuilderFactory|SAXParserFactory|XMLReaderFactory)\.`, lines[i])
    i > 0
    m := regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\s*=\s*$`, lines[i - 1], 1)
    count(m) > 0
    v := m[0][1]
}

# Resolve a feature/property argument: a literal, an XMLConstants name, or a
# constant declared in the file.
_arg_value(_, a) := a if startswith(a, "\"")

_arg_value(_, a) := a if startswith(a, "XMLConstants.")

_arg_value(content, a) := v if {
    regex.match(`^[A-Za-z_]\w*$`, a)
    m := regex.find_all_string_submatch_n(concat("", [`\b`, a, `\s*=\s*("[^"]*")`]), content, 1)
    count(m) > 0
    v := m[0][1]
}

_set_re := `\.(setFeature|setAttribute|setProperty)\(\s*([\w.]+|"[^"]*")\s*,\s*([^)]*?)\s*\)`

_hardening(content, line) if {
    some m in regex.find_all_string_submatch_n(_set_re, line, -1)
    val := _arg_value(content, m[2])
    _hardens(val, trim_space(m[3]))
}

_hardens(name, "true") if contains(name, "disallow-doctype-decl")

_hardens(name, "true") if contains(name, "FEATURE_SECURE_PROCESSING")

_hardens(name, "true") if contains(name, "feature/secure-processing")

_hardens(name, "false") if contains(name, "external-general-entities")

_hardens(name, "\"\"") if contains(name, "ACCESS_EXTERNAL_DTD")

_hardens(name, "\"\"") if contains(name, "accessExternalDTD")

# hardening on the factory variable anywhere in the file
_hardened(content, lines, _, v) if {
    some k, l in lines
    contains(l, v)
    regex.match(concat("", [`\b`, v, `\.set(?:Feature|Attribute|Property)\(`]), l)
    not helpers.is_comment_line(l)
    _hardening(content, _stmt(lines, k))
}

# A call wrapped over up to three lines, joined.
_stmt(lines, k) := concat(" ", array.slice(lines, k, min([count(lines), k + 3])))

# a harden/secure helper given the factory
_hardened(_, lines, _, v) if {
    some l in lines
    contains(l, v)
    regex.match(concat("", [`(?i)\w*(?:secure|harden|safe|protect)\w*\(\s*`, v, `\s*\)`]), l)
}

# hardening on a parser/reader derived from it within the next 30 lines
_hardened(content, lines, i, _) if {
    some k in numbers.range(i + 1, min([count(lines) - 1, i + 30]))
    l := lines[k]
    contains(l, ".set")
    not helpers.is_comment_line(l)
    _hardening(content, _stmt(lines, k))
}

findings contains finding if {
    some path, content in input.file_contents
    endswith(path, ".java")
    regex.match(_create_re, content)
    lines := split(content, "\n")
    some i, line in lines
    contains(line, "Factory")
    not helpers.is_comment_line(line)
    regex.match(_create_re, _strip(line))
    _unhardened(content, lines, i)
    finding := {
        "rule_id": metadata.id,
        "message": "XML parser factory created without disabling DOCTYPEs or external entities; set disallow-doctype-decl to true (or external-general-entities to false and ACCESS_EXTERNAL_DTD to \"\") before parsing",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}

_unhardened(content, lines, i) if {
    v := _var(lines, i)
    not _hardened(content, lines, i, v)
}

# no variable: created and used in one expression
_unhardened(_, lines, i) if {
    not _var(lines, i)
}

# external entities explicitly switched on
findings contains finding if {
    some path, content in input.file_contents
    endswith(path, ".java")
    contains(content, "-entities")
    lines := split(content, "\n")
    some i, line in lines
    contains(line, "setFeature")
    not helpers.is_comment_line(line)
    some m in regex.find_all_string_submatch_n(`([A-Za-z_]\w*)\.setFeature\(\s*([\w.]+|"[^"]*")\s*,\s*true\s*\)`, line, -1)
    regex.match(`external-(?:general|parameter)-entities`, _arg_value(content, m[2]))
    not _restricted(content, lines, m[1])
    finding := {
        "rule_id": metadata.id,
        "message": "External entity resolution explicitly enabled on an XML parser; set external-general-entities and external-parameter-entities to false",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}

_restricted(content, lines, v) if {
    some l in lines
    contains(l, v)
    regex.match(concat("", [`\b`, v, `\.set(?:Feature|Attribute|Property)\(`]), l)
    not helpers.is_comment_line(l)
    some m in regex.find_all_string_submatch_n(_set_re, l, -1)
    val := _arg_value(content, m[2])
    _restricts(val, trim_space(m[3]))
}

_restricts(name, "\"\"") if contains(name, "ACCESS_EXTERNAL_DTD")

_restricts(name, "\"\"") if contains(name, "accessExternalDTD")

_restricts(name, "true") if contains(name, "FEATURE_SECURE_PROCESSING")

_restricts(name, "true") if contains(name, "disallow-doctype-decl")
