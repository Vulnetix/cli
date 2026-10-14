package vulnetix.rules.vnx_java_028

import rego.v1

import data.vulnetix.helpers

metadata := {
    "id": "VNX-JAVA-028",
    "name": "SQL injection via string concatenation in Java",
    "description": "A JDBC or Spring JdbcTemplate call (Statement execute/executeQuery/executeUpdate/executeLargeUpdate/addBatch, Connection prepareStatement/prepareCall, JdbcTemplate query/queryForList/queryForObject/queryForMap/queryForRowSet/update/batchUpdate) receives SQL text that was built from a SQL string literal and a non-constant value: concatenated with +, appended with +=, String.concat(), String.format() with %s, or StringBuilder.append(). The SQL may be built inline in the call (including a call split over several lines) or in a variable assigned up to 40 lines above it. Not reported: parameterised queries (? placeholders with bound arguments), SQL built only from literals and UPPER_CASE constants, non-SQL execute() calls (HTTP clients, executors) whose text carries no SQL, the pattern inside a string literal or a comment. The rule does not follow values across methods or files and does not judge whether the concatenated value is attacker-controlled.",
    "help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-java-028/",
    "languages": ["java"],
    "severity": "high",
    "level": "error",
    "kind": "sast",
    "cwe": [89],
    "capec": ["CAPEC-66"],
    "attack_technique": ["T1059.003"],
    "cvssv4": "",
    "cwss": "CWSS:1.0/TI:H/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:H/DI:H/EX:H/EC:N/P:H",
    "tags": ["sql-injection", "database", "query"],
}

_sink_names := `executeQuery|executeUpdate|executeLargeUpdate|execute|addBatch|prepareStatement|prepareCall|query|queryForList|queryForObject|queryForMap|queryForRowSet|queryForLong|queryForInt|queryForStream|update|batchUpdate`

_sink_re := concat("", [`\.(?:`, _sink_names, `)\s*\(`])

_sink_arg_re := concat("", [`\.(?:`, _sink_names, `)\s*\(([^;]*)`])

_str_re := `"(?:[^"\\\n]|\\.)*"`

# A string literal that carries SQL.
_sql_lit_re := `(?i)"[^"]*(?:\b(?:select\s|insert\s+into|update\s+\w+\s+set|delete\s+from|merge\s+into|(?:create|drop)\s+(?:table|schema|user|index|view|database)|alter\s+table|truncate\s|from\s|where\s|values\s*\(|order\s+by|group\s+by|set\s+schema)|\{\s*call\b)`

_file_gate := `(?i)"[^"\n]*\b(select|insert|update|delete|create|drop|alter|truncate|merge|call|schema|from|where|values)\b`

_is_const(name) if {
    parts := split(name, ".")
    regex.match(`^[A-Z][A-Z0-9_]*$`, parts[count(parts) - 1])
}

# An operand of a concatenation, a format, a concat() or an append() that is
# not a literal and not an UPPER_CASE constant.
_dynamic_operand(stripped) if {
    some m in regex.find_all_string_submatch_n(`\+\s*([A-Za-z_][\w.]*)`, stripped, -1)
    not _is_const(m[1])
}

_dynamic_operand(stripped) if {
    some m in regex.find_all_string_submatch_n(`([A-Za-z_][\w.]*)(?:\([^()]*\))?\s*\+[^=]`, stripped, -1)
    not _is_const(m[1])
    not regex.match(`^(String|return|new)$`, m[1])
}

_dynamic_operand(stripped) if {
    some m in regex.find_all_string_submatch_n(`\.(?:concat|append)\(\s*([A-Za-z_][\w.]*)`, stripped, -1)
    not _is_const(m[1])
}

_dynamic_operand(stripped) if {
    some m in regex.find_all_string_submatch_n(`String\.format\(\s*""\s*,([^;]*)`, stripped, -1)
    some a in regex.find_n(`[A-Za-z_][\w.]*`, m[1], -1)
    not _is_const(a)
}

_strip(text) := regex.replace(text, _str_re, `""`)

_dynamic_sql(text) if {
    regex.match(_sql_lit_re, text)
    _dynamic_operand(_strip(text))
}

# The statement starting at line i (up to 8 lines, cut at the first ';').
_stmt(lines, i) := s if {
    joined := concat(" ", array.slice(lines, i, min([count(lines), i + 8])))
    s := regex.find_n(`^[^;]*`, joined, 1)[0]
}

# All the statements in the 40 lines above i that build variable v.
_builds(lines, i, v) := concat("\n", [s |
    some k in numbers.range(max([0, i - 40]), i - 1)
    l := lines[k]
    contains(l, v)
    not helpers.is_comment_line(l)
    regex.match(concat("", [`(?:^|[^\w.])`, v, `\s*(?:\+?=(?:[^=]|$)|\.append\()`]), l)
    s := _stmt(lines, k)
])

_lambda(arg) if regex.match(`^\s*\(?[\w\s,]*\)?\s*->`, arg)

# inline: the SQL is built in the call's own argument
_vulnerable(_, _, arg) if {
    not _lambda(arg)
    _dynamic_sql(arg)
}

# the argument is a variable (or its toString()) built above
_vulnerable(lines, i, arg) if {
    m := regex.find_all_string_submatch_n(`^\s*([A-Za-z_]\w*)\s*(?:\.toString\(\)\s*)?(?:[,)]|$)`, arg, 1)
    count(m) > 0
    v := m[0][1]
    not _is_const(v)
    _dynamic_sql(_builds(lines, i, v))
}

findings contains finding if {
    some path, content in input.file_contents
    endswith(path, ".java")
    regex.match(_file_gate, content)
    regex.match(concat("", ["(?m)", _sink_re]), content)
    lines := split(content, "\n")
    some i, line in lines
    regex.match(_sink_re, line)
    not helpers.is_comment_line(line)
    regex.match(_sink_re, _strip(line))
    m := regex.find_all_string_submatch_n(_sink_arg_re, _stmt(lines, i), 1)
    count(m) > 0
    _vulnerable(lines, i, m[0][1])
    finding := {
        "rule_id": metadata.id,
        "message": "SQL text built by string concatenation or formatting reaches a JDBC/JdbcTemplate call; use a PreparedStatement or JdbcTemplate with ? placeholders and bound arguments",
        "artifact_uri": path,
        "severity": metadata.severity,
        "level": metadata.level,
        "start_line": i + 1,
        "snippet": line,
    }
}
