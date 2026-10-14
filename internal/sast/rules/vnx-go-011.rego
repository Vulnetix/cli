package vulnetix.rules.vnx_go_011

import rego.v1

import data.vulnetix.helpers

metadata := {
	"id": "VNX-GO-011",
	"name": "Go gob deserialization of an HTTP request body or accepted connection",
	"description": "encoding/gob decodes data a client controls: gob.NewDecoder reads an HTTP request body (net/http's *http.Request.Body under any parameter name, gin's c.Request.Body, echo's c.Request().Body, fiber's c.Body(), fasthttp's ctx.PostBody()) or a connection returned by Listener.Accept, directly or through a variable assigned from it in the same function (io.ReadAll, bytes.NewReader, http.MaxBytesReader). The gob package is documented as not hardened against adversarial input: crafted streams exhaust memory and stack, and a size limit does not change that, so a MaxBytesReader-wrapped body is still reported. Not reported: json.NewDecoder, gob.NewEncoder, gob decoding of local files, in-memory data, an outbound client's response body or a dialled connection, comments and strings. net/rpc servers (which use gob internally) and connections passed in from another function are not followed.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-011/",
	"languages": ["go"],
	"severity": "medium",
	"level": "warning",
	"kind": "sast",
	"cwe": [502],
	"capec": ["CAPEC-586"],
	"attack_technique": ["T1190"],
	"cvssv4": "",
	"cwss": "CWSS:1.0/TI:M/AP:A/AL:A/IC:N/FC:LT/RP:N/RL:A/AV:I/AS:N/IN:A/SC:A/BI:M/DI:H/EX:M/EC:N/P:C",
	"tags": ["deserialization", "go", "dos"],
}

# Start of the enclosing top-level function (0 when there is none above).
_fn_start(lines, i) := s if {
	starts := [j | some j in numbers.range(0, i); startswith(lines[j], "func ")]
	count(starts) > 0
	s := starts[count(starts) - 1]
}

_fn_start(lines, i) := 0 if {
	not _has_func_above(lines, i)
}

_has_func_above(lines, i) if {
	some j in numbers.range(0, i)
	startswith(lines[j], "func ")
}

# The request-body (or accepted-connection) expressions visible in the window.
_sources(fn) := srcs if {
	reqs := {m[1] | some m in regex.find_all_string_submatch_n(`\b(\w+)\s+\*http\.Request\b`, fn, -1)}
	conns := {m[1] | some m in regex.find_all_string_submatch_n(`\b(\w+)\s*(?:,\s*\w+\s*)?:?=\s*\w+\.Accept(?:TCP|Unix)?\(\)`, fn, -1)}
	fast := {s |
		some s in [`\b\w+\.(?:PostBody|BodyRaw)\(\)`, `\b\w+\.Body\(\)`]
		regex.match(`\*?fiber\.Ctx|\*fasthttp\.RequestCtx`, fn)
	}
	ginecho := {`\b\w+\.Request(?:\(\))?\.Body\b` | regex.match(`\*gin\.Context|echo\.Context`, fn)}
	srcs := (({concat("", [`\b`, n, `\.Body\b`]) | some n in reqs} | {concat("", [`\b`, n, `\b`]) | some n in conns}) | fast) | ginecho
}

# Undefined when the function has no request or connection in scope (an
# empty alternation would match everything).
_source_re(fn) := r if {
	s := _sources(fn)
	count(s) > 0
	r := concat("|", s)
}

# The decoder's argument (the rest of the call, before .Decode)...
_decoder_arg(_, _, line) := a if {
	not regex.match(`gob\.NewDecoder\(\s*$`, line)
	parts := split(line, "gob.NewDecoder(")
	count(parts) > 1
	rest := parts[1]
	a := split(rest, ".Decode(")[0]
}

# ...or the next code line when the call is broken after its parenthesis.
_decoder_arg(lines, i, line) := a if {
	regex.match(`gob\.NewDecoder\(\s*$`, line)
	j := helpers.next_code_index(lines, i, 3)
	a := split(lines[j], ".Decode(")[0]
}

_tainted(lines, i, start, src_re) := names if {
	i > start
	before := i - start
	l1 := helpers.tainted_names(lines, i, before, src_re)
	l2 := {v |
		count(l1) > 0
		i > start
		some j in numbers.range(start, i - 1)
		prev := lines[j]
		not helpers.is_comment_line(prev)
		some n in l1
		regex.match(concat("", [`\b`, n, `\b`]), prev)
		v := helpers.assigned_first(prev)
		not v in l1
	}
	names := l1 | l2
}

# The call text sits inside a string: the code before it opens an
# interpreted ("...) or raw (`...) literal it has not closed.
_in_string_literal(prefix) if regex.match(`^\s*[^"]*"[^"]*$`, prefix)

_in_string_literal(prefix) if regex.match("^[^`]*`[^`]*$", prefix)

_reads_untrusted(_, _, _, arg, src_re) if regex.match(src_re, arg)

_reads_untrusted(lines, i, start, arg, src_re) if {
	some n in _tainted(lines, i, start, src_re)
	regex.match(concat("", [`\b`, n, `\b`]), arg)
}

findings contains finding if {
	some path, content in input.file_contents
	endswith(path, ".go")
	contains(content, "gob.NewDecoder(")
	lines := split(content, "\n")
	some i, line in lines
	contains(line, "gob.NewDecoder(")
	not helpers.is_comment_line(line)
	arg := _decoder_arg(lines, i, line)
	not _in_string_literal(split(line, "gob.NewDecoder(")[0])
	start := _fn_start(lines, i)
	fn := helpers.code_window(lines, i, i - start, 0)
	src_re := _source_re(fn)
	_reads_untrusted(lines, i, start, arg, src_re)
	finding := {
		"rule_id": metadata.id,
		"message": "gob.NewDecoder reads client-controlled data (an HTTP request body or an accepted connection); gob is not hardened against adversarial input. Decode JSON or protobuf into explicit types instead",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
