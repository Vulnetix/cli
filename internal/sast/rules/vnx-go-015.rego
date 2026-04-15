package vulnetix.rules.vnx_go_015

import rego.v1

metadata := {
	"id": "VNX-GO-015",
	"name": "sync.WaitGroup.Add() called inside goroutine",
	"description": "Calling WaitGroup.Add() inside an anonymous goroutine creates a race condition: the goroutine may not have started (and thus not called Add) before Wait() is called, causing Wait() to return prematurely or the program to panic.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-015/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [362, 667],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "waitgroup", "race-condition", "concurrency"],
}

_is_go(path) if endswith(path, ".go")

findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_go(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	# Detect WaitGroup.Add() call inside a goroutine body
	regex.match(`\bgo\s+func\s*\(`, line)
	not regex.match(`^\s*//`, line)
	# Look for .Add( in a nearby following line within the goroutine (within 10 lines)
	some j in numbers.range(i + 1, i + 10)
	j < count(lines)
	inner := lines[j]
	regex.match(`\.\s*Add\s*\(`, inner)
	not regex.match(`^\s*//`, inner)
	# Make sure we haven't closed the goroutine yet (no }() pattern before the Add)
	not regex.match(`\}\s*\(`, inner)
	finding := {
		"rule_id": metadata.id,
		"message": "WaitGroup.Add() called inside a goroutine; call wg.Add(n) before launching the goroutine to avoid a race between Add() and Wait()",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": j + 1,
		"snippet": inner,
	}
}
