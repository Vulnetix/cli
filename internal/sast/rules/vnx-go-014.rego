package vulnetix.rules.vnx_go_014

import rego.v1

metadata := {
	"id": "VNX-GO-014",
	"name": "sync.Mutex or sync.RWMutex Lock() without deferred Unlock()",
	"description": "A sync.Mutex.Lock() or sync.RWMutex.RLock() call is not immediately paired with a deferred Unlock/RUnlock. If a subsequent code path panics or returns early, the mutex remains locked, causing goroutine deadlocks and denial of service.",
	"help_uri": "https://docs.cli.vulnetix.com/docs/sast-rules/vnx-go-014/",
	"languages": ["go"],
	"severity": "high",
	"level": "error",
	"kind": "sast",
	"cwe": [667, 833],
	"capec": [],
	"attack_technique": ["T1499"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["go", "mutex", "deadlock", "concurrency"],
}

_is_go(path) if endswith(path, ".go")

# Detect .Lock() or .RLock() call not followed by a defer .Unlock() / .RUnlock() on the next non-blank line
findings contains finding if {
	some path in object.keys(input.file_contents)
	_is_go(path)
	lines := split(input.file_contents[path], "\n")
	some i, line in lines
	regex.match(`\.(Lock|RLock)\(\)`, line)
	not regex.match(`^\s*//`, line)
	# Check that the immediately following non-empty line is NOT a defer unlock
	j := i + 1
	j < count(lines)
	next := lines[j]
	not regex.match(`\bdefer\b.*\.(Unlock|RUnlock)\(\)`, next)
	not regex.match(`^\s*//`, next)
	finding := {
		"rule_id": metadata.id,
		"message": "Mutex Lock()/RLock() not immediately followed by 'defer mu.Unlock()'/'defer mu.RUnlock()'; add defer to ensure the lock is always released even when a panic or early return occurs",
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": i + 1,
		"snippet": line,
	}
}
