package execwatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/sensor/decide"
	"github.com/vulnetix/cli/v3/internal/sensor/engine"
	"github.com/vulnetix/cli/v3/internal/sensor/feed"
	"github.com/vulnetix/cli/v3/internal/sensor/uplink"
)

const execLine = `{"process_exec":{"process":{"pid":4242,"binary":"/tmp/.x/miner","arguments":"--pool x","pod":{"namespace":"web","name":"api-7d"}}},"node_name":"n1","time":"2026-10-28T12:00:00Z"}`

func TestParseLine(t *testing.T) {
	e, ok := ParseLine([]byte(execLine))
	if !ok || e.PID != 4242 || e.Binary != "/tmp/.x/miner" || e.Pod != "api-7d" || e.Namespace != "web" {
		t.Fatalf("exec = %+v %v", e, ok)
	}
	if _, ok := ParseLine([]byte(`{"process_exit":{"process":{"pid":1}}}`)); ok {
		t.Fatal("only process_exec is an exec")
	}
	if _, ok := ParseLine([]byte(`not json`)); ok {
		t.Fatal("garbage is not an exec")
	}
}

func TestCheckReportsAHashMatchWithoutClaimingABlock(t *testing.T) {
	root := t.TempDir()
	payload := []byte("pretend this is a miner")
	sum := sha256.Sum256(payload)
	hexSum := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Join(root, "tmp", ".x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tmp", ".x", "miner"), payload, 0o755); err != nil {
		t.Fatal(err)
	}

	stix := feed.Rule{RuleTable: "countermeasure", RuleUUID: "cm-1", RuleType: "STIX", DeployMode: "block",
		Body: `{"type":"bundle","objects":[{"type":"indicator","pattern":"[file:hashes.'SHA-256' = '` + hexSum + `']"}]}`}
	set, _ := engine.Compile([]feed.Rule{stix})
	verdicts := decide.New(decide.Enforce, decide.Config{})
	verdicts.SetRules([]decide.Rule{{Ref: decide.RuleRef{Table: "countermeasure", UUID: "cm-1"}, Mode: decide.Block, Verified: true}})

	var mu sync.Mutex
	var got []uplink.Event
	w := &Watcher{Root: root, Rules: func() *engine.Set { return set }, Verdicts: verdicts, Report: func(e uplink.Event) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	}}
	e, _ := ParseLine([]byte(execLine))
	w.Check(e)

	if len(got) != 1 {
		t.Fatalf("events = %+v", got)
	}
	ev := got[0]
	if ev.Lane != "malware" || ev.SubjectKind != "process" || ev.Detail["sha256"] != hexSum || ev.Detail["pod"] != "web/api-7d" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Action != "allowed" {
		t.Fatalf("the watcher cannot stop a process and must not report that it did: %s", ev.Action)
	}

	// A binary that matches nothing is not reported.
	if err := os.WriteFile(filepath.Join(root, "tmp", ".x", "miner"), []byte("changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(filepath.Join(root, "tmp", ".x", "miner"), future, future)
	w.Check(e)
	if len(got) != 1 {
		t.Fatal("a changed binary must be hashed again, and no longer matches")
	}
}

func TestCheckRunsSigmaOverTheStart(t *testing.T) {
	rule := feed.Rule{RuleTable: "countermeasure", RuleUUID: "sg-1", RuleType: "SIGMA", DeployMode: "log", Body: `
title: Shell spawned by a web server
logsource: {category: process_creation, product: linux}
detection:
  parent: {ParentImage|endswith: [/nginx, /httpd]}
  shell: {Image|endswith: [/sh, /bash]}
  condition: parent and shell
`}
	set, results := engine.Compile([]feed.Rule{rule})
	if results[0].Status != engine.Compiled {
		t.Fatalf("compile = %+v", results[0])
	}
	verdicts := decide.New(decide.Monitor, decide.Config{})
	verdicts.SetRules([]decide.Rule{{Ref: decide.RuleRef{Table: "countermeasure", UUID: "sg-1"}, Verified: true}})
	var got []uplink.Event
	w := &Watcher{Root: t.TempDir(), Rules: func() *engine.Set { return set }, Verdicts: verdicts, Report: func(e uplink.Event) { got = append(got, e) }}

	line := `{"process_exec":{"process":{"pid":9,"binary":"/bin/sh","arguments":"-c id","cwd":"/var/www"},"parent":{"binary":"/usr/sbin/nginx"}},"time":"2026-10-28T12:00:00Z"}`
	e, ok := ParseLine([]byte(line))
	if !ok || e.ParentBinary != "/usr/sbin/nginx" || e.Cwd != "/var/www" {
		t.Fatalf("exec = %+v", e)
	}
	w.Check(e)
	if len(got) != 1 || got[0].Lane != "countermeasure" || got[0].RuleUUID != "sg-1" || got[0].Detail["commandLine"] != "/bin/sh -c id" {
		t.Fatalf("events = %+v", got)
	}

	e.ParentBinary = "/usr/bin/cron"
	w.Check(e)
	if len(got) != 1 {
		t.Fatal("a shell under cron does not match")
	}
}

func TestFollowReadsNewLinesAndRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tetragon.log")
	if err := os.WriteFile(path, []byte(execLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var seen []int
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Follow(ctx, path, func(e Exec) {
			mu.Lock()
			seen = append(seen, e.PID)
			mu.Unlock()
		})
	}()
	time.Sleep(100 * time.Millisecond)

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString(`{"process_exec":{"process":{"pid":1,"binary":"/bin/a"}}}` + "\n")
	_ = f.Close()

	time.Sleep(400 * time.Millisecond)
	_ = os.Rename(path, path+".1")
	_ = os.WriteFile(path, []byte(`{"process_exec":{"process":{"pid":2,"binary":"/bin/b"}}}`+"\n"), 0o644)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != 1 || seen[1] != 2 {
		t.Fatalf("seen = %v: the existing line is skipped, the new one and the rotated file's are read", seen)
	}
}

func TestCheckRunsYaraOverTheBinary(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "bin", "helper"), []byte("\x7fELF ... stratum+tcp://pool:3333 ..."), 0o755); err != nil {
		t.Fatal(err)
	}
	rule := feed.Rule{RuleTable: "countermeasure", RuleUUID: "y-1", RuleType: "YARA", DeployMode: "log",
		Body: `rule Miner { strings: $p = "stratum+tcp://" condition: uint32(0) == 0x464c457f and $p }`}
	set, results := engine.Compile([]feed.Rule{rule})
	if results[0].Status != engine.Compiled {
		t.Fatalf("compile = %+v", results[0])
	}
	verdicts := decide.New(decide.Monitor, decide.Config{})
	verdicts.SetRules([]decide.Rule{{Ref: decide.RuleRef{Table: "countermeasure", UUID: "y-1"}, Verified: true}})
	var got []uplink.Event
	w := &Watcher{Root: root, Rules: func() *engine.Set { return set }, Verdicts: verdicts, Report: func(e uplink.Event) { got = append(got, e) }}

	e, _ := ParseLine([]byte(`{"process_exec":{"process":{"pid":77,"binary":"/usr/bin/helper"}},"time":"2026-10-28T12:00:00Z"}`))
	w.Check(e)
	w.Check(e)
	if len(got) != 2 || got[0].RuleUUID != "y-1" || got[0].Lane != "malware" || got[0].Detail["rule"] != "Miner" {
		t.Fatalf("events = %+v", got)
	}
	if len(w.yaraHits) != 1 {
		t.Fatal("the same binary is evaluated once and the result reused")
	}
}
