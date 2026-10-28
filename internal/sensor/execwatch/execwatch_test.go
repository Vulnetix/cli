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
