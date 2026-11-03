package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const openVEXDoc = `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.com/vex/1","author":"acme","timestamp":"2026-01-01T00:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-0001"},"products":[{"@id":"pkg:npm/lodash@4.17.0"}],"status":"not_affected","justification":"vulnerable_code_not_present"}]}`

const vexSourceDoc = `apiVersion: vulnetix.com/v1
kind: VexSource
metadata: {name: ci-vex}
spec:
  path:
    path: vex
`

func vexRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	writeConfigFile(t, filepath.Join(dir, ".vulnetix", "config"), "vex.yaml", vexSourceDoc)
	writeConfigFile(t, dir, "vex/openvex.json", openVEXDoc)
	writeConfigFile(t, dir, "vex/notes.json", `{"not":"vex"}`)
	return dir
}

func TestApplyUploadsAPathSourceSnapshot(t *testing.T) {
	f := newFakeEngine(t)
	vexRepo(t)
	out, _, err := runCmd(t, newConfigApplyCommand(), "", "--manager", "gitops:acme/platform", "--auto-approve")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	body := f.lastBody("/config/vex-sources/ci-vex/snapshot")
	docs, _ := body["documents"].([]any)
	if len(docs) != 1 {
		t.Fatalf("documents %v (the non-VEX json must be skipped)", docs)
	}
	d := docs[0].(map[string]any)
	raw, err := base64.StdEncoding.DecodeString(d["content"].(string))
	if err != nil || string(raw) != openVEXDoc {
		t.Fatalf("content %v %q", err, raw)
	}
	sum := sha256.Sum256(raw)
	if d["sha256"] != hex.EncodeToString(sum[:]) || d["path"] != "vex/openvex.json" {
		t.Fatalf("document %v", d)
	}
	if !strings.Contains(out, "uploaded a snapshot of 1 document") {
		t.Fatalf("not reported:\n%s", out)
	}
}

// The files can change when the document does not.
func TestNothingToApplyStillUploadsTheSnapshot(t *testing.T) {
	f := newFakeEngine(t)
	f.plan["summary"] = map[string]any{"create": 0, "update": 0, "delete": 0, "noop": 1}
	f.plan["items"] = []any{}
	vexRepo(t)
	out, _, err := runCmd(t, newConfigApplyCommand(), "", "--manager", "gitops:acme/platform", "--auto-approve")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if f.called("POST /config/apply") != 0 || f.called("POST /config/vex-sources/ci-vex/snapshot") != 1 {
		t.Fatalf("calls %v", f.calls)
	}
}

func TestPathSourceWithNoVEXFailsTheApply(t *testing.T) {
	newFakeEngine(t)
	dir := vexRepo(t)
	if err := os.Remove(filepath.Join(dir, "vex", "openvex.json")); err != nil {
		t.Fatal(err)
	}
	out, _, err := runCmd(t, newConfigApplyCommand(), "", "--manager", "gitops:acme/platform", "--auto-approve")
	if err == nil || !strings.Contains(out, "holds no VEX documents") {
		t.Fatalf("err %v\n%s", err, out)
	}
}

func TestCollectVexSnapshotLimits(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < vexSnapshotMaxDocs+1; i++ {
		writeConfigFile(t, dir, "v"+string(rune('a'+i))+".json", openVEXDoc)
	}
	if _, err := collectVexSnapshot(dir, nil); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("err %v", err)
	}
	one := filepath.Join(dir, "single.json")
	if err := os.WriteFile(one, []byte(`{"x":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := collectVexSnapshot(one, nil); err == nil || !strings.Contains(err.Error(), "not a recognised VEX") {
		t.Fatalf("a named file must be VEX: %v", err)
	}
}
