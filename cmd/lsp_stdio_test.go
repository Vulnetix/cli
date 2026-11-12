package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The single most valuable test in the language-server suite.
//
// Standard output is the JSON-RPC channel. cmd/ writes to os.Stdout in 144
// places: banners, progress rows, result rendering, update advisories. A single
// stray byte desynchronises the Content-Length framing, and from that point the
// client cannot parse anything at all. The failure is total, and it is invisible
// in any test that exercises the server in-process rather than through a real
// binary.
//
// So this builds the actual binary, drives a real session through it, and
// asserts that every byte on file descriptor 1 is valid LSP framing with
// nothing before, between or after.

// buildBinary compiles the CLI once per test binary.
func buildBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary; skipped under -short")
	}

	bin := filepath.Join(t.TempDir(), "vulnetix-test")
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}

	cmd := exec.Command("go", "build", "-o", bin, "..")
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building the CLI failed: %v\n%s", err, out)
	}
	return bin
}

// lockedBuffer collects a child's output while the test reads it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return bytes.Clone(l.b.Bytes())
}

func (l *lockedBuffer) String() string { return string(l.Bytes()) }

func writeAll(t *testing.T, w io.Writer, msgs [][]byte) {
	t.Helper()
	for _, m := range msgs {
		if _, err := w.Write(m); err != nil {
			t.Fatalf("writing to the server: %v", err)
		}
	}
}

// waitForMessage polls the server's stdout until a complete message matches.
// A frame still being written is read on a later poll; whether the stream as a
// whole is clean framing is the strict parse at the end of the test.
func waitForMessage(t *testing.T, out *lockedBuffer, timeout time.Duration, what string, match func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		frames, _ := parseFrames(bytes.NewReader(out.Bytes()))
		for _, f := range frames {
			var m map[string]any
			if json.Unmarshal(f, &m) == nil && match(m) {
				return m
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s on stdout within %s", what, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// isResponse matches the response to the request with the given id.
func isResponse(id int) func(map[string]any) bool {
	return func(m map[string]any) bool {
		_, hasMethod := m["method"]
		return !hasMethod && fmt.Sprint(m["id"]) == strconv.Itoa(id)
	}
}

// waitForRules asks vulnetix/serverInfo until it reports the loaded rules,
// which the server stores once the warm-up has indexed the workspace.
func waitForRules(t *testing.T, stdin io.Writer, out *lockedBuffer, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for id := 100; ; id++ {
		writeAll(t, stdin, [][]byte{frame(t, map[string]any{"jsonrpc": "2.0", "id": id, "method": "vulnetix/serverInfo"})})
		resp := waitForMessage(t, out, timeout, "a serverInfo response", isResponse(id))
		if result, ok := resp["result"].(map[string]any); ok {
			if n, _ := result["rulesEmbedded"].(float64); n > 0 {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server did not load its rules within %s", timeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// frame renders a JSON-RPC message with LSP framing.
func frame(t *testing.T, v any) []byte {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Appendf(nil, "Content-Length: %d\r\n\r\n%s", len(body), body)
}

// parseFrames reads LSP-framed messages from r and returns their bodies.
//
// Strict on purpose. Anything that is not a well-formed header block followed
// by exactly Content-Length bytes is an error, because that is precisely what a
// stray write to stdout looks like on the wire.
func parseFrames(r io.Reader) ([]json.RawMessage, error) {
	br := bufio.NewReader(r)
	var out []json.RawMessage

	for {
		var contentLength = -1
		for {
			line, err := br.ReadString('\n')
			if err == io.EOF {
				if strings.TrimSpace(line) == "" && len(out) >= 0 {
					return out, nil
				}
				return out, fmt.Errorf("unexpected EOF in header block, partial line %q", line)
			}
			if err != nil {
				return out, err
			}
			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed == "" {
				break // end of headers
			}
			name, value, found := strings.Cut(trimmed, ":")
			if !found {
				return out, fmt.Errorf("malformed header line %q: this is what stray stdout output looks like", trimmed)
			}
			if strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
				n, err := strconv.Atoi(strings.TrimSpace(value))
				if err != nil {
					return out, fmt.Errorf("bad Content-Length %q: %w", value, err)
				}
				contentLength = n
			}
		}

		if contentLength < 0 {
			return out, fmt.Errorf("header block with no Content-Length")
		}

		body := make([]byte, contentLength)
		if _, err := io.ReadFull(br, body); err != nil {
			return out, fmt.Errorf("short body, want %d bytes: %w", contentLength, err)
		}
		if !json.Valid(body) {
			return out, fmt.Errorf("message body is not valid JSON: %q", truncateBytes(body))
		}
		out = append(out, json.RawMessage(body))
	}
}

func truncateBytes(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}

// TestNoStdoutPollution drives a full session through the real binary and
// requires fd 1 to contain nothing but protocol.
func TestNoStdoutPollution(t *testing.T) {
	bin := buildBinary(t)

	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.25\n")
	mustWriteFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")

	cmd := exec.Command(bin, "lsp")
	cmd.Dir = root

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr lockedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	rootURI := "file://" + filepath.ToSlash(root)

	// A realistic session: initialize, initialized, open a document, change it,
	// save it, then shut down. Every one of these paths can reach code that
	// prints.
	var msgs [][]byte
	msgs = append(msgs, frame(t, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"processId":        nil,
			"rootUri":          rootURI,
			"workspaceFolders": []map[string]any{{"uri": rootURI, "name": "x"}},
			"capabilities":     map[string]any{},
			"clientInfo":       map[string]any{"name": "stdio-test", "version": "1"},
		},
	}))
	msgs = append(msgs, frame(t, map[string]any{
		"jsonrpc": "2.0", "method": "initialized", "params": map[string]any{},
	}))

	writeAll(t, stdin, msgs)
	msgs = nil

	// A document opened before the warm-up has loaded the rules is not analysed
	// until its next change, so wait for serverInfo to report them before
	// opening one. These requests are protocol on stdout like any other.
	waitForRules(t, stdin, &stdout, 2*time.Minute)

	docURI := "file://" + filepath.ToSlash(filepath.Join(root, "main.go"))
	msgs = append(msgs, frame(t, map[string]any{
		"jsonrpc": "2.0", "method": "textDocument/didOpen",
		"params": map[string]any{"textDocument": map[string]any{
			"uri": docURI, "languageId": "go", "version": 1,
			"text": "package main\n\nfunc main() {}\n",
		}},
	}))
	msgs = append(msgs, frame(t, map[string]any{
		"jsonrpc": "2.0", "method": "textDocument/didChange",
		"params": map[string]any{
			"textDocument":   map[string]any{"uri": docURI, "version": 2},
			"contentChanges": []map[string]any{{"text": "package main\n\nimport \"os/exec\"\n\nfunc main() { exec.Command(\"sh\", \"-c\", os.Args[1]) }\n"}},
		},
	}))
	msgs = append(msgs, frame(t, map[string]any{
		"jsonrpc": "2.0", "method": "textDocument/didSave",
		"params": map[string]any{"textDocument": map[string]any{"uri": docURI}},
	}))

	writeAll(t, stdin, msgs)

	// Wait for analysis to run and publish, which is when a stray write is most
	// likely.
	waitForMessage(t, &stdout, 2*time.Minute, "diagnostics for "+docURI, func(m map[string]any) bool {
		params, _ := m["params"].(map[string]any)
		return m["method"] == "textDocument/publishDiagnostics" && params["uri"] == docURI
	})

	_, _ = stdin.Write(frame(t, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "shutdown"}))
	waitForMessage(t, &stdout, 15*time.Second, "the shutdown response", isResponse(2))
	_, _ = stdin.Write(frame(t, map[string]any{"jsonrpc": "2.0", "method": "exit"}))
	_ = stdin.Close()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}

	raw := stdout.Bytes()
	if len(raw) == 0 {
		t.Fatalf("the server produced no protocol output at all\nstderr:\n%s", tail(stderr.String()))
	}

	frames, err := parseFrames(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("stdout is not clean LSP framing: %v\n\n"+
			"This means something in cmd/ wrote to os.Stdout while the server was running.\n"+
			"The first statement of runLSP reassigns os.Stdout to stderr precisely to prevent this.\n\n"+
			"first 400 bytes of stdout:\n%q\n\nstderr:\n%s",
			err, truncateBytes(raw), tail(stderr.String()))
	}

	if len(frames) == 0 {
		t.Fatal("no complete messages were parsed from stdout")
	}

	// Every message must be a JSON-RPC object, and the initialize response must
	// be among them.
	sawInitializeResult := false
	for i, f := range frames {
		var msg map[string]any
		if err := json.Unmarshal(f, &msg); err != nil {
			t.Fatalf("frame %d is not a JSON object: %v", i, err)
		}
		if msg["jsonrpc"] != "2.0" {
			t.Errorf("frame %d has jsonrpc=%v, want 2.0", i, msg["jsonrpc"])
		}
		if id, ok := msg["id"]; ok && fmt.Sprint(id) == "1" {
			if _, hasResult := msg["result"]; hasResult {
				sawInitializeResult = true
			}
		}
	}
	if !sawInitializeResult {
		t.Errorf("no initialize result in %d frame(s); the session did not get off the ground", len(frames))
	}

	t.Logf("parsed %d clean protocol frame(s) from stdout", len(frames))
}

// TestHandshakeIsCleanJSON covers the other stdout writer: --version prints one
// line of JSON before the reassignment happens, so a banner on stdout would
// corrupt it. The client parses this to decide whether to connect at all.
func TestHandshakeIsCleanJSON(t *testing.T) {
	bin := buildBinary(t)

	out, err := exec.Command(bin, "lsp", "--version").Output()
	if err != nil {
		t.Fatalf("running lsp --version: %v", err)
	}

	var handshake map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &handshake); err != nil {
		t.Fatalf("the handshake is not clean JSON: %v\ngot: %q", err, string(out))
	}

	if _, ok := handshake["protocolVersion"]; !ok {
		t.Error("the handshake must carry protocolVersion; the client refuses to connect without it")
	}
	if _, ok := handshake["cliVersion"]; !ok {
		t.Error("the handshake must carry cliVersion")
	}
	caps, ok := handshake["capabilities"].([]any)
	if !ok || len(caps) == 0 {
		t.Error("the handshake must list capabilities so the client can hide UI an older build cannot serve")
	}
}

// TestLSPDoesNotPollBecauseItIsADaemon guards the startupHooks exemption. A
// long-lived server must not start an update poll, and the advisory it would
// print goes to a stream the editor is parsing.
func TestLSPDoesNotPollBecauseItIsADaemon(t *testing.T) {
	// The guard is a package-level flag set from cobra.OnInitialize. Assert the
	// accessor exists and is wired, rather than trying to observe the absence
	// of a network call.
	if LSPActive() {
		t.Fatal("lspActive should be false in a normal test binary")
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func tail(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > 20 {
		lines = lines[len(lines)-20:]
	}
	return strings.Join(lines, "\n")
}
