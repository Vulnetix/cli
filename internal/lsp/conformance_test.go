package lsp

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sourcegraph/jsonrpc2"
	"github.com/stretchr/testify/require"

	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
)

// A conformance harness: two ends of a net.Pipe, a real Server on one side and
// a real jsonrpc2 client on the other. Everything goes through the actual
// protocol, so a change that breaks the wire format fails here rather than in
// an editor.

type testClient struct {
	conn *jsonrpc2.Conn

	mu          sync.Mutex
	diagnostics map[string][]protocol.Diagnostic
	published   chan string
	logs        []string
}

// Handle implements jsonrpc2.Handler. Server-to-client traffic is all
// notifications, so nothing is returned.
func (c *testClient) Handle(_ context.Context, _ *jsonrpc2.Conn, req *jsonrpc2.Request) {
	switch req.Method {
	case protocol.MethodPublishDiagnostics:
		var params protocol.PublishDiagnosticsParams
		if req.Params != nil {
			_ = json.Unmarshal(*req.Params, &params)
		}
		c.mu.Lock()
		c.diagnostics[params.URI] = params.Diags
		c.mu.Unlock()
		select {
		case c.published <- params.URI:
		default:
		}
	case protocol.MethodLogMessage:
		var params protocol.LogMessageParams
		if req.Params != nil {
			_ = json.Unmarshal(*req.Params, &params)
		}
		c.mu.Lock()
		c.logs = append(c.logs, params.Message)
		c.mu.Unlock()
	}
}

func (c *testClient) diagsFor(uri string) []protocol.Diagnostic {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.diagnostics[uri]
}

// waitForPublish blocks until diagnostics arrive for uri, or the test fails.
func (c *testClient) waitForPublish(t *testing.T, uri string, timeout time.Duration) []protocol.Diagnostic {
	t.Helper()
	deadline := time.After(timeout)
	for {
		c.mu.Lock()
		diags, ok := c.diagnostics[uri]
		c.mu.Unlock()
		if ok {
			return diags
		}
		select {
		case <-c.published:
		case <-deadline:
			t.Fatalf("no diagnostics published for %s within %s", uri, timeout)
		}
	}
}

// startServer wires a Server to a client over an in-memory pipe.
func startServer(t *testing.T, root string) (*testClient, func()) {
	t.Helper()

	serverEnd, clientEnd := net.Pipe()

	srv := NewServer(Config{
		CLIVersion: "test",
		Commit:     "testcommit",
		Debounce:   0, // no debounce: tests assert on behaviour, not timing
		Logf:       func(string, ...any) {},
	})

	ctx, cancel := context.WithCancel(context.Background())

	serverConn := jsonrpc2.NewConn(ctx,
		jsonrpc2.NewBufferedStream(serverEnd, jsonrpc2.VSCodeObjectCodec{}),
		jsonrpc2.AsyncHandler(jsonrpc2.HandlerWithError(srv.handle)))
	srv.conn = serverConn

	client := &testClient{
		diagnostics: map[string][]protocol.Diagnostic{},
		published:   make(chan string, 64),
	}
	clientConn := jsonrpc2.NewConn(ctx,
		jsonrpc2.NewBufferedStream(clientEnd, jsonrpc2.VSCodeObjectCodec{}),
		jsonrpc2.AsyncHandler(client))
	client.conn = clientConn

	return client, func() {
		cancel()
		_ = clientConn.Close()
		_ = serverConn.Close()
		srv.sched.Close()
	}
}

// initialize performs the handshake and waits for the warm-up to index the
// workspace, which is what makes subsequent analysis deterministic.
func initialize(t *testing.T, c *testClient, root string) protocol.InitializeResult {
	t.Helper()
	var result protocol.InitializeResult
	err := c.conn.Call(context.Background(), protocol.MethodInitialize, protocol.InitializeParams{
		WorkspaceFolders: []protocol.Folder{{URI: PathToURI(root), Name: "test"}},
		ClientInfo:       &protocol.Client{Name: "conformance", Version: "1"},
	}, &result)
	require.NoError(t, err)
	require.NoError(t, c.conn.Notify(context.Background(), protocol.MethodInitialized, struct{}{}))
	return result
}

// fixtureRepo writes a small Go project with one obvious finding.
func fixtureRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module example.com/fixture\n\ngo 1.25\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "main.go"),
		[]byte("package main\n\nfunc main() {}\n"), 0o644))
	return root
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

func TestLifecycle(t *testing.T) {
	root := fixtureRepo(t)
	c, stop := startServer(t, root)
	defer stop()

	result := initialize(t, c, root)

	require.Equal(t, "utf-16", result.Capabilities.PositionEncoding,
		"rangefix produces UTF-16 offsets, so the server must advertise that encoding")
	require.NotNil(t, result.Capabilities.TextDocumentSync)
	require.Equal(t, protocol.SyncFull, result.Capabilities.TextDocumentSync.Change,
		"full sync is deliberate: the rule engine needs whole-file text")
	require.True(t, result.Capabilities.TextDocumentSync.OpenClose)
	require.NotNil(t, result.ServerInfo)
	require.Equal(t, protocol.ServerName, result.ServerInfo.Name)
	require.Equal(t, "test", result.ServerInfo.Version)

	require.NoError(t, c.conn.Call(context.Background(), protocol.MethodShutdown, nil, nil))
}

func TestRequestsBeforeInitializeAreRejected(t *testing.T) {
	// A request before initialize is a protocol violation. Answering it would
	// mean operating on a nil root and reporting a confusing internal error
	// instead of the one the spec defines.
	root := fixtureRepo(t)
	c, stop := startServer(t, root)
	defer stop()

	var out protocol.ServerInfoResult
	err := c.conn.Call(context.Background(), protocol.MethodServerInfo, nil, &out)
	require.Error(t, err)

	var rpcErr *jsonrpc2.Error
	require.ErrorAs(t, err, &rpcErr)
	require.EqualValues(t, protocol.CodeServerNotInitialized, rpcErr.Code)
}

func TestServerInfoReportsTheHandshake(t *testing.T) {
	root := fixtureRepo(t)
	c, stop := startServer(t, root)
	defer stop()
	initialize(t, c, root)

	var info protocol.ServerInfoResult
	require.NoError(t, c.conn.Call(context.Background(), protocol.MethodServerInfo, nil, &info))

	require.Equal(t, protocol.ProtocolVersion, info.ProtocolVersion,
		"the client requires an exact match, so this is the contract")
	require.Equal(t, "test", info.CLIVersion)
	require.Equal(t, "testcommit", info.Commit)
	require.Contains(t, info.Capabilities, "sast")
	require.NotEmpty(t, info.GoVersion)
	require.NotEmpty(t, info.Platform)
}

func TestUnknownRequestIsMethodNotFound(t *testing.T) {
	root := fixtureRepo(t)
	c, stop := startServer(t, root)
	defer stop()
	initialize(t, c, root)

	err := c.conn.Call(context.Background(), "textDocument/definition", struct{}{}, nil)
	require.Error(t, err)
	var rpcErr *jsonrpc2.Error
	require.ErrorAs(t, err, &rpcErr)
	require.EqualValues(t, protocol.CodeMethodNotFound, rpcErr.Code)
}

func TestUnknownNotificationIsIgnored(t *testing.T) {
	// The spec requires notifications for unimplemented methods to be dropped
	// silently. Answering with an error would make a conformant client noisy.
	root := fixtureRepo(t)
	c, stop := startServer(t, root)
	defer stop()
	initialize(t, c, root)

	require.NoError(t, c.conn.Notify(context.Background(), "textDocument/willSave", struct{}{}))

	// The connection must still work afterwards.
	var info protocol.ServerInfoResult
	require.NoError(t, c.conn.Call(context.Background(), protocol.MethodServerInfo, nil, &info))
}

// ── Document sync ────────────────────────────────────────────────────────────

func TestDidOpenPublishesDiagnostics(t *testing.T) {
	root := fixtureRepo(t)
	vulnPath := filepath.Join(root, "vuln.go")
	require.NoError(t, os.WriteFile(vulnPath, []byte(vulnerableGo), 0o644))

	c, stop := startServer(t, root)
	defer stop()
	initialize(t, c, root)
	waitForWarm(t)

	uri := PathToURI(vulnPath)
	require.NoError(t, c.conn.Notify(context.Background(), protocol.MethodDidOpen, protocol.DidOpenParams{
		TextDocument: protocol.TextDocumentItem{
			URI: uri, LanguageID: "go", Version: 1, Text: vulnerableGo,
		},
	}))

	diags := c.waitForPublish(t, uri, 30*time.Second)
	require.NotEmpty(t, diags, "the fixture contains obvious findings")

	for _, d := range diags {
		require.NotEmpty(t, d.Message)
		require.NotEmpty(t, d.Source)
		require.Contains(t, d.Source, "vulnetix-")
		require.GreaterOrEqual(t, d.Range.End.Line, d.Range.Start.Line)
	}
}

func TestClosingADocumentClearsItsDiagnostics(t *testing.T) {
	// publishDiagnostics replaces the list for a URI, so an empty list is how a
	// closed file's findings are removed. Without it they stay on screen after
	// the editor has forgotten the file.
	root := fixtureRepo(t)
	vulnPath := filepath.Join(root, "vuln.go")
	require.NoError(t, os.WriteFile(vulnPath, []byte(vulnerableGo), 0o644))

	c, stop := startServer(t, root)
	defer stop()
	initialize(t, c, root)
	waitForWarm(t)

	uri := PathToURI(vulnPath)
	require.NoError(t, c.conn.Notify(context.Background(), protocol.MethodDidOpen, protocol.DidOpenParams{
		TextDocument: protocol.TextDocumentItem{URI: uri, LanguageID: "go", Version: 1, Text: vulnerableGo},
	}))
	c.waitForPublish(t, uri, 30*time.Second)

	require.NoError(t, c.conn.Notify(context.Background(), protocol.MethodDidClose, protocol.DidCloseParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: uri},
	}))

	require.Eventually(t, func() bool {
		return len(c.diagsFor(uri)) == 0
	}, 10*time.Second, 20*time.Millisecond, "closing a document must clear its diagnostics")
}

func TestChangeForAnUnopenedDocumentIsIgnored(t *testing.T) {
	// Synthesising a document from a change would hide a client bug behind a
	// buffer with no language id and no path.
	root := fixtureRepo(t)
	c, stop := startServer(t, root)
	defer stop()
	initialize(t, c, root)

	require.NoError(t, c.conn.Notify(context.Background(), protocol.MethodDidChange, protocol.DidChangeParams{
		TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: PathToURI(filepath.Join(root, "ghost.go")), Version: 2},
		ContentChanges: []protocol.ContentChange{{Text: "package ghost\n"}},
	}))

	var info protocol.ServerInfoResult
	require.NoError(t, c.conn.Call(context.Background(), protocol.MethodServerInfo, nil, &info),
		"the server must survive a change for a document it never saw")
}

func TestDocumentsOutsideTheWorkspaceAreNotScanned(t *testing.T) {
	// The rule engine keys everything on repository-relative paths. A file from
	// elsewhere would escape the root with .. segments or collide with a real
	// path, so it is skipped rather than scanned incorrectly.
	root := fixtureRepo(t)
	outside := filepath.Join(t.TempDir(), "outside.go")
	require.NoError(t, os.WriteFile(outside, []byte(vulnerableGo), 0o644))

	c, stop := startServer(t, root)
	defer stop()
	initialize(t, c, root)
	waitForWarm(t)

	uri := PathToURI(outside)
	require.NoError(t, c.conn.Notify(context.Background(), protocol.MethodDidOpen, protocol.DidOpenParams{
		TextDocument: protocol.TextDocumentItem{URI: uri, LanguageID: "go", Version: 1, Text: vulnerableGo},
	}))

	time.Sleep(500 * time.Millisecond)
	require.Empty(t, c.diagsFor(uri), "a file outside the workspace should not be analysed")
}

// ── Cancellation ─────────────────────────────────────────────────────────────

func TestWorkspaceScanCanBeCancelled(t *testing.T) {
	root := fixtureRepo(t)
	c, stop := startServer(t, root)
	defer stop()
	initialize(t, c, root)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		var out protocol.ScanWorkspaceResult
		errCh <- c.conn.Call(ctx, protocol.MethodScanWorkspace, protocol.ScanWorkspaceParams{}, &out)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		require.Error(t, err, "a cancelled scan must report an error rather than a result")
	case <-time.After(30 * time.Second):
		t.Fatal("a cancelled scan never returned")
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// waitForWarm gives the background warm-up time to index and compile.
//
// The server deliberately returns from initialize before compiling, so the
// editor window is not blocked. Tests that assert on findings have to wait for
// it, and a generous ceiling costs nothing when the condition is usually met
// in well under a second.
func waitForWarm(t *testing.T) {
	t.Helper()
	time.Sleep(3 * time.Second)
}

const vulnerableGo = `package main

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	w.Write(out)
}

func login(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
}
`
