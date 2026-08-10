package lsp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sourcegraph/jsonrpc2"

	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
	"github.com/vulnetix/cli/v3/internal/sast"
)

// Config is what the process supplies to the server.
type Config struct {
	// CLIVersion, Commit and BuildDate come from the ldflags-injected build
	// metadata and are reported in the handshake.
	CLIVersion string
	Commit     string
	BuildDate  string

	// Debounce is the quiet period after a change before analysis runs.
	Debounce time.Duration

	// MaxTotalBytes caps how much file content is held in memory at once.
	// Zero means unlimited, which is the CLI default and the wrong choice for a
	// long-lived process.
	MaxTotalBytes int64

	// Logf receives server-side log lines. Never stdout: that is the JSON-RPC
	// channel. Nil discards.
	Logf func(format string, args ...any)
}

func (c Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// Server implements the Vulnetix language server.
type Server struct {
	cfg   Config
	conn  *jsonrpc2.Conn
	docs  *DocumentStore
	sched *Scheduler

	// session holds compiled rule sets across evaluations. This is what makes
	// analysis on a keystroke viable rather than a fresh compile each time.
	session *sast.Session

	mu sync.Mutex
	// rootPath is the first workspace folder's filesystem path. Multi-root is
	// M2; until then everything is relative to one root.
	rootPath string
	// baseInput is the last full index: the file set and per-directory language
	// map. Shared read-only into every overlay evaluation.
	baseInput *sast.ScanInput
	// modules is the loaded rule corpus.
	modules map[string]string
	// initialized gates request handling. A request before initialize is a
	// protocol violation and gets ServerNotInitialized rather than a confusing
	// nil dereference.
	initialized bool
	shutdownReq bool

	// severity is how findings map onto LSP severities.
	severity SeverityMapping
}

// NewServer constructs a server. Serve wires it to a connection.
func NewServer(cfg Config) *Server {
	if cfg.Debounce == 0 {
		cfg.Debounce = 400 * time.Millisecond
	}
	return &Server{
		cfg:     cfg,
		docs:    NewDocumentStore(),
		sched:   NewScheduler(cfg.Debounce),
		session: &sast.Session{},
	}
}

// Serve runs the server over the given streams until the connection closes.
//
// r and w are the JSON-RPC channel. The caller is responsible for making sure
// nothing else in the process writes to w: cmd/ writes to os.Stdout in 144
// places, and a single stray byte desynchronises the framing and the client
// hard-fails. See cmd/lsp.go.
func Serve(ctx context.Context, r io.Reader, w io.Writer, cfg Config) error {
	srv := NewServer(cfg)

	stream := jsonrpc2.NewBufferedStream(rwc{r: r, w: w}, jsonrpc2.VSCodeObjectCodec{})

	// AsyncHandler is required, not a tuning choice. Without it a long
	// workspace scan blocks the read loop, so $/cancelRequest cannot be
	// delivered and the scan the user asked to stop runs to completion.
	handler := jsonrpc2.AsyncHandler(jsonrpc2.HandlerWithError(srv.handle))

	conn := jsonrpc2.NewConn(ctx, stream, handler)
	srv.conn = conn

	select {
	case <-conn.DisconnectNotify():
	case <-ctx.Done():
		_ = conn.Close()
	}

	srv.sched.Close()
	return nil
}

// rwc adapts a reader and a writer into the ReadWriteCloser the stream wants.
//
// Close is a no-op on purpose: the reader is the process's stdin and the writer
// its stdout, and closing either would take the process down in a way the
// caller cannot control. Shutdown is the caller's business.
type rwc struct {
	r io.Reader
	w io.Writer
}

func (s rwc) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s rwc) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s rwc) Close() error                { return nil }

// handle dispatches one request.
func (s *Server) handle(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) (any, error) {
	// Lifecycle methods are handled before the initialized gate, since they are
	// what opens it.
	switch req.Method {
	case protocol.MethodInitialize:
		return s.onInitialize(ctx, req)
	case protocol.MethodInitialized:
		return nil, nil
	case protocol.MethodShutdown:
		s.mu.Lock()
		s.shutdownReq = true
		s.mu.Unlock()
		s.sched.Close()
		return nil, nil
	case protocol.MethodExit:
		_ = conn.Close()
		return nil, nil
	case protocol.MethodSetTrace:
		return nil, nil
	}

	s.mu.Lock()
	ready := s.initialized
	s.mu.Unlock()
	if !ready {
		return nil, &jsonrpc2.Error{
			Code:    protocol.CodeServerNotInitialized,
			Message: "server has not been initialized",
		}
	}

	switch req.Method {
	case protocol.MethodDidOpen:
		return nil, s.onDidOpen(req)
	case protocol.MethodDidChange:
		return nil, s.onDidChange(req)
	case protocol.MethodDidSave:
		return nil, s.onDidSave(req)
	case protocol.MethodDidClose:
		return nil, s.onDidClose(req)
	case protocol.MethodServerInfo:
		return s.serverInfo(), nil
	case protocol.MethodScanWorkspace:
		return s.onScanWorkspace(ctx, req)
	}

	// Notifications for methods the server does not implement are ignored
	// rather than answered with an error: the spec requires it, and a client
	// sending one is not doing anything wrong.
	if req.Notif {
		return nil, nil
	}
	return nil, &jsonrpc2.Error{
		Code:    protocol.CodeMethodNotFound,
		Message: fmt.Sprintf("method not supported: %s", req.Method),
	}
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

func (s *Server) onInitialize(ctx context.Context, req *jsonrpc2.Request) (any, error) {
	var params protocol.InitializeParams
	if err := unmarshalParams(req, &params); err != nil {
		return nil, err
	}

	root := ""
	if len(params.WorkspaceFolders) > 0 {
		if p, ok := URIToPath(params.WorkspaceFolders[0].URI); ok {
			root = p
		}
	}
	if root == "" && params.RootURI != "" {
		if p, ok := URIToPath(params.RootURI); ok {
			root = p
		}
	}

	s.mu.Lock()
	s.rootPath = root
	s.initialized = true
	s.mu.Unlock()

	client := "unknown client"
	if params.ClientInfo != nil {
		client = strings.TrimSpace(params.ClientInfo.Name + " " + params.ClientInfo.Version)
	}
	s.cfg.logf("initialize from %s, root %q", client, root)

	// Warm the rule set in the background. initialize must return promptly:
	// the editor blocks on it, and the user is looking at a window that has not
	// finished opening.
	go s.warm(context.WithoutCancel(ctx))

	save := &protocol.SaveOptions{IncludeText: false}
	return protocol.InitializeResult{
		Capabilities: protocol.ServerCaps{
			PositionEncoding: "utf-16",
			TextDocumentSync: &protocol.TextDocumentSyncOptions{
				OpenClose: true,
				Change:    protocol.SyncFull,
				Save:      save,
			},
			Workspace: &protocol.WorkspaceCaps{
				WorkspaceFolders: &protocol.WorkspaceFoldersCaps{
					Supported:           true,
					ChangeNotifications: true,
				},
			},
		},
		ServerInfo: &protocol.ServerInfo{
			Name:    protocol.ServerName,
			Version: s.cfg.CLIVersion,
		},
	}, nil
}

// warm loads the rule corpus and indexes the workspace, then compiles the
// interactive rule set so the first keystroke does not pay for it.
func (s *Server) warm(ctx context.Context) {
	s.mu.Lock()
	root := s.rootPath
	s.mu.Unlock()
	if root == "" {
		return
	}

	start := time.Now()
	modules, err := sast.LoadAllModules(sast.DefaultRulesFS, false, nil, "", io.Discard)
	if err != nil {
		s.cfg.logf("could not load rules: %v", err)
		return
	}

	input, err := sast.BuildScanInputContext(ctx, root, sast.BuildOptions{
		MaxDepth:         3,
		RespectGitignore: true,
		// Git history walks hundreds of commits and thousands of file
		// versions. That is a CI job, not something to do while someone is
		// typing, so it is off unless a workspace scan asks for it.
		IgnoreGit: true,
	})
	if err != nil {
		if ctx.Err() == nil {
			s.cfg.logf("could not index the workspace: %v", err)
		}
		return
	}

	s.mu.Lock()
	s.modules = modules
	s.baseInput = input
	s.mu.Unlock()

	s.cfg.logf("indexed %d file(s) in %s", len(input.FileSet), time.Since(start).Round(time.Millisecond))

	// Compile the interactive kinds now. Secrets are excluded: they are 92% of
	// evaluation cost and cannot fire until the user has finished typing the
	// credential anyway.
	compileStart := time.Now()
	if _, err := s.session.Prepare(ctx, modules, sast.InteractiveKinds); err != nil {
		if ctx.Err() == nil {
			s.cfg.logf("could not compile rules: %v", err)
		}
		return
	}
	s.cfg.logf("compiled the interactive rule set in %s", time.Since(compileStart).Round(time.Millisecond))
}

func (s *Server) serverInfo() protocol.ServerInfoResult {
	s.mu.Lock()
	modules := s.modules
	s.mu.Unlock()

	kinds := map[string]int{}
	total := 0
	if modules != nil {
		kinds = sast.CountByKind(modules)
		total = len(modules)
	}

	return protocol.ServerInfoResult{
		ProtocolVersion: protocol.ProtocolVersion,
		CLIVersion:      s.cfg.CLIVersion,
		Commit:          s.cfg.Commit,
		BuildDate:       s.cfg.BuildDate,
		GoVersion:       runtime.Version(),
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		Capabilities:    []string{"sast", "secrets", "iac", "containers"},
		RulesEmbedded:   total,
		RuleKinds:       kinds,
	}
}

// ── Document sync ────────────────────────────────────────────────────────────

func (s *Server) onDidOpen(req *jsonrpc2.Request) error {
	var params protocol.DidOpenParams
	if err := unmarshalParams(req, &params); err != nil {
		return err
	}

	rel, ok := s.relPath(params.TextDocument.URI)
	if !ok {
		// A file outside every workspace folder cannot be keyed against the
		// repository-relative paths the rule engine uses, so it is not scanned
		// rather than scanned incorrectly.
		return nil
	}

	s.docs.Open(params.TextDocument.URI, params.TextDocument.LanguageID,
		params.TextDocument.Version, params.TextDocument.Text, rel)

	s.scheduleDocument(params.TextDocument.URI)
	return nil
}

func (s *Server) onDidChange(req *jsonrpc2.Request) error {
	var params protocol.DidChangeParams
	if err := unmarshalParams(req, &params); err != nil {
		return err
	}
	if len(params.ContentChanges) == 0 {
		return nil
	}

	// Full sync is advertised, so the last change carries the whole document.
	text := params.ContentChanges[len(params.ContentChanges)-1].Text
	if _, ok := s.docs.Update(params.TextDocument.URI, params.TextDocument.Version, text); !ok {
		return nil
	}

	s.scheduleDocument(params.TextDocument.URI)
	return nil
}

func (s *Server) onDidSave(req *jsonrpc2.Request) error {
	var params protocol.DidSaveParams
	if err := unmarshalParams(req, &params); err != nil {
		return err
	}

	// Save adds the secret rules, which are deliberately skipped while typing.
	uri := params.TextDocument.URI
	s.sched.RunDocumentNow(uri, func(ctx context.Context) {
		s.analyseDocument(ctx, uri, sast.AllKinds)
	})
	return nil
}

func (s *Server) onDidClose(req *jsonrpc2.Request) error {
	var params protocol.DidCloseParams
	if err := unmarshalParams(req, &params); err != nil {
		return err
	}

	s.sched.CancelDocument(params.TextDocument.URI)
	s.docs.Close(params.TextDocument.URI)

	// Clear the document's diagnostics. publishDiagnostics replaces the list
	// for a URI, so an empty list is how a closed file's findings are removed
	// rather than left on screen.
	s.publish(params.TextDocument.URI, nil)
	return nil
}

func (s *Server) scheduleDocument(uri string) {
	s.sched.ScheduleDocument(uri, func(ctx context.Context) {
		s.analyseDocument(ctx, uri, sast.InteractiveKinds)
	})
}

// analyseDocument evaluates one document and publishes its diagnostics.
//
// kinds decides the cost: the interactive set on a keystroke, everything on
// save. This path never touches the network, which is a structural property
// rather than a policy: it calls the rule session directly and has no client
// for anything else.
func (s *Server) analyseDocument(ctx context.Context, uri string, kinds []string) {
	doc, ok := s.docs.Get(uri)
	if !ok {
		return
	}

	s.mu.Lock()
	modules := s.modules
	base := s.baseInput
	severity := s.severity
	s.mu.Unlock()

	if modules == nil {
		// Still warming. The document is analysed when the warm-up finishes and
		// the next change arrives; publishing nothing is better than publishing
		// an empty list, which would read as "clean".
		return
	}

	set, err := s.session.Prepare(ctx, modules, kinds)
	if err != nil {
		if ctx.Err() == nil {
			s.cfg.logf("could not prepare rules for %s: %v", uri, err)
		}
		return
	}

	input := sast.Overlay(base, map[string]string{doc.RelPath: doc.Text})

	report, err := s.session.Eval(ctx, set, input)
	if err != nil {
		if ctx.Err() == nil {
			s.cfg.logf("could not evaluate %s: %v", uri, err)
		}
		return
	}

	// A cancelled evaluation must not publish: its result describes text the
	// user has already replaced.
	if ctx.Err() != nil {
		return
	}

	docs := map[string]docText{doc.RelPath: {URI: uri, Text: doc.Text}}
	byURI := GroupByURI(report.Findings, docs, severity)
	s.publish(uri, byURI[uri])
}

// ── Workspace scan ───────────────────────────────────────────────────────────

func (s *Server) onScanWorkspace(ctx context.Context, req *jsonrpc2.Request) (any, error) {
	var params protocol.ScanWorkspaceParams
	if req.Params != nil {
		_ = unmarshalParams(req, &params)
	}

	start := time.Now()
	scanID := fmt.Sprintf("scan-%d", start.UnixNano())

	var result protocol.ScanWorkspaceResult
	var scanErr error

	done := s.sched.RunWorkspace(func(scanCtx context.Context) {
		result, scanErr = s.runWorkspaceScan(scanCtx, params)
	})

	select {
	case <-done:
	case <-ctx.Done():
		s.sched.CancelWorkspace()
		return nil, &jsonrpc2.Error{
			Code:    protocol.CodeRequestCancelled,
			Message: "scan cancelled",
		}
	}

	if scanErr != nil {
		return nil, &jsonrpc2.Error{Code: protocol.CodeInternalError, Message: scanErr.Error()}
	}

	result.ProtocolVersion = protocol.ProtocolVersion
	result.ScanID = scanID
	result.DurationMS = time.Since(start).Milliseconds()
	return result, nil
}

func (s *Server) runWorkspaceScan(ctx context.Context, params protocol.ScanWorkspaceParams) (protocol.ScanWorkspaceResult, error) {
	var result protocol.ScanWorkspaceResult

	s.mu.Lock()
	root := s.rootPath
	modules := s.modules
	severity := s.severity
	s.mu.Unlock()

	if root == "" {
		return result, fmt.Errorf("no workspace folder")
	}
	if modules == nil {
		return result, fmt.Errorf("rules are still loading")
	}

	input, err := sast.BuildScanInputContext(ctx, root, sast.BuildOptions{
		MaxDepth:         3,
		RespectGitignore: true,
		IgnoreGit:        !params.GitHistory,
		GitHistory:       params.GitHistory,
	})
	if err != nil {
		return result, err
	}

	load, err := sast.LoadFileContentsBudgeted(ctx, input, sast.LoadOptions{
		MaxFileSize: 1 << 20,
	}, s.cfg.MaxTotalBytes)
	if err != nil {
		return result, err
	}
	result.Degradations = load.Degradations()

	// The editor's version of any open buffer wins over what is on disk, so a
	// workspace scan reflects unsaved work rather than contradicting the
	// diagnostics already on screen.
	input = sast.OverlayOnto(input, s.docs.Snapshot())

	set, err := s.session.Prepare(ctx, modules, sast.AllKinds)
	if err != nil {
		return result, err
	}

	report, err := s.session.Eval(ctx, set, input)
	if err != nil {
		return result, err
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}

	// Diagnostics are published only for open documents: a range needs the
	// current text, and a closed file has none the client would agree with.
	// The counts cover everything, so the summary is complete even though the
	// squiggles are not.
	docs := map[string]docText{}
	for uri, text := range s.openDocsByRelPath() {
		docs[uri] = text
	}
	byURI := GroupByURI(report.Findings, docs, severity)
	for uri, diags := range byURI {
		s.publish(uri, diags)
	}

	result.Counts = protocol.ScanCounts{
		Total:      len(report.Findings),
		BySeverity: countFindings(report.Findings),
	}
	result.Degradations = append(result.Degradations, report.Degradations...)
	return result, nil
}

// openDocsByRelPath keys the open buffers by repository-relative path, which is
// how findings identify their file, while carrying the URI the diagnostics have
// to be published against.
func (s *Server) openDocsByRelPath() map[string]docText {
	out := map[string]docText{}
	for _, doc := range s.docs.All() {
		if doc.RelPath != "" {
			out[doc.RelPath] = docText{URI: doc.URI, Text: doc.Text}
		}
	}
	return out
}

func countFindings(findings []sast.Finding) map[string]int {
	counts := map[string]int{}
	for _, f := range findings {
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if sev == "" {
			sev = "info"
		}
		counts[sev]++
	}
	return counts
}

// ── Outbound ─────────────────────────────────────────────────────────────────

// publish sends diagnostics for one URI.
//
// A nil slice is sent as an empty array rather than JSON null, because null is
// not a valid diagnostics list and some clients drop the message instead of
// clearing.
func (s *Server) publish(uri string, diags []protocol.Diagnostic) {
	if s.conn == nil {
		return
	}
	if diags == nil {
		diags = []protocol.Diagnostic{}
	}
	params := protocol.PublishDiagnosticsParams{URI: uri, Diags: diags}
	if err := s.conn.Notify(context.Background(), protocol.MethodPublishDiagnostics, params); err != nil {
		s.cfg.logf("could not publish diagnostics for %s: %v", uri, err)
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func (s *Server) relPath(uri string) (string, bool) {
	s.mu.Lock()
	root := s.rootPath
	s.mu.Unlock()
	if root == "" {
		return "", false
	}
	return RelPathFor(root, uri)
}

// unmarshalParams decodes a request's params, reporting a protocol-level
// InvalidParams rather than a generic failure so the client can tell a
// malformed message from a server bug.
func unmarshalParams(req *jsonrpc2.Request, out any) error {
	if req.Params == nil {
		return nil
	}
	if err := json.Unmarshal(*req.Params, out); err != nil {
		return &jsonrpc2.Error{
			Code:    protocol.CodeInvalidParams,
			Message: fmt.Sprintf("could not decode %s params: %v", req.Method, err),
		}
	}
	return nil
}

// DefaultLogger writes server logs to stderr, which is where they belong: the
// JSON-RPC channel owns stdout.
func DefaultLogger(prefix string) func(string, ...any) {
	return func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, prefix+format+"\n", args...)
	}
}
