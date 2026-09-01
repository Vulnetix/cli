package lsp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

	// settings is the validated client configuration. Replaced wholesale on
	// workspace/didChangeConfiguration; never read field-by-field from raw JSON.
	settings Settings

	// sca owns the dependency picture and is the only part of this server that
	// talks to the network. Kept separate from the rule session so the local-only
	// property of code analysis stays visible in the type.
	sca *scaEngine

	// suppressions filters findings from every family before they are published.
	suppressions *suppressionStore

	// diagMu guards the per-family diagnostic caches below.
	//
	// publishDiagnostics replaces the whole list for a URI, so code findings and
	// dependency findings cannot be published independently: the second publish
	// would erase the first. They are cached separately, because they refresh on
	// different triggers, and sent as one merged list.
	diagMu   sync.Mutex
	codeDiag map[string][]protocol.Diagnostic
	depDiag  map[string][]protocol.Diagnostic
}

// NewServer constructs a server. Serve wires it to a connection.
func NewServer(cfg Config) *Server {
	if cfg.Debounce == 0 {
		cfg.Debounce = 400 * time.Millisecond
	}
	return &Server{
		cfg:          cfg,
		docs:         NewDocumentStore(),
		sched:        NewScheduler(cfg.Debounce),
		session:      &sast.Session{},
		settings:     DefaultSettings(),
		sca:          newSCAEngine(cfg.CLIVersion, cfg.logf),
		suppressions: newSuppressionStore(),
		codeDiag:     map[string][]protocol.Diagnostic{},
		depDiag:      map[string][]protocol.Diagnostic{},
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
	case protocol.MethodHover:
		return s.onHover(req)
	case protocol.MethodCodeAction:
		return s.onCodeAction(req)
	case protocol.MethodInlayHint:
		return s.onInlayHint(req)
	case protocol.MethodDidChangeConfiguration:
		return nil, s.onDidChangeConfiguration(req)
	case protocol.MethodDidChangeWatchedFiles:
		return nil, s.onDidChangeWatchedFiles(req)
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

	// Settings arrive before the first scan when the client sends them here,
	// which matters: didChangeConfiguration lands after initialize, and a scan
	// started in between would run against defaults the user had overridden.
	if len(params.InitializationOptions) > 0 {
		var raw map[string]any
		if err := json.Unmarshal(params.InitializationOptions, &raw); err == nil {
			s.applySettings(raw)
		} else {
			s.cfg.logf("could not decode initializationOptions: %v", err)
		}
	}
	if root != "" {
		s.mu.Lock()
		settings := s.settings
		s.mu.Unlock()
		s.suppressions.Reload(root, settings)
	}

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

	s.mu.Lock()
	scaEnabled := s.settings.SCA.Enabled
	s.mu.Unlock()
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

			// The dependency features are advertised together with the SCA path
			// that feeds them. With SCA off they would answer nothing on every
			// request, which costs a round trip per hover to say so.
			Hover:      scaEnabled,
			CodeAction: codeActionCaps(scaEnabled),
			InlayHint:  scaEnabled,
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

	// Dependency analysis runs after the rule set is ready, not before. Code
	// findings are local and instant; the dependency check is a network round
	// trip, and making the user wait on it for the squiggles that do not need it
	// would be the wrong trade.
	s.runDependencyScan(ctx)
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
		Capabilities:    s.capabilityList(),
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

	// Opening a manifest is what triggers the deferred Safe-Harbour lookup. The
	// bulk pass already said which packages are vulnerable; ranked replacement
	// versions are only worth fetching for a file someone is looking at.
	if s.sca.IsManifest(rel) {
		s.refreshDependencyDiagnostics(params.TextDocument.URI, rel, params.TextDocument.Text)
		s.scheduleSafeVersions(params.TextDocument.URI, rel)
	}
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
	doc, ok := s.docs.Update(params.TextDocument.URI, params.TextDocument.Version, text)
	if !ok {
		return nil
	}

	s.scheduleDocument(params.TextDocument.URI)

	// Re-anchor dependency findings against the edited text. This is a local
	// recomputation from cached verdicts and never touches the network, so it is
	// safe on a keystroke: it keeps the squiggle on the right line while the user
	// types rather than letting it drift until the next save.
	if s.sca.IsManifest(doc.RelPath) {
		s.refreshDependencyDiagnostics(params.TextDocument.URI, doc.RelPath, text)
	}
	return nil
}

func (s *Server) onDidSave(req *jsonrpc2.Request) error {
	var params protocol.DidSaveParams
	if err := unmarshalParams(req, &params); err != nil {
		return err
	}

	// Save adds the secret rules, which are deliberately skipped while typing.
	uri := params.TextDocument.URI

	// A saved manifest is re-parsed and re-checked. Deferring the network call to
	// save rather than running it on a keystroke is the whole reason a version
	// being typed one character at a time does not produce a request per digit.
	if doc, ok := s.docs.Get(uri); ok && s.sca.IsManifest(doc.RelPath) {
		s.rescanManifest()
	}

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
	s.forgetDiagnostics(params.TextDocument.URI)

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
	s.setCodeDiagnostics(uri, byURI[uri])
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

// ── Merged publishing ────────────────────────────────────────────────────────

// setCodeDiagnostics records the rule engine's findings for a document and
// republishes.
func (s *Server) setCodeDiagnostics(uri string, diags []protocol.Diagnostic) {
	s.diagMu.Lock()
	s.codeDiag[uri] = diags
	s.diagMu.Unlock()
	s.publishMerged(uri)
}

// setDependencyDiagnostics records the SCA findings for a document and
// republishes.
func (s *Server) setDependencyDiagnostics(uri string, diags []protocol.Diagnostic) {
	s.diagMu.Lock()
	s.depDiag[uri] = diags
	s.diagMu.Unlock()
	s.publishMerged(uri)
}

// forgetDiagnostics drops both caches for a closed document.
func (s *Server) forgetDiagnostics(uri string) {
	s.diagMu.Lock()
	delete(s.codeDiag, uri)
	delete(s.depDiag, uri)
	s.diagMu.Unlock()
}

// publishMerged sends the union of the two families for a URI, after
// suppression.
//
// Filtering happens here rather than at each producer so a suppression rule
// covers every family with one implementation, and so a rule added while a file
// is open takes effect on the next publish without re-running any scan.
func (s *Server) publishMerged(uri string) {
	s.diagMu.Lock()
	code := s.codeDiag[uri]
	deps := s.depDiag[uri]
	s.diagMu.Unlock()

	merged := make([]protocol.Diagnostic, 0, len(code)+len(deps))
	merged = append(merged, code...)
	merged = append(merged, deps...)

	s.mu.Lock()
	showSuppressed := s.settings.ShowSuppressed
	floor := s.settings.MinimumSeverity
	s.mu.Unlock()

	merged = aboveSeverityFloor(merged, floor)

	rel, ok := s.relPath(uri)
	if !ok {
		rel = uri
	}
	s.publish(uri, s.suppressions.Filter(rel, merged, showSuppressed))
}

// ── Settings ─────────────────────────────────────────────────────────────────

// applySettings validates a raw configuration object and adopts it.
//
// Everything downstream reads the validated struct, so an out-of-range value
// changes a log line and nothing else. That is the requirement: a scanner that
// stops working because of a typo in settings.json is indistinguishable from a
// broken one.
func (s *Server) applySettings(raw map[string]any) {
	next := ParseSettings(vulnetixSection(raw), s.cfg.logf)

	s.mu.Lock()
	s.settings = next
	s.severity = SeverityMapping{LowAsHint: next.LowAsHint}
	root := s.rootPath
	s.mu.Unlock()

	s.sched.SetDebounce(next.Debounce)
	s.sca.SetSettings(next.SCA)
	if root != "" {
		s.suppressions.Reload(root, next)
	}

	// A settings change can hide or reveal findings without any file changing,
	// so every open document is republished from cache rather than rescanned.
	for _, doc := range s.docs.All() {
		s.publishMerged(doc.URI)
	}
}

// vulnetixSection unwraps the client's settings envelope.
//
// vscode-languageclient sends the whole configuration tree under the section
// name it was told to synchronise, while initializationOptions carries the
// section's contents directly. Accepting both means neither shape silently does
// nothing.
func vulnetixSection(raw map[string]any) map[string]any {
	if raw == nil {
		return nil
	}
	if inner, ok := raw["vulnetix"].(map[string]any); ok {
		return inner
	}
	return raw
}

// ── Dependency analysis ──────────────────────────────────────────────────────

// runDependencyScan performs the bulk declared-dependency check and publishes
// the result into every open manifest.
//
// Failure is logged and otherwise ignored on purpose. There is no network in an
// air-gapped checkout and no credentials in some CI images; in both cases the
// right behaviour is code analysis without dependency analysis, not a broken
// server.
func (s *Server) runDependencyScan(ctx context.Context) {
	s.mu.Lock()
	root := s.rootPath
	enabled := s.settings.SCA.Enabled
	s.mu.Unlock()

	if root == "" || !enabled {
		return
	}

	if err := s.sca.Discover(root, s.docs.Snapshot()); err != nil {
		s.cfg.logf("sca: %v", err)
		return
	}
	if err := s.sca.RunBulk(ctx); err != nil {
		s.cfg.logf("sca: %v", err)
		return
	}

	for _, doc := range s.docs.All() {
		if s.sca.IsManifest(doc.RelPath) {
			s.refreshDependencyDiagnostics(doc.URI, doc.RelPath, doc.Text)
			s.scheduleSafeVersions(doc.URI, doc.RelPath)
		}
	}
}

// refreshDependencyDiagnostics recomputes a manifest's dependency diagnostics
// from cached verdicts. No network, so it is safe on a keystroke.
func (s *Server) refreshDependencyDiagnostics(uri, relPath, text string) {
	s.mu.Lock()
	severity := s.severity
	enabled := s.settings.SCA.Enabled
	s.mu.Unlock()

	if !enabled || !s.sca.Ready() {
		return
	}
	s.setDependencyDiagnostics(uri, s.sca.SCADiagnostics(relPath, text, severity))
}

// scheduleSafeVersions resolves Safe-Harbour for the open manifest in the
// background.
//
// Deferred to an open document and run off the request path: the answer takes a
// round trip, and blocking didOpen on it would delay every other feature for a
// file the user can already see findings in.
func (s *Server) scheduleSafeVersions(uri, relPath string) {
	s.mu.Lock()
	enabled := s.settings.SCA.Enabled
	s.mu.Unlock()
	if !enabled || uri == "" || relPath == "" {
		return
	}

	go func() {
		ctx := context.Background()

		// Publish once up front so the pending markers appear while the lookup
		// runs, which is what turns a missing fix into a visible "not yet".
		if doc, ok := s.docs.Get(uri); ok {
			s.refreshDependencyDiagnostics(uri, relPath, doc.Text)
		}

		changed, err := s.sca.EnsureSafeVersions(ctx, relPath)
		if err != nil {
			s.cfg.logf("sca: %v", err)
		}
		if len(changed) == 0 {
			return
		}
		if doc, ok := s.docs.Get(uri); ok {
			s.refreshDependencyDiagnostics(uri, relPath, doc.Text)
		}
	}()
}

// rescanManifest re-parses the workspace manifests and re-checks anything new.
//
// Triggered by a save or by a watched file changing on disk. The whole set is
// re-parsed rather than the one file, because a lockfile and the manifest that
// declares against it are one unit: editing either changes what the other means.
func (s *Server) rescanManifest() {
	s.mu.Lock()
	root := s.rootPath
	enabled := s.settings.SCA.Enabled
	s.mu.Unlock()

	if root == "" || !enabled {
		return
	}

	go func() {
		ctx := context.Background()
		if err := s.sca.Discover(root, s.docs.Snapshot()); err != nil {
			s.cfg.logf("sca: %v", err)
			return
		}
		if err := s.sca.RunBulk(ctx); err != nil {
			s.cfg.logf("sca: %v", err)
			return
		}
		for _, doc := range s.docs.All() {
			if !s.sca.IsManifest(doc.RelPath) {
				continue
			}
			s.refreshDependencyDiagnostics(doc.URI, doc.RelPath, doc.Text)
			// Re-resolving Safe-Harbour for every open manifest, not just the
			// saved one: a lockfile rewrite changes which packages are present
			// everywhere in the group, not only in the file that was written.
			s.scheduleSafeVersions(doc.URI, doc.RelPath)
		}
	}()
}

// ── Dependency requests ──────────────────────────────────────────────────────

// onHover answers with the dependency card for a manifest position.
//
// A position that is not on a known dependency answers null rather than an
// empty card, so the editor shows nothing instead of an empty popup.
func (s *Server) onHover(req *jsonrpc2.Request) (any, error) {
	var params protocol.HoverParams
	if err := unmarshalParams(req, &params); err != nil {
		return nil, err
	}
	doc, ok := s.docs.Get(params.TextDocument.URI)
	if !ok || doc.RelPath == "" {
		return nil, nil
	}
	return s.sca.Hover(doc.RelPath, doc.Text, params.Position), nil
}

// onCodeAction offers the version bumps for dependencies in the requested
// range.
func (s *Server) onCodeAction(req *jsonrpc2.Request) (any, error) {
	var params protocol.CodeActionParams
	if err := unmarshalParams(req, &params); err != nil {
		return nil, err
	}
	doc, ok := s.docs.Get(params.TextDocument.URI)
	if !ok || doc.RelPath == "" {
		return []protocol.CodeAction{}, nil
	}
	actions := s.sca.CodeActions(doc.RelPath, doc.Text, params.TextDocument.URI, params.Range)
	if actions == nil {
		// An empty array, not null: null is not a valid result for this request
		// and clients differ on how gracefully they handle it.
		actions = []protocol.CodeAction{}
	}
	return actions, nil
}

// onInlayHint answers with the per-dependency status markers.
func (s *Server) onInlayHint(req *jsonrpc2.Request) (any, error) {
	var params protocol.InlayHintParams
	if err := unmarshalParams(req, &params); err != nil {
		return nil, err
	}
	doc, ok := s.docs.Get(params.TextDocument.URI)
	if !ok || doc.RelPath == "" {
		return []protocol.InlayHint{}, nil
	}
	hints := s.sca.InlayHints(doc.RelPath, doc.Text, params.Range)
	if hints == nil {
		hints = []protocol.InlayHint{}
	}
	return hints, nil
}

// onDidChangeConfiguration adopts a settings change.
func (s *Server) onDidChangeConfiguration(req *jsonrpc2.Request) error {
	var params protocol.DidChangeConfigurationParams
	if err := unmarshalParams(req, &params); err != nil {
		return err
	}
	if len(params.Settings) == 0 {
		return nil
	}
	var raw map[string]any
	if err := json.Unmarshal(params.Settings, &raw); err != nil {
		// A settings payload that will not decode is reported and dropped. The
		// server keeps the configuration it already had rather than falling back
		// to defaults, which would silently undo whatever the user had set.
		s.cfg.logf("could not decode configuration: %v", err)
		return nil
	}
	s.applySettings(raw)
	return nil
}

// onDidChangeWatchedFiles reacts to manifests, lockfiles and the memory file
// changing outside the editor.
//
// This is the notification that makes `npm install` visible. Without it a
// lockfile rewritten by a package manager is invisible to the server, because
// nothing ever opened it in a text editor.
func (s *Server) onDidChangeWatchedFiles(req *jsonrpc2.Request) error {
	var params protocol.DidChangeWatchedFilesParams
	if err := unmarshalParams(req, &params); err != nil {
		return err
	}

	s.mu.Lock()
	root := s.rootPath
	settings := s.settings
	s.mu.Unlock()

	memoryChanged := false
	manifestChanged := false
	memoryFile := s.suppressions.MemoryFile()

	for _, change := range params.Changes {
		path, ok := URIToPath(change.URI)
		if !ok {
			continue
		}
		if memoryFile != "" && filepath.Clean(path) == filepath.Clean(memoryFile) {
			memoryChanged = true
			continue
		}
		manifestChanged = true
	}

	if memoryChanged && root != "" {
		s.suppressions.Reload(root, settings)
		for _, doc := range s.docs.All() {
			s.publishMerged(doc.URI)
		}
	}
	if manifestChanged {
		s.rescanManifest()
	}
	return nil
}

// codeActionCaps advertises the quick-fix kind, or nothing when dependency
// analysis is off.
func codeActionCaps(enabled bool) *protocol.CodeActionOptions {
	if !enabled {
		return nil
	}
	return &protocol.CodeActionOptions{
		CodeActionKinds: []string{protocol.CodeActionQuickFix},
	}
}

// capabilityList is what the handshake and vulnetix/serverInfo report.
//
// The client uses it to hide UI for analysis this binary cannot do, so a family
// listed here has to actually run. "sca" appears only when dependency analysis
// is enabled, for that reason.
func (s *Server) capabilityList() []string {
	caps := []string{"sast", "secrets", "iac", "containers"}

	s.mu.Lock()
	enabled := s.settings.SCA.Enabled
	s.mu.Unlock()

	if enabled {
		caps = append(caps, "sca")
	}
	return caps
}

// aboveSeverityFloor drops diagnostics below the configured minimum.
//
// Applied at publish rather than at production so raising the floor takes
// effect immediately on every open file, without re-running a scan, and so
// lowering it again does not need one either.
func aboveSeverityFloor(diags []protocol.Diagnostic, floor string) []protocol.Diagnostic {
	if floor == "" {
		return diags
	}
	limit := severityRank(floor)
	// An unrecognised floor is not a reason to hide anything.
	if limit >= len(severityOrder) {
		return diags
	}

	out := make([]protocol.Diagnostic, 0, len(diags))
	for _, d := range diags {
		if lspSeverityRank(d.Severity) <= limit {
			out = append(out, d)
		}
	}
	return out
}

// lspSeverityRank maps an LSP severity back onto the severity scale, so the
// floor can be applied to findings from every family without each one carrying
// its original label.
//
// Error covers both critical and high, so it ranks as critical: a floor of
// "high" must not hide an error, and one of "critical" is better erring towards
// showing a high finding than hiding a critical one.
func lspSeverityRank(severity int) int {
	switch severity {
	case protocol.SeverityError:
		return severityRank("critical")
	case protocol.SeverityWarning:
		return severityRank("medium")
	case protocol.SeverityInformation, protocol.SeverityHint:
		return severityRank("low")
	}
	return severityRank("info")
}
