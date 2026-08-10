package protocol

import "encoding/json"

// ── Method names ─────────────────────────────────────────────────────────────

const (
	MethodInitialize  = "initialize"
	MethodInitialized = "initialized"
	MethodShutdown    = "shutdown"
	MethodExit        = "exit"
	MethodSetTrace    = "$/setTrace"
	MethodCancel      = "$/cancelRequest"
	MethodProgress    = "$/progress"

	MethodDidOpen   = "textDocument/didOpen"
	MethodDidChange = "textDocument/didChange"
	MethodDidSave   = "textDocument/didSave"
	MethodDidClose  = "textDocument/didClose"

	MethodPublishDiagnostics = "textDocument/publishDiagnostics"

	MethodLogMessage             = "window/logMessage"
	MethodShowMessage            = "window/showMessage"
	MethodWorkDoneProgressCreate = "window/workDoneProgress/create"

	MethodConfiguration          = "workspace/configuration"
	MethodDidChangeConfiguration = "workspace/didChangeConfiguration"
	MethodDidChangeWatchedFiles  = "workspace/didChangeWatchedFiles"

	// Vulnetix extensions. One namespace, so a client can discover them and a
	// reader can tell at a glance what is standard and what is ours.
	MethodServerInfo    = "vulnetix/serverInfo"
	MethodScanWorkspace = "vulnetix/scanWorkspace"
	MethodScanStatus    = "vulnetix/scanStatus"
	MethodFindings      = "vulnetix/findings"
)

// ── Errors ───────────────────────────────────────────────────────────────────

// JSON-RPC and LSP error codes. RequestCancelled is the one that matters most
// here: a cancelled scan must be distinguishable from a failed one, or the
// client reports an error for something the user asked to stop.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603

	CodeServerNotInitialized = -32002
	CodeRequestCancelled     = -32800
	CodeContentModified      = -32801
)

// ── Positions ────────────────────────────────────────────────────────────────

// Position is zero-based. Character is measured in UTF-16 code units, which is
// the LSP default and what this server advertises. See internal/lsp/rangefix
// for why that distinction is load-bearing.
type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// Range is a half-open interval.
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// Location is a range within a document.
type Location struct {
	URI   string `json:"uri"`
	Range Range  `json:"range"`
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

type InitializeParams struct {
	ProcessID  *int    `json:"processId"`
	RootURI    string  `json:"rootUri,omitempty"`
	ClientInfo *Client `json:"clientInfo,omitempty"`
	// InitializationOptions carries settings the client wants applied before
	// the first workspace/configuration round trip.
	InitializationOptions json.RawMessage `json:"initializationOptions,omitempty"`
	Capabilities          ClientCaps      `json:"capabilities"`
	WorkspaceFolders      []Folder        `json:"workspaceFolders,omitempty"`
	Trace                 string          `json:"trace,omitempty"`
}

type Client struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type Folder struct {
	URI  string `json:"uri"`
	Name string `json:"name"`
}

// ClientCaps is the subset of client capabilities the server branches on.
// Everything else is ignored rather than modelled: a field nobody reads is a
// field that drifts.
type ClientCaps struct {
	Workspace struct {
		Configuration          bool `json:"configuration,omitempty"`
		WorkspaceFolders       bool `json:"workspaceFolders,omitempty"`
		DidChangeConfiguration struct {
			DynamicRegistration bool `json:"dynamicRegistration,omitempty"`
		} `json:"didChangeConfiguration"`
	} `json:"workspace"`
	TextDocument struct {
		PublishDiagnostics struct {
			RelatedInformation bool `json:"relatedInformation,omitempty"`
			DataSupport        bool `json:"dataSupport,omitempty"`
			TagSupport         struct {
				ValueSet []int `json:"valueSet,omitempty"`
			} `json:"tagSupport"`
		} `json:"publishDiagnostics"`
	} `json:"textDocument"`
	Window struct {
		WorkDoneProgress bool `json:"workDoneProgress,omitempty"`
	} `json:"window"`
	General struct {
		// PositionEncodings is the client's preference order. The server
		// advertises utf-16 regardless, because that is what rangefix produces.
		PositionEncodings []string `json:"positionEncodings,omitempty"`
	} `json:"general"`
}

type InitializeResult struct {
	Capabilities ServerCaps  `json:"capabilities"`
	ServerInfo   *ServerInfo `json:"serverInfo,omitempty"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// TextDocumentSyncKind values. The server advertises Full.
//
// Incremental sync would mean applying ranged edits to a local copy of every
// open document. The rule engine needs whole-file text anyway, so incremental
// buys nothing and adds a class of bug where the server's copy silently drifts
// from the editor's. Files are capped at 1 MiB, so the transfer cost is not
// worth that risk.
const (
	SyncNone        = 0
	SyncFull        = 1
	SyncIncremental = 2
)

type SaveOptions struct {
	IncludeText bool `json:"includeText"`
}

type TextDocumentSyncOptions struct {
	OpenClose bool         `json:"openClose"`
	Change    int          `json:"change"`
	Save      *SaveOptions `json:"save,omitempty"`
}

type ServerCaps struct {
	PositionEncoding string                   `json:"positionEncoding,omitempty"`
	TextDocumentSync *TextDocumentSyncOptions `json:"textDocumentSync,omitempty"`
	Workspace        *WorkspaceCaps           `json:"workspace"`
	ExecuteCommand   *ExecuteCommandOptions   `json:"executeCommandProvider,omitempty"`
}

type WorkspaceCaps struct {
	WorkspaceFolders *WorkspaceFoldersCaps `json:"workspaceFolders,omitempty"`
}

type WorkspaceFoldersCaps struct {
	Supported           bool `json:"supported"`
	ChangeNotifications bool `json:"changeNotifications,omitempty"`
}

type ExecuteCommandOptions struct {
	Commands []string `json:"commands"`
}

type SetTraceParams struct {
	Value string `json:"value"`
}

// ── Documents ────────────────────────────────────────────────────────────────

type TextDocumentItem struct {
	URI        string `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
	Text       string `json:"text"`
}

type TextDocumentIdentifier struct {
	URI string `json:"uri"`
}

type VersionedTextDocumentIdentifier struct {
	URI     string `json:"uri"`
	Version int    `json:"version"`
}

type DidOpenParams struct {
	TextDocument TextDocumentItem `json:"textDocument"`
}

// ContentChange carries the whole document, because the server advertises full
// sync. Range and RangeLength are accepted and ignored, so a client that sends
// incremental changes anyway is detected rather than silently misapplied.
type ContentChange struct {
	Range       *Range `json:"range,omitempty"`
	RangeLength *int   `json:"rangeLength,omitempty"`
	Text        string `json:"text"`
}

type DidChangeParams struct {
	TextDocument   VersionedTextDocumentIdentifier `json:"textDocument"`
	ContentChanges []ContentChange                 `json:"contentChanges"`
}

type DidSaveParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Text         *string                `json:"text,omitempty"`
}

type DidCloseParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

// ── Diagnostics ──────────────────────────────────────────────────────────────

// Severity values. Vulnetix maps critical and high to Error, medium to Warning,
// and low and info to Information or Hint depending on a setting.
const (
	SeverityError       = 1
	SeverityWarning     = 2
	SeverityInformation = 3
	SeverityHint        = 4
)

// Diagnostic tags. Deprecated is used for end-of-life packages, which the
// editor renders with a strikethrough: exactly the right signal for a
// dependency that is not going to get fixed because it is not maintained.
const (
	TagUnnecessary = 1
	TagDeprecated  = 2
)

// CodeDescription links a diagnostic code to its documentation, so the code in
// the Problems panel becomes a link to the rule page.
type CodeDescription struct {
	Href string `json:"href"`
}

type DiagnosticRelatedInformation struct {
	Location Location `json:"location"`
	Message  string   `json:"message"`
}

type Diagnostic struct {
	Range    Range  `json:"range"`
	Severity int    `json:"severity,omitempty"`
	Code     string `json:"code,omitempty"`
	// CodeDescription turns Code into a link. Omitted when the rule has no
	// documentation page rather than pointing at a 404.
	CodeDescription *CodeDescription `json:"codeDescription,omitempty"`
	// Source names the scanner family, which is what the Problems panel groups
	// and filters by: vulnetix-sca, vulnetix-sast, vulnetix-secrets and so on.
	Source             string                         `json:"source,omitempty"`
	Message            string                         `json:"message"`
	Tags               []int                          `json:"tags,omitempty"`
	RelatedInformation []DiagnosticRelatedInformation `json:"relatedInformation,omitempty"`
	// Data round-trips to the client untouched. Carries the finding id, the
	// anchor confidence and whether a fix exists, so a code action can be
	// resolved without a second lookup.
	Data json.RawMessage `json:"data,omitempty"`
}

type PublishDiagnosticsParams struct {
	URI     string       `json:"uri"`
	Version *int         `json:"version,omitempty"`
	Diags   []Diagnostic `json:"diagnostics"`
}

// ── Window and progress ──────────────────────────────────────────────────────

// MessageType values, matching pipeline.Level without translation.
const (
	MessageError   = 1
	MessageWarning = 2
	MessageInfo    = 3
	MessageLog     = 4
)

type LogMessageParams struct {
	Type    int    `json:"type"`
	Message string `json:"message"`
}

type ShowMessageParams struct {
	Type    int    `json:"type"`
	Message string `json:"message"`
}

type WorkDoneProgressCreateParams struct {
	Token string `json:"token"`
}

type ProgressParams struct {
	Token string          `json:"token"`
	Value json.RawMessage `json:"value"`
}

type WorkDoneProgressBegin struct {
	Kind        string `json:"kind"` // "begin"
	Title       string `json:"title"`
	Cancellable bool   `json:"cancellable,omitempty"`
	Message     string `json:"message,omitempty"`
	Percentage  *int   `json:"percentage,omitempty"`
}

type WorkDoneProgressReport struct {
	Kind        string `json:"kind"` // "report"
	Cancellable bool   `json:"cancellable,omitempty"`
	Message     string `json:"message,omitempty"`
	Percentage  *int   `json:"percentage,omitempty"`
}

type WorkDoneProgressEnd struct {
	Kind    string `json:"kind"` // "end"
	Message string `json:"message,omitempty"`
}

// ── Configuration ────────────────────────────────────────────────────────────

type ConfigurationItem struct {
	// ScopeURI is the folder the setting is being asked about. Requesting per
	// folder rather than once at startup is what makes a folder-scoped
	// vulnetix.scan.exclude take effect in a multi-root workspace.
	ScopeURI string `json:"scopeUri,omitempty"`
	Section  string `json:"section,omitempty"`
}

type ConfigurationParams struct {
	Items []ConfigurationItem `json:"items"`
}

type DidChangeConfigurationParams struct {
	Settings json.RawMessage `json:"settings"`
}

// FileChangeType values.
const (
	FileCreated = 1
	FileChanged = 2
	FileDeleted = 3
)

type FileEvent struct {
	URI  string `json:"uri"`
	Type int    `json:"type"`
}

type DidChangeWatchedFilesParams struct {
	Changes []FileEvent `json:"changes"`
}

// ── Cancellation ─────────────────────────────────────────────────────────────

type CancelParams struct {
	// ID is a request id, which JSON-RPC allows to be a number or a string.
	ID json.RawMessage `json:"id"`
}
