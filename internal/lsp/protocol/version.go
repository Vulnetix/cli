// Package protocol is the Language Server Protocol subset the Vulnetix server
// speaks, plus the vulnetix/* extension methods.
//
// Hand-written rather than generated or imported. The options were:
//
//   - golang.org/x/tools/gopls/internal/protocol lives under an internal/
//     directory, so Go's own rules make it unimportable from here. Not a
//     trade-off, a hard block.
//   - go.lsp.dev/protocol last released in 2021 against LSP 3.16, so it has no
//     inlay hints, no pull diagnostics and no positionEncoding, and it pulls in
//     a logging framework this binary has no other use for.
//   - github.com/tliron/glsp is complete and current, but it owns the process:
//     its own context type, its own logging, its own stdio loop. This server
//     specifically needs to control stdio, because cmd/ writes to os.Stdout in
//     144 places and a single stray byte desynchronises the framing.
//
// So the transport is github.com/sourcegraph/jsonrpc2 (framing, request
// correlation, concurrent write serialisation) and the types are here. Only
// what is used is defined; the spec is large and most of it is a language
// server's job rather than a security scanner's.
package protocol

// ProtocolVersion is the contract version for the vulnetix/* extension methods.
//
// The client requires an exact match. Bump it ONLY on a breaking change to a
// vulnetix/* method's params or result: a field removed, renamed, or changed in
// type or meaning.
//
// Adding a field does NOT bump it. Every params and result type is an object
// for exactly this reason, so a server can grow a field and an older client
// ignores it, while a newer client reading a missing field gets a zero value it
// can handle.
//
// The extension declares the same integer in its package.json under
// "vulnetix.lspProtocolVersion", and an integration test asserts the two agree.
// `vulnetix lsp --version` prints it so the client can check before connecting.
const ProtocolVersion = 1

// ServerName is reported in the initialize result and in log messages.
const ServerName = "vulnetix"
