package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/v3/internal/lsp"
	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
)

var (
	lspShowVersion   bool
	lspLogFile       string
	lspDebounceMS    int
	lspMemoryLimitMB int
)

// lspActive reports whether this process is running as a language server.
//
// startupHooks fires on every command via cobra.OnInitialize and starts a
// GitHub update check and per-command analytics. Both are wrong for a daemon:
// a long-lived process must not poll GitHub, and one analytics event per
// command becomes one per editor session that never ends.
//
// A package-level flag rather than a parameter because startupHooks takes none
// and is registered by cobra, not called by us.
var lspActive bool

// LSPActive reports whether the process is serving LSP. Read by startupHooks.
func LSPActive() bool { return lspActive }

var lspCmd = &cobra.Command{
	Use:   "lsp",
	Short: "Run the Vulnetix language server (LSP over stdio)",
	Long: `Run Vulnetix as a Language Server Protocol server, speaking JSON-RPC over
standard input and output.

Intended to be started by an editor rather than by hand. The Vulnetix VS Code
extension does this automatically; other editors can point their LSP client at
this command.

The server holds the compiled rule set in memory, so it evaluates an edited file
in milliseconds rather than recompiling ~1,900 policy modules per check. As you
type it runs the sast, iac and oci rule kinds; on save it adds secrets, which
are around 92% of evaluation cost and cannot fire until a credential is fully
typed anyway.

Nothing is printed to standard output except protocol messages. Logs go to
standard error, or to --log-file.`,
	Args: cobra.NoArgs,
	RunE: runLSP,
}

func runLSP(cmd *cobra.Command, _ []string) error {
	if lspShowVersion {
		return printLSPHandshake()
	}

	// ── The stdout hazard ───────────────────────────────────────────────────
	//
	// Standard output IS the JSON-RPC channel. cmd/ writes to os.Stdout in 144
	// places (banners, progress, result rendering), and a single stray byte
	// desynchronises the Content-Length framing, at which point the client
	// stops being able to parse anything and hard-fails.
	//
	// Capture the real descriptor, then point the package variable at stderr.
	// fmt.Println and friends resolve os.Stdout at call time, so every existing
	// writer is redirected by this one assignment rather than needing 144 edits.
	//
	// This must be the first thing that happens, before any code that might
	// print. TestNoStdoutPollution drives a full session against the real
	// binary and asserts fd 1 contains nothing but valid framing.
	rpcOut := os.Stdout
	os.Stdout = os.Stderr

	logTarget := os.Stderr
	if lspLogFile != "" {
		f, err := os.OpenFile(lspLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return fmt.Errorf("could not open --log-file: %w", err)
		}
		defer f.Close()
		logTarget = f
	}

	logf := func(format string, args ...any) {
		fmt.Fprintf(logTarget, "[vulnetix-lsp] "+format+"\n", args...)
	}

	// A panic in a handler would otherwise take the process down with a stack
	// trace on stdout, corrupting the channel on the way out. Write the
	// breadcrumb to the log and exit with a code the client can distinguish
	// from a clean shutdown.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(logTarget, "[vulnetix-lsp] panic: %v\n%s\n", r, debug.Stack())
			writeCrashBreadcrumb(r)
			os.Exit(70)
		}
	}()

	logf("starting: version %s, commit %s, protocol %d, %s/%s",
		version, commit, protocol.ProtocolVersion, runtime.GOOS, runtime.GOARCH)

	cfg := lsp.Config{
		CLIVersion:    version,
		Commit:        commit,
		BuildDate:     buildDate,
		Debounce:      time.Duration(lspDebounceMS) * time.Millisecond,
		MaxTotalBytes: int64(lspMemoryLimitMB) << 20,
		Logf:          logf,
	}

	// A memory limit the runtime enforces, so the garbage collector works
	// harder instead of the process being killed by the OS. Belt and braces
	// with the content-loading budget, which bounds what is held rather than
	// what is allocated in total.
	if lspMemoryLimitMB > 0 {
		debug.SetMemoryLimit(int64(lspMemoryLimitMB) << 20)
	}

	err := lsp.Serve(cmd.Context(), os.Stdin, rpcOut, cfg)
	logf("stopped")
	return err
}

// printLSPHandshake writes the compatibility handshake as one line of JSON.
//
// The client runs `vulnetix lsp --version` before connecting and refuses to
// start a server whose protocol version does not match exactly. Doing that as a
// separate short-lived invocation, rather than as the first LSP request, means
// an incompatible binary is detected before a connection exists to be confused
// by it.
func printLSPHandshake() error {
	out := protocol.ServerInfoResult{
		ProtocolVersion: protocol.ProtocolVersion,
		CLIVersion:      version,
		Commit:          commit,
		BuildDate:       buildDate,
		GoVersion:       runtime.Version(),
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		// Dependency analysis ships in the binary and defaults on, so the
		// pre-connect handshake reports it. A client uses this list to decide
		// whether to offer the dependency UI at all, and it has to answer before
		// a session exists to ask.
		Capabilities: []string{"sast", "secrets", "iac", "containers", "sca"},
	}
	enc, err := json.Marshal(out)
	if err != nil {
		return err
	}
	// The one legitimate write to stdout from this command, and only when not
	// serving.
	fmt.Println(string(enc))
	return nil
}

// writeCrashBreadcrumb records a crash where the extension can find it, so a
// user reporting "it stopped working" has something to attach.
func writeCrashBreadcrumb(r any) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return
	}
	path := dir + string(os.PathSeparator) + "vulnetix" + string(os.PathSeparator) + "lsp-crash.json"
	_ = os.MkdirAll(dir+string(os.PathSeparator)+"vulnetix", 0o700)

	payload, err := json.Marshal(map[string]any{
		"ts":         time.Now().UTC().Format(time.RFC3339),
		"cliVersion": version,
		"commit":     commit,
		"panic":      fmt.Sprint(r),
		"stack":      string(debug.Stack()),
	})
	if err != nil {
		return
	}
	_ = os.WriteFile(path, payload, 0o600)
}

func init() {
	rootCmd.AddCommand(lspCmd)

	lspCmd.Flags().BoolVar(&lspShowVersion, "version", false,
		"Print the protocol handshake as JSON and exit")
	lspCmd.Flags().StringVar(&lspLogFile, "log-file", "",
		"Append server logs to this file instead of stderr")
	lspCmd.Flags().IntVar(&lspDebounceMS, "debounce-ms", 400,
		"Quiet period after a change before analysis runs")
	lspCmd.Flags().IntVar(&lspMemoryLimitMB, "memory-limit-mb", 2048,
		"Soft memory ceiling for the server (0 disables)")

	// Set as early as possible: startupHooks runs via cobra.OnInitialize,
	// after flag parsing but before RunE, and needs to know not to start an
	// update poll or per-command analytics for a daemon.
	cobra.OnInitialize(func() {
		if lspCmd.CalledAs() != "" {
			lspActive = true
		}
	})
}
