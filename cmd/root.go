package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/v3/internal/analytics"
	"github.com/vulnetix/cli/v3/internal/config"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/update"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/cache"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

var (
	// Command line flags
	orgID         string
	silent        bool
	verbose       bool
	noProgress    bool
	disableMemory bool
	noAnalytics   bool

	// Build metadata (injected via ldflags)
	version   = "1.0.0"   // -X github.com/vulnetix/cli/v3/cmd.version=
	commit    = "unknown" // -X github.com/vulnetix/cli/v3/cmd.commit=
	buildDate = "unknown" // -X github.com/vulnetix/cli/v3/cmd.buildDate=
)

// updateCheckResult receives the update advisory message from the background
// goroutine started by the most recent startupHooks invocation. It is guarded
// by updateCheckMu because cobra.OnInitialize fires startupHooks once per
// Execute — a process that runs multiple commands (notably the test binary)
// reassigns this pointer while prior background goroutines and the PostRun
// consumer may still touch it.
var (
	updateCheckMu     sync.Mutex
	updateCheckResult chan string
)

// startUpdateAdvisory installs a fresh advisory channel for the current command
// and runs check in the background, delivering a non-empty advisory message (if
// any) exactly once. Each call owns its own channel: the goroutine sends to and
// closes only that local channel, never the shared pointer, so overlapping
// invocations can never send on or close another call's channel (the historical
// "send on closed channel" panic). The channel is buffered (cap 1) so the send
// never blocks even when no consumer is waiting.
func startUpdateAdvisory(check func() (msg string, ok bool)) {
	ch := make(chan string, 1)
	updateCheckMu.Lock()
	updateCheckResult = ch
	updateCheckMu.Unlock()
	go func() {
		defer close(ch)
		if msg, ok := check(); ok && msg != "" {
			ch <- msg
		}
	}()
}

// consumeUpdateAdvisory non-blockingly reads the pending advisory message for
// the current command, returning "" when none is ready. Safe to call from any
// goroutine.
func consumeUpdateAdvisory() string {
	updateCheckMu.Lock()
	ch := updateCheckResult
	updateCheckMu.Unlock()
	if ch == nil {
		return ""
	}
	select {
	case msg := <-ch:
		return msg
	default:
		return ""
	}
}

// checkForUpdateMessage performs the network update check and returns an
// advisory string when a newer release is available. It records that a check
// happened so ShouldCheckForUpdate throttles subsequent runs.
func checkForUpdateMessage() (string, bool) {
	release, err := update.CheckLatest()
	if err != nil {
		return "", false
	}
	update.RecordUpdateCheck()
	latest, err := update.ParseVersion(release.TagName)
	if err != nil {
		return "", false
	}
	current, err := update.ParseVersion(version)
	if err != nil {
		return "", false
	}
	if !latest.IsNewerThan(current) {
		return "", false
	}
	return fmt.Sprintf(
		"\nUpdate available: v%s → v%s\nRun 'vulnetix update' to update.\n",
		current, latest,
	), true
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vulnetix",
	Short: "Vulnetix CLI - Automate vulnerability remediation",
	Long: `Vulnetix CLI is a command-line tool for vulnerability management that focuses on
automated remediation over discovery. It helps organizations prioritize and resolve
vulnerabilities efficiently.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initDisplayContext(cmd, display.ModeText)
		printBanner(cmd)
		// Track command invocation
		analytics.TrackCommand(cmd.Name(), map[string]interface{}{
			"full_command": cmd.CommandPath(),
		})
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if msg := consumeUpdateAdvisory(); msg != "" {
			fmt.Fprint(os.Stderr, msg)
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInfoTask(cmd)
	},
}

// initDisplayContext creates and attaches a display.Context to the command.
func initDisplayContext(cmd *cobra.Command, mode display.OutputMode) {
	dc := display.NewWithProgress(mode, silent, noProgress)
	dc.Attach(cmd)
}

// runInfoTask performs an authentication healthcheck across all credential sources
func runInfoTask(cmd *cobra.Command) error {
	ctx := display.FromCommand(cmd)
	t := ctx.Term
	progress := ctx.Progress("Authentication healthcheck", 6)

	var b strings.Builder
	b.WriteString(display.Bold(t, fmt.Sprintf("Vulnetix CLI v%s", version)) + "\n")
	b.WriteString(display.Muted(t, fmt.Sprintf("Platform: %s", config.DetectPlatform())) + "\n")
	b.WriteString("\n" + display.Subheader(t, "Authentication Sources") + "\n")

	anyFound := false

	formatSource := func(name, dots string, status string, ok bool) {
		mark := display.CheckMark(t)
		if !ok {
			mark = display.CrossMark(t)
		}
		b.WriteString(fmt.Sprintf("  %s %s %s %s\n", name, display.Muted(t, dots), mark, status))
	}
	formatNotSet := func(name, dots string) {
		b.WriteString(fmt.Sprintf("  %s %s %s\n", name, display.Muted(t, dots), display.Muted(t, "not set")))
	}
	formatNotFound := func(name, dots string) {
		b.WriteString(fmt.Sprintf("  %s %s %s\n", name, display.Muted(t, dots), display.Muted(t, "not found")))
	}

	// 1. Check Direct API Key env vars
	progress.SetStage("Checking Direct API Key environment credentials")
	apiKey := os.Getenv("VULNETIX_API_KEY")
	envOrgID := os.Getenv("VULNETIX_ORG_ID")
	if apiKey != "" && envOrgID != "" {
		anyFound = true
		creds := &auth.Credentials{
			OrgID:  envOrgID,
			APIKey: apiKey,
			Method: auth.DirectAPIKey,
		}
		if err := verifyDirectAPIKey(creds); err != nil {
			formatSource("VULNETIX_API_KEY + VULNETIX_ORG_ID (env)", "···", fmt.Sprintf("(%s)", err), false)
		} else {
			formatSource("VULNETIX_API_KEY + VULNETIX_ORG_ID (env)", "···", display.Muted(t, fmt.Sprintf("org: %s", envOrgID)), true)
		}
	} else {
		formatNotSet("VULNETIX_API_KEY + VULNETIX_ORG_ID (env)", "···")
	}
	progress.Update(1, "Checked Direct API Key environment credentials")

	// 2. Check SigV4 env vars
	progress.SetStage("Checking SigV4 environment credentials")
	vvdOrg := os.Getenv("VVD_ORG")
	vvdSecret := os.Getenv("VVD_SECRET")
	if vvdOrg != "" && vvdSecret != "" {
		anyFound = true
		if err := verifySigV4(vvdOrg, vvdSecret); err != nil {
			formatSource("VVD_ORG + VVD_SECRET (env)", "···············", fmt.Sprintf("(%s)", err), false)
		} else {
			formatSource("VVD_ORG + VVD_SECRET (env)", "···············", display.Muted(t, fmt.Sprintf("org: %s", vvdOrg)), true)
		}
	} else {
		formatNotSet("VVD_ORG + VVD_SECRET (env)", "···············")
	}
	progress.Update(2, "Checked SigV4 environment credentials")

	// 3. Check project dotfile
	progress.SetStage("Checking project credential file")
	if creds, err := loadCredentialFile(auth.StoreProject); err == nil {
		anyFound = true
		if verr := verifyCredentials(creds); verr != nil {
			formatSource(".vulnetix/credentials.json (project)", "······", fmt.Sprintf("(%s)", verr), false)
		} else {
			formatSource(".vulnetix/credentials.json (project)", "······", display.Muted(t, fmt.Sprintf("%s, org: %s", creds.Method, creds.OrgID)), true)
		}
	} else {
		formatNotFound(".vulnetix/credentials.json (project)", "······")
	}
	progress.Update(3, "Checked project credential file")

	// 4. Check home directory
	progress.SetStage("Checking home credential file")
	homeDir, _ := os.UserHomeDir()
	homePath := filepath.Join(homeDir, ".vulnetix", "credentials.json")
	homeLabel := homePath + " (home)"
	if creds, err := loadCredentialFile(auth.StoreHome); err == nil {
		anyFound = true
		if verr := verifyCredentials(creds); verr != nil {
			formatSource(homeLabel, "···", fmt.Sprintf("(%s)", verr), false)
		} else {
			formatSource(homeLabel, "···", display.Muted(t, fmt.Sprintf("%s, org: %s", creds.Method, creds.OrgID)), true)
		}
	} else {
		formatNotFound(homeLabel, "···")
	}
	progress.Update(4, "Checked home credential file")

	// 5. Check Package Firewall netrc
	progress.SetStage("Checking Package Firewall netrc credentials")
	netrc := auth.NetrcStatus()
	netrcLabel := fmt.Sprintf("%s machine %s (netrc)", netrc.Path, auth.PackageFirewallHost)
	switch {
	case netrc.Found && netrc.Err != nil:
		anyFound = true
		formatSource(netrcLabel, "······", fmt.Sprintf("(%s)", netrc.Err), false)
	case netrc.Found && netrc.MachineFound:
		anyFound = true
		creds := &auth.Credentials{
			OrgID:  netrc.OrgID,
			APIKey: netrc.APIKey,
			Method: auth.DirectAPIKey,
		}
		if verr := verifyCredentials(creds); verr != nil {
			formatSource(netrcLabel, "······", fmt.Sprintf("(%s)", verr), false)
		} else {
			formatSource(netrcLabel, "······", display.Muted(t, fmt.Sprintf("%s, org: %s", creds.Method, creds.OrgID)), true)
		}
	case netrc.Found:
		formatNotFound(netrcLabel, "······")
	default:
		formatNotFound(netrcLabel, "······")
	}
	progress.Update(5, "Checked Package Firewall netrc credentials")

	// 6. Community fallback (VDB only)
	progress.SetStage("Checking community fallback availability")
	formatSource("Unauthenticated Community (VDB only)", "······", display.Muted(t, "available"), true)
	progress.Complete("authentication healthcheck complete")

	if !anyFound {
		b.WriteString("\n" + display.Muted(t, "No credentials configured. Run 'vulnetix auth login' to get started.") + "\n")
	}

	ctx.Logger.Result(b.String())
	return nil
}

// loadCredentialFile loads credentials from a specific store without fallback
func loadCredentialFile(store auth.CredentialStore) (*auth.Credentials, error) {
	var path string
	switch store {
	case auth.StoreProject:
		path = filepath.Join(".vulnetix", "credentials.json")
	case auth.StoreHome:
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(homeDir, ".vulnetix", "credentials.json")
	default:
		return nil, fmt.Errorf("unsupported store")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var creds auth.Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}
	if creds.OrgID == "" {
		return nil, fmt.Errorf("missing org_id")
	}
	return &creds, nil
}

// verifyCredentials validates credentials based on their method
func verifyCredentials(creds *auth.Credentials) error {
	switch creds.Method {
	case auth.DirectAPIKey:
		return verifyDirectAPIKey(creds)
	case auth.SigV4:
		return verifySigV4(creds.OrgID, creds.Secret)
	default:
		return fmt.Errorf("unknown method: %s", creds.Method)
	}
}

// verifyDirectAPIKey tests Direct API Key connectivity
func verifyDirectAPIKey(creds *auth.Credentials) error {
	now := time.Now()
	vdbClient := vdb.NewClientFromCredentials(creds)
	_, err := vdbClient.GetGCVEIssuances(now.Year(), int(now.Month()), 1, 0)
	return err
}

// verifySigV4 tests SigV4 authentication via token exchange
func verifySigV4(orgID, secret string) error {
	vdbClient := vdb.NewClient(orgID, secret)
	_, err := vdbClient.GetToken()
	if err != nil {
		return fmt.Errorf("token exchange failed")
	}
	return nil
}

func Execute() error {
	// Suppress cobra's default error printing — we handle it in main.
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true
	err := rootCmd.Execute()
	if err == nil {
		return nil
	}
	// PolicyBreachError (quality gate breach from scan) — caller handles messaging.
	if _, ok := err.(PolicyBreachError); ok {
		return err
	}
	// SeverityBreachError (license command) — caller handles messaging.
	if _, ok := err.(*SeverityBreachError); ok {
		return err
	}
	// For all other errors, restore normal error reporting.
	fmt.Fprintln(os.Stderr, "Error:", err)
	return err
}

// startupHooks runs before any command via cobra.OnInitialize.
func startupHooks() {
	installCommandProgress()

	// Propagate verbose flag into vdb client (gates retry/backoff stderr chatter).
	vdb.Verbose = verbose

	// Initialize GA4 analytics (respects VULNETIX_NO_ANALYTICS / DO_NOT_TRACK / --no-analytics)
	if noAnalytics {
		os.Setenv("VULNETIX_NO_ANALYTICS", "1")
	}
	analytics.Init(version, string(config.DetectPlatform()))

	// Clean old versioned caches (fast, filesystem-only)
	go func() {
		if n, _ := cache.CleanOldCaches(version); n > 0 {
			suffix := "ies"
			if n == 1 {
				suffix = "y"
			}
			fmt.Fprintf(os.Stderr, "Cleaned %d old cache entr%s\n", n, suffix)
		}
	}()

	// Update check: skip in CI, dev builds, or if checked recently
	if config.DetectPlatform() != config.PlatformCLI {
		return
	}
	if strings.Contains(version, "-dev") {
		return
	}
	if !update.ShouldCheckForUpdate() {
		return
	}

	startUpdateAdvisory(checkForUpdateMessage)
}

func init() {
	rootCmd.PersistentFlags().StringVar(&orgID, "org-id", "", "Organization ID (UUID) for Vulnetix operations")
	rootCmd.PersistentFlags().BoolVar(&silent, "silent", false, "Suppress all log output, only print final result")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Show verbose diagnostic output (rate limits, cache status, auth notes)")
	rootCmd.PersistentFlags().BoolVar(&noProgress, "no-progress", false, "Suppress progress indicators")
	rootCmd.PersistentFlags().BoolVar(&disableMemory, "disable-memory", false, "Disable memory file reads/writes. For users who do not use the Claude Code Plugin or for debugging. VDB commands will skip memory-related side effects when set.")
	rootCmd.PersistentFlags().BoolVar(&noAnalytics, "no-analytics", false, "Disable anonymous usage analytics")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	cobra.OnInitialize(startupHooks)
}
