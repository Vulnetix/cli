package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/internal/auth"
	"github.com/vulnetix/cli/internal/cache"
	"github.com/vulnetix/cli/internal/config"
	"github.com/vulnetix/cli/internal/display"
	"github.com/vulnetix/cli/internal/update"
	"github.com/vulnetix/cli/internal/vdb"
)

var (
	// Command line flags
	orgID  string
	silent bool

	// Build metadata (injected via ldflags)
	version   = "1.0.0"   // -X github.com/vulnetix/cli/cmd.version=
	commit    = "unknown" // -X github.com/vulnetix/cli/cmd.commit=
	buildDate = "unknown" // -X github.com/vulnetix/cli/cmd.buildDate=
)

// updateCheckResult receives the update advisory message from the background goroutine.
var updateCheckResult chan string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vulnetix",
	Short: "Vulnetix CLI - Automate vulnerability remediation",
	Long: `Vulnetix CLI is a command-line tool for vulnerability management that focuses on
automated remediation over discovery. It helps organizations prioritize and resolve
vulnerabilities efficiently.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initDisplayContext(cmd, display.ModeText)
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if updateCheckResult == nil {
			return
		}
		select {
		case msg := <-updateCheckResult:
			if msg != "" {
				fmt.Fprint(os.Stderr, msg)
			}
		default:
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInfoTask(cmd)
	},
}

// initDisplayContext creates and attaches a display.Context to the command.
func initDisplayContext(cmd *cobra.Command, mode display.OutputMode) {
	dc := display.New(mode, silent)
	dc.Attach(cmd)
}

// runInfoTask performs an authentication healthcheck across all credential sources
func runInfoTask(cmd *cobra.Command) error {
	ctx := display.FromCommand(cmd)
	t := ctx.Term

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

	// 2. Check SigV4 env vars
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

	// 3. Check project dotfile
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

	// 4. Check home directory
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

	// 5. Community fallback (VDB only)
	formatSource("Unauthenticated Community (VDB only)", "······", display.Muted(t, "available"), true)

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
	// SeverityBreachError is a controlled policy exit — caller handles messaging.
	if _, ok := err.(*SeverityBreachError); ok {
		return err
	}
	// For all other errors, restore normal error reporting.
	fmt.Fprintln(os.Stderr, "Error:", err)
	return err
}

// startupHooks runs before any command via cobra.OnInitialize.
func startupHooks() {
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

	updateCheckResult = make(chan string, 1)
	go func() {
		defer close(updateCheckResult)
		release, err := update.CheckLatest()
		if err != nil {
			return
		}
		update.RecordUpdateCheck()
		latest, err := update.ParseVersion(release.TagName)
		if err != nil {
			return
		}
		current, err := update.ParseVersion(version)
		if err != nil {
			return
		}
		if latest.IsNewerThan(current) {
			updateCheckResult <- fmt.Sprintf(
				"\nUpdate available: v%s → v%s\nRun 'vulnetix update' to update.\n",
				current, latest,
			)
		}
	}()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&orgID, "org-id", "", "Organization ID (UUID) for Vulnetix operations")
	rootCmd.PersistentFlags().BoolVar(&silent, "silent", false, "Suppress all log output, only print final result")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	cobra.OnInitialize(startupHooks)
}
