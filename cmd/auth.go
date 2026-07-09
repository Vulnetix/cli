package cmd

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/analytics"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/upload"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

var (
	authMethod         string
	authOrgID          string
	authSecret         string
	authAPIKey         string
	authToken          string
	authStore          string
	authStoreDir       string
	authNoninteractive bool
	authStatusBaseURL  string
)

// authCmd represents the auth command
var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage Vulnetix authentication",
	Long: `Manage authentication credentials for the Vulnetix API.

Examples:
  # Browser Device Flow login
  vulnetix auth

  # Non-interactive login with ApiKey
  vulnetix auth login --noninteractive --api-key KEY --store keyring

  # Non-interactive login with SigV4
  vulnetix auth login --org-id UUID --secret KEY --store home

  # Check auth status
  vulnetix auth status

  # Remove stored credentials
  vulnetix auth logout`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAuthLogin(cmd)
	},
}

var authLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Vulnetix",
	Long: `Log in to the Vulnetix API. Browser Device Flow is used by default.

Credential flags (org-scoped methods require --org-id):
  --api-key KEY        ApiKey credential from your VDB account (requires --org-id)
  --secret KEY         SigV4 secret from your VDB account (requires --org-id)
  --token KEY          Bearer token (org resolved server-side; no --org-id)
  --noninteractive     Require ApiKey (--api-key + --org-id) from flags or environment
  --store home|project|keyring
  --store-dir DIR      Override the default home credential directory`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAuthLogin(cmd)
	},
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current authentication state",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := display.FromCommand(cmd)
		t := ctx.Term

		source := auth.CredentialSource()
		_, creds := auth.CredentialStatus()
		plan := "COMMUNITY"
		if creds != nil {
			plan = fetchLivePlan(creds, authStatusBaseURL)
		}

		ctx.Logger.Result(display.Header(t, "Auth state"))
		if creds != nil {
			var secretLabel, secretValue string
			switch creds.Method {
			case auth.Token:
				secretLabel = "Bearer token"
				secretValue = maskSecret(creds.Token)
			case auth.DirectAPIKey:
				secretLabel = "ApiKey"
				secretValue = maskSecret(creds.APIKey)
			default:
				secretLabel = "Secret"
				secretValue = maskSecret(creds.Secret)
			}
			ctx.Logger.Result(display.CheckMark(t) + " " + display.Success(t, "Authenticated"))
			ctx.Logger.Result(display.KeyValue(t, []display.KVPair{
				{Key: "Organization", Value: creds.OrgID},
				{Key: "Method", Value: string(creds.Method)},
				{Key: "Source", Value: authSourceLabel(source)},
				{Key: "Plan", Value: plan, ValueStyle: func(_ string) string { return planBadge(t, plan) }},
				{Key: secretLabel, Value: secretValue},
			}))
		} else {
			ctx.Logger.Result(display.WarningMark(t) + " " + display.Accent(t, "Community - unauthenticated (VDB only)"))
			ctx.Logger.Result(display.KeyValue(t, []display.KVPair{
				{Key: "Plan", Value: plan, ValueStyle: func(_ string) string { return planBadge(t, plan) }},
			}))
		}

		ctx.Logger.Result(display.Header(t, "Credential sources"))
		for _, s := range auth.AllSourceStatusDetailed() {
			mark := display.Muted(t, display.CrossMark(t))
			state := display.Muted(t, s.State)
			switch s.State {
			case "set":
				mark = display.CheckMark(t)
				state = display.Success(t, s.State)
			case "unusable":
				mark = display.WarningMark(t)
				state = display.Muted(t, s.State)
			}
			if s.Active {
				state = display.Success(t, "active")
			}
			line := fmt.Sprintf("  %s %s %s", mark, display.Bold(t, s.Label), state)
			if s.Detail != "" {
				line += " " + display.Muted(t, s.Detail)
			}
			ctx.Logger.Result(line)
		}

		ctx.Logger.Result(display.Header(t, "Package Firewall"))
		if home, err := os.UserHomeDir(); err == nil {
			groups := groupEcosystems(home, auth.PackageFirewallHost)
			if len(groups.Configured) > 0 {
				ctx.Logger.Result(display.Subheader(t, "Configured"))
				for _, eco := range groups.Configured {
					ctx.Logger.Result(fmt.Sprintf("  %s %s %s %s",
						display.CheckMark(t),
						display.Success(t, eco.Ecosystem.DisplayName),
						tierBadge(t, eco.Ecosystem.Tier),
						display.Teal(t, eco.Path),
					))
				}
			}
			if len(groups.Available) > 0 {
				ctx.Logger.Result(display.Subheader(t, "Available to configure"))
				for _, eco := range groups.Available {
					hint := tierRequiresPlan(eco.Ecosystem.Tier, plan)
					line := fmt.Sprintf("  %s %s %s",
						display.Muted(t, "o"),
						eco.Ecosystem.DisplayName,
						tierBadge(t, eco.Ecosystem.Tier),
					)
					if hint != "" {
						line += " " + display.Muted(t, hint)
					}
					ctx.Logger.Result(line)
				}
			}
		} else {
			ctx.Logger.Result("  " + display.WarningMark(t) + " " + display.Muted(t, err.Error()))
		}
		return nil
	},
}

var authVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify stored credentials are valid",
	Long: `Verify that the stored (or provided) credentials can authenticate with the Vulnetix API.

This command does not save or modify any credentials. It's useful for CI/CD pipelines
to validate authentication before running tasks.

Examples:
  # Verify stored credentials
  vulnetix auth verify

  # Verify with explicit base URL
  vulnetix auth verify --base-url https://app.vulnetix.com/api`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAuthVerify(cmd)
	},
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := display.FromCommand(cmd)
		if err := auth.RemoveCredentials(); err != nil {
			return fmt.Errorf("failed to remove credentials: %w", err)
		}
		ctx.Logger.Info(display.CheckMark(ctx.Term) + " Credentials removed successfully")
		return nil
	},
}

func runAuthLogin(cmd *cobra.Command) error {
	var store auth.CredentialStore
	var creds *auth.Credentials

	// Method flags are mutually exclusive: --api-key (org-scoped ApiKey),
	// --secret (org-scoped SigV4), --token (org-less Bearer).
	methodsSet := 0
	for _, v := range []string{authAPIKey, authSecret, authToken} {
		if v != "" {
			methodsSet++
		}
	}
	if methodsSet > 1 {
		return fmt.Errorf("choose only one of --api-key, --secret, or --token")
	}

	s, err := auth.ValidateStore(authStore)
	if err != nil {
		return err
	}
	store = s

	switch {
	case authNoninteractive:
		// Force org-scoped ApiKey from flags/env; never browser, never prompt.
		if authSecret != "" || authToken != "" {
			return fmt.Errorf("--noninteractive uses ApiKey credentials only; use --api-key with --org-id")
		}
		key := firstNonEmpty(authAPIKey, os.Getenv("VULNETIX_API_KEY"))
		org := firstNonEmpty(authOrgID, os.Getenv("VULNETIX_ORG_ID"))
		if key == "" || org == "" {
			return fmt.Errorf("missing ApiKey or org for noninteractive login. Get your ApiKey and Org ID from your Vulnetix VDB account, then pass --api-key and --org-id (or set VULNETIX_API_KEY and VULNETIX_ORG_ID)")
		}
		if _, err := uuid.Parse(org); err != nil {
			return fmt.Errorf("--org-id must be a valid UUID, got: %s", org)
		}
		creds = &auth.Credentials{OrgID: org, APIKey: stripOrgPrefix(org, key), Method: auth.DirectAPIKey}

	case authAPIKey != "":
		// Org-scoped ApiKey (sent as `Authorization: ApiKey <orgID>:<key>`).
		org, err := resolveLoginOrgID("--api-key")
		if err != nil {
			return err
		}
		creds = &auth.Credentials{OrgID: org, APIKey: stripOrgPrefix(org, authAPIKey), Method: auth.DirectAPIKey}

	case authSecret != "":
		// Org-scoped SigV4.
		org, err := resolveLoginOrgID("--secret")
		if err != nil {
			return err
		}
		creds = &auth.Credentials{OrgID: org, Secret: authSecret, Method: auth.SigV4}

	case authToken != "":
		// Bearer token: separate and org-less (org resolved server-side).
		creds = &auth.Credentials{OrgID: authOrgID, Token: authToken, Method: auth.Token}

	case authMethod != "":
		return fmt.Errorf("--method is deprecated; use --api-key + --org-id (ApiKey), --secret + --org-id (SigV4), or --token (Bearer)")

	default:
		reader := bufio.NewReader(os.Stdin)
		method, orgIDVal, secret, selectedStore, err := browserLogin(reader, isInteractive())
		if err != nil {
			return err
		}
		store = selectedStore
		creds = &auth.Credentials{OrgID: orgIDVal, Method: method}
		switch method {
		case auth.Token:
			creds.Token = secret
		case auth.DirectAPIKey:
			creds.APIKey = secret
		case auth.SigV4:
			creds.Secret = secret
		}
	}

	// Test authentication
	ctx := display.FromCommand(cmd)
	ctx.Logger.Info("Testing authentication...")
	if err := testAuth(ctx, creds); err != nil {
		return fmt.Errorf("authentication test failed: %w", err)
	}
	ctx.Logger.Info(display.CheckMark(ctx.Term) + " Authentication verified")
	analytics.TrackAuth(string(creds.Method), "login", true)

	// Save credentials (keychain-aware, with file fallback).
	savedStore, err := saveCredentialsWithFallback(ctx, creds, store)
	if err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}
	ctx.Logger.Infof("%s Credentials saved to %s store", display.CheckMark(ctx.Term), savedStore)

	return nil
}

// saveCredentialsWithFallback persists credentials, preferring the OS keychain
// for the HMAC secret when the keyring store is chosen. If no keychain backend
// is present it surfaces clear guidance (with a setup URL) and falls back to the
// standard home-directory config file.
func saveCredentialsWithFallback(ctx *display.Context, creds *auth.Credentials, store auth.CredentialStore) (auth.CredentialStore, error) {
	err := auth.SaveCredentialsInDir(creds, store, authStoreDir)
	if err != nil && store == auth.StoreKeyring {
		ctx.Logger.Warn(err.Error())
		ctx.Logger.Info("No usable OS keychain - falling back to file storage.")
		creds.HMACInKeyring = false
		creds.TokenInKeyring = false
		creds.APIKeyInKeyring = false
		if ferr := auth.SaveCredentialsInDir(creds, auth.StoreHome, authStoreDir); ferr != nil {
			return "", ferr
		}
		return auth.StoreHome, nil
	}
	if err != nil {
		return "", err
	}
	return store, nil
}

func fetchLivePlan(creds *auth.Credentials, baseURL string) string {
	client := vdb.NewClientFromCredentials(creds)
	if baseURL != "" {
		base := strings.TrimRight(baseURL, "/")
		base = strings.TrimSuffix(base, "/v1")
		base = strings.TrimSuffix(base, "/v2")
		client.BaseURL = base
	}
	client.HTTPClient = &http.Client{Timeout: 3 * time.Second}
	now := time.Now()
	_, err := client.GetGCVEIssuances(now.Year(), int(now.Month()), 1, 0)
	if err != nil || client.LastRateLimit == nil || strings.TrimSpace(client.LastRateLimit.Plan) == "" {
		return "unknown"
	}
	return strings.ToUpper(client.LastRateLimit.Plan)
}

// resolveLoginOrgID returns a validated org UUID for the org-scoped methods,
// prompting on an interactive TTY when --org-id was not supplied.
func resolveLoginOrgID(flag string) (string, error) {
	org := authOrgID
	if org == "" {
		if !isInteractive() {
			return "", fmt.Errorf("--org-id is required with %s", flag)
		}
		fmt.Print("Organization ID (UUID): ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		org = strings.TrimSpace(line)
	}
	if _, err := uuid.Parse(org); err != nil {
		return "", fmt.Errorf("--org-id must be a valid UUID, got: %s", org)
	}
	return org, nil
}

// stripOrgPrefix removes a leading "<org>:" from an ApiKey value. The account
// GUI presents the ApiKey as "<orgId>:<hex>", but the CLI prepends the org
// itself when building the header, so accept either form.
func stripOrgPrefix(org, value string) string {
	return strings.TrimPrefix(value, org+":")
}

func promptStore(reader *bufio.Reader) (auth.CredentialStore, error) {
	keyringNote := "System keyring (OS keychain)"
	if err := auth.KeyringAvailable(); err != nil {
		keyringNote = "System keyring (no backend detected - will fall back to file)"
	}
	fmt.Println("Where to store credentials?")
	fmt.Println("  [1] Home directory ~/.vulnetix/ (default)")
	fmt.Println("  [2] Project .vulnetix/")
	fmt.Println("  [3] " + keyringNote)
	fmt.Print("Choice [1]: ")
	storeChoice, _ := reader.ReadString('\n')
	storeChoice = strings.TrimSpace(storeChoice)

	switch storeChoice {
	case "", "1":
		return auth.StoreHome, nil
	case "2":
		return auth.StoreProject, nil
	case "3":
		return auth.StoreKeyring, nil
	default:
		return "", fmt.Errorf("invalid choice: %s", storeChoice)
	}
}

const (
	browserLoginURL     = "https://app.vulnetix.com/cli-login-code"
	browserPollURL      = "https://app.vulnetix.com/api/cli/auth-code/poll/"
	browserCodeCharset  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	browserCodeTimeout  = 5 * time.Minute
	browserPollInterval = 5 * time.Second
)

func generateCode() (string, error) {
	b := make([]byte, 6)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(browserCodeCharset))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random code: %w", err)
		}
		b[i] = browserCodeCharset[n.Int64()]
	}
	return string(b[:3]) + "-" + string(b[3:]), nil
}

func browserLogin(reader *bufio.Reader, interactive bool) (auth.AuthMethod, string, string, auth.CredentialStore, error) {
	for {
		code, err := generateCode()
		if err != nil {
			return "", "", "", "", err
		}

		fmt.Println()
		fmt.Println("Device Flow login")
		fmt.Println()
		if interactive {
			if err := openBrowser(browserLoginURL); err == nil {
				fmt.Println("Opened your browser. If it did not appear, open this URL:")
			} else {
				fmt.Println("Open this URL in your browser:")
			}
		} else {
			fmt.Println("Open this URL in a browser:")
		}
		fmt.Println()
		fmt.Printf("  %s\n", browserLoginURL)
		fmt.Println()
		fmt.Println("Enter this code when prompted:")
		fmt.Println()
		fmt.Printf("  %s\n", code)
		fmt.Println()
		fmt.Println("Waiting for browser authorization...")

		orgID, apiKey, err := pollForAuth(code)
		if err != nil {
			if !interactive {
				return "", "", "", "", fmt.Errorf("device flow timed out")
			}
			// Timeout; prompt retry.
			fmt.Println()
			fmt.Print("Code expired. Try again? [Y/n]: ")
			retry, _ := reader.ReadString('\n')
			retry = strings.TrimSpace(strings.ToLower(retry))
			if retry == "" || retry == "y" || retry == "yes" {
				continue
			}
			return "", "", "", "", fmt.Errorf("browser login cancelled")
		}

		// Parse apiKey "orgId:hex"; the full value is the api key.
		// The orgId is returned separately
		parts := strings.SplitN(apiKey, ":", 2)
		if len(parts) != 2 {
			return "", "", "", "", fmt.Errorf("unexpected API key format from server")
		}
		apiKeyHex := parts[1]

		fmt.Printf("\nAuthentication accepted.\n")
		fmt.Println()

		store := auth.StoreHome
		if interactive {
			store, err = promptStore(reader)
			if err != nil {
				return "", "", "", "", err
			}
		} else {
			store, err = auth.ValidateStore(authStore)
			if err != nil {
				return "", "", "", "", err
			}
		}

		return auth.DirectAPIKey, orgID, apiKeyHex, store, nil
	}
}

func pollForAuth(code string) (orgID string, apiKey string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), browserCodeTimeout)
	defer cancel()

	ticker := time.NewTicker(browserPollInterval)
	defer ticker.Stop()

	countdownTicker := time.NewTicker(1 * time.Second)
	defer countdownTicker.Stop()

	deadline, _ := ctx.Deadline()
	httpClient := &http.Client{Timeout: 10 * time.Second}
	pollURL := browserPollURL + code

	for {
		select {
		case <-ctx.Done():
			fmt.Print("\r                              \r") // clear countdown line
			return "", "", fmt.Errorf("timeout")

		case <-countdownTicker.C:
			remaining := time.Until(deadline).Round(time.Second)
			mins := int(remaining.Minutes())
			secs := int(remaining.Seconds()) % 60
			fmt.Printf("\r  Time remaining: %d:%02d  ", mins, secs)

		case <-ticker.C:
			resp, reqErr := httpClient.Get(pollURL)
			if reqErr != nil {
				continue // network error, keep trying
			}

			if resp.StatusCode == http.StatusNotFound {
				resp.Body.Close()
				continue // not yet claimed
			}

			if resp.StatusCode == http.StatusOK {
				var result struct {
					OK    bool   `json:"ok"`
					OrgID string `json:"orgId"`
					Key   string `json:"apiKey"`
				}
				json.NewDecoder(resp.Body).Decode(&result)
				resp.Body.Close()

				if result.OK && result.OrgID != "" && result.Key != "" {
					fmt.Print("\r                              \r") // clear countdown line
					return result.OrgID, result.Key, nil
				}
			} else {
				resp.Body.Close()
			}
		}
	}
}

func testAuth(ctx *display.Context, creds *auth.Credentials) error {
	switch creds.Method {
	case auth.Token:
		if creds.Token == "" {
			return fmt.Errorf("token is empty")
		}
		now := time.Now()
		vdbClient := vdb.NewClientFromCredentials(creds)
		if _, err := vdbClient.GetGCVEIssuances(now.Year(), int(now.Month()), 1, 0); err != nil {
			return err
		}
		ctx.Logger.Info(display.CheckMark(ctx.Term) + " VDB API: OK")
		return nil

	case auth.DirectAPIKey:
		// Validate the API key format (must be non-empty hex string)
		if len(creds.APIKey) == 0 {
			return fmt.Errorf("API key is empty")
		}
		// Test credentials against an authenticated GCVE endpoint
		now := time.Now()
		vdbClient := vdb.NewClientFromCredentials(creds)
		_, err := vdbClient.GetGCVEIssuances(now.Year(), int(now.Month()), 1, 0)
		if err != nil {
			return err
		}
		ctx.Logger.Info(display.CheckMark(ctx.Term) + " VDB API: OK")
		return nil

	case auth.SigV4:
		// For SigV4, do a full token exchange to validate the secret
		vdbClient := vdb.NewClient(creds.OrgID, creds.Secret)
		_, err := vdbClient.GetToken()
		return err

	default:
		return nil
	}
}

var verifyBaseURL string

func runAuthVerify(cmd *cobra.Command) error {
	ctx := display.FromCommand(cmd)
	t := ctx.Term
	progress := ctx.Progress("Authentication verify", 3)

	progress.SetStage("Loading stored credentials")
	creds, err := auth.LoadCredentials()
	if err != nil {
		progress.Fail("credentials not found")
		return fmt.Errorf("no credentials found: %w\nRun 'vulnetix auth login' to authenticate", err)
	}
	progress.Update(1, fmt.Sprintf("Loaded credentials for org %s", creds.OrgID))

	progress.SetStage("Verifying credentials with Vulnetix API")
	client := upload.NewClient(verifyBaseURL, creds)
	result, err := client.VerifyAuth()
	if err != nil {
		progress.Fail("verification failed")
		return fmt.Errorf("verification failed: %w", err)
	}
	progress.Update(2, "Vulnetix API accepted credentials")
	progress.Complete("authentication verified")

	ctx.Logger.Info(display.CheckMark(t) + " Authentication verified successfully")
	ctx.Logger.Result(display.KeyValue(t, []display.KVPair{
		{Key: "Organization", Value: result.OrgID},
	}))
	return nil
}

func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func init() {
	authLoginCmd.Flags().StringVar(&authMethod, "method", "", "Deprecated authentication method selector")
	authLoginCmd.Flags().StringVar(&authOrgID, "org-id", "", "Organization ID (UUID; required for --api-key and --secret)")
	authLoginCmd.Flags().StringVar(&authToken, "token", "", "Bearer token (org resolved server-side; no --org-id needed)")
	authLoginCmd.Flags().StringVar(&authAPIKey, "api-key", "", "ApiKey credential from your VDB account (requires --org-id)")
	authLoginCmd.Flags().StringVar(&authSecret, "secret", "", "SigV4 secret from your VDB account (requires --org-id)")
	authLoginCmd.Flags().StringVar(&authStore, "store", "home", "Credential storage: home, project, keyring")
	authLoginCmd.Flags().StringVar(&authStoreDir, "store-dir", "", "Directory for home/keyring credential metadata instead of $HOME/.vulnetix")
	authLoginCmd.Flags().BoolVar(&authNoninteractive, "noninteractive", false, "Require ApiKey from --api-key or environment; never launch a browser")
	_ = authLoginCmd.Flags().MarkHidden("token")
	_ = authLoginCmd.RegisterFlagCompletionFunc("method", cobra.FixedCompletions([]string{"apikey", "sigv4"}, cobra.ShellCompDirectiveNoFileComp))
	_ = authLoginCmd.RegisterFlagCompletionFunc("store", cobra.FixedCompletions([]string{"home", "project", "keyring"}, cobra.ShellCompDirectiveNoFileComp))

	// Also add flags to the parent auth command for `vulnetix auth --method ...`
	authCmd.Flags().StringVar(&authMethod, "method", "", "Deprecated authentication method selector")
	authCmd.Flags().StringVar(&authOrgID, "org-id", "", "Organization ID (UUID; required for --secret)")
	authCmd.Flags().StringVar(&authToken, "token", "", "Deprecated alias for --api-key")
	authCmd.Flags().StringVar(&authAPIKey, "api-key", "", "ApiKey credential from your VDB account (requires --org-id)")
	authCmd.Flags().StringVar(&authSecret, "secret", "", "SigV4 secret from your VDB account (requires --org-id)")
	authCmd.Flags().StringVar(&authStore, "store", "home", "Credential storage: home, project, keyring")
	authCmd.Flags().StringVar(&authStoreDir, "store-dir", "", "Directory for home/keyring credential metadata instead of $HOME/.vulnetix")
	authCmd.Flags().BoolVar(&authNoninteractive, "noninteractive", false, "Require ApiKey from --api-key or environment; never launch a browser")
	_ = authCmd.Flags().MarkHidden("token")
	_ = authCmd.RegisterFlagCompletionFunc("method", cobra.FixedCompletions([]string{"apikey", "sigv4"}, cobra.ShellCompDirectiveNoFileComp))
	_ = authCmd.RegisterFlagCompletionFunc("store", cobra.FixedCompletions([]string{"home", "project", "keyring"}, cobra.ShellCompDirectiveNoFileComp))

	authStatusCmd.Flags().StringVar(&authStatusBaseURL, "base-url", upload.DefaultBaseURL, "Base URL for Vulnetix API")
	authVerifyCmd.Flags().StringVar(&verifyBaseURL, "base-url", upload.DefaultBaseURL, "Base URL for Vulnetix API")

	authCmd.AddCommand(authLoginCmd, authStatusCmd, authLogoutCmd, authVerifyCmd)
	rootCmd.AddCommand(authCmd)
}
