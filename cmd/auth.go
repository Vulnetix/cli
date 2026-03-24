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
	"github.com/vulnetix/cli/internal/auth"
	"github.com/vulnetix/cli/internal/upload"
	"github.com/vulnetix/cli/internal/vdb"
)

var (
	authMethod string
	authOrgID  string
	authSecret string
	authAPIKey string
	authStore  string
)

// authCmd represents the auth command
var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage Vulnetix authentication",
	Long: `Manage authentication credentials for the Vulnetix API.

Examples:
  # Interactive login
  vulnetix auth

  # Non-interactive login with Direct API Key
  vulnetix auth login --org-id UUID --api-key KEY --store home

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
	Long: `Log in to the Vulnetix API. Interactive by default when run in a terminal.

Non-interactive flags:
  --method apikey|sigv4    Authentication method (auto-detected if omitted)
  --org-id UUID            Organization ID
  --api-key KEY            API key for Direct API Key auth
  --secret KEY             Secret key for SigV4 auth
  --store home|project     Where to save credentials`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAuthLogin(cmd)
	},
}

var authStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current authentication state",
	RunE: func(cmd *cobra.Command, args []string) error {
		status, creds := auth.CredentialStatus()
		fmt.Println(status)
		if creds != nil {
			fmt.Printf("  Organization: %s\n", creds.OrgID)
			fmt.Printf("  Method: %s\n", creds.Method)
			if creds.Method == auth.DirectAPIKey {
				masked := creds.APIKey
				if len(masked) > 8 {
					masked = masked[:4] + "..." + masked[len(masked)-4:]
				}
				fmt.Printf("  API Key: %s\n", masked)
			} else {
				masked := creds.Secret
				if len(masked) > 8 {
					masked = masked[:4] + "..." + masked[len(masked)-4:]
				}
				fmt.Printf("  Secret: %s\n", masked)
			}
		}
		fmt.Println("\nAll credential sources:")
		for _, line := range auth.AllSourceStatus() {
			fmt.Printf("  %s\n", line)
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
		return runAuthVerify()
	},
}

var authLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := auth.RemoveCredentials(); err != nil {
			return fmt.Errorf("failed to remove credentials: %w", err)
		}
		fmt.Println("Credentials removed successfully")
		return nil
	},
}

func runAuthLogin(cmd *cobra.Command) error {
	interactive := isInteractive() && authMethod == "" && authOrgID == "" && authSecret == "" && authAPIKey == ""

	var method auth.AuthMethod
	var orgIDVal string
	var store auth.CredentialStore
	var creds *auth.Credentials

	if interactive {
		var secret string
		var err error
		method, orgIDVal, secret, store, err = interactiveLogin()
		if err != nil {
			return err
		}
		creds = &auth.Credentials{
			OrgID:  orgIDVal,
			Method: method,
		}
		switch method {
		case auth.DirectAPIKey:
			creds.APIKey = secret
		case auth.SigV4:
			creds.Secret = secret
		}
	} else {
		// Non-interactive: use flags
		if authSecret != "" && authAPIKey != "" {
			return fmt.Errorf("cannot use both --secret and --api-key; choose one authentication method")
		}

		if authOrgID == "" {
			return fmt.Errorf("--org-id is required in non-interactive mode")
		}
		if _, err := uuid.Parse(authOrgID); err != nil {
			return fmt.Errorf("--org-id must be a valid UUID, got: %s", authOrgID)
		}
		orgIDVal = authOrgID

		// Determine method
		if authMethod != "" {
			m, err := auth.ValidateMethod(authMethod)
			if err != nil {
				return err
			}
			method = m
			switch m {
			case auth.DirectAPIKey:
				if authAPIKey == "" {
					return fmt.Errorf("--method apikey requires --api-key")
				}
			case auth.SigV4:
				if authSecret == "" {
					return fmt.Errorf("--method sigv4 requires --secret")
				}
			}
		} else {
			// Auto-detect from which flag was provided
			switch {
			case authAPIKey != "":
				method = auth.DirectAPIKey
			case authSecret != "":
				method = auth.SigV4
			default:
				return fmt.Errorf("--api-key or --secret is required in non-interactive mode")
			}
		}

		if authStore == "" {
			authStore = "home"
		}
		s, err := auth.ValidateStore(authStore)
		if err != nil {
			return err
		}
		store = s

		creds = &auth.Credentials{
			OrgID:  orgIDVal,
			Method: method,
		}
		switch method {
		case auth.DirectAPIKey:
			creds.APIKey = authAPIKey
		case auth.SigV4:
			creds.Secret = authSecret
		}
	}

	// Test authentication
	fmt.Println("Testing authentication...")
	if err := testAuth(creds); err != nil {
		return fmt.Errorf("authentication test failed: %w", err)
	}
	fmt.Println("Authentication successful")

	// Save credentials
	if err := auth.SaveCredentials(creds, store); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}
	fmt.Printf("Credentials saved to %s store\n", store)

	return nil
}

func interactiveLogin() (auth.AuthMethod, string, string, auth.CredentialStore, error) {
	reader := bufio.NewReader(os.Stdin)

	// 1. Select auth method
	fmt.Println("Select authentication method:")
	fmt.Println("  [1] Direct API Key (recommended)")
	fmt.Println("  [2] SigV4")
	fmt.Println("  [3] Browser Login")
	fmt.Print("Choice [1]: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "", "1":
		// Direct API Key flow
	case "2":
		// SigV4 flow
	case "3":
		return browserLogin(reader)
	default:
		return "", "", "", "", fmt.Errorf("invalid choice: %s", choice)
	}

	var method auth.AuthMethod
	if choice == "2" {
		method = auth.SigV4
	} else {
		method = auth.DirectAPIKey
	}

	// 2. Organization ID
	fmt.Print("Organization ID (UUID): ")
	orgIDVal, _ := reader.ReadString('\n')
	orgIDVal = strings.TrimSpace(orgIDVal)
	if _, err := uuid.Parse(orgIDVal); err != nil {
		return "", "", "", "", fmt.Errorf("invalid UUID: %s", orgIDVal)
	}

	// 3. Secret/API Key
	var prompt string
	if method == auth.DirectAPIKey {
		prompt = "API Key (hex): "
	} else {
		prompt = "Secret Key: "
	}
	fmt.Print(prompt)
	secret, _ := reader.ReadString('\n')
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "", "", "", "", fmt.Errorf("secret cannot be empty")
	}

	// 4. Storage location
	store, err := promptStore(reader)
	if err != nil {
		return "", "", "", "", err
	}

	return method, orgIDVal, secret, store, nil
}

func promptStore(reader *bufio.Reader) (auth.CredentialStore, error) {
	fmt.Println("Where to store credentials?")
	fmt.Println("  [1] Home directory ~/.vulnetix/ (default)")
	fmt.Println("  [2] Project .vulnetix/")
	fmt.Println("  [3] System keyring (not yet implemented)")
	fmt.Print("Choice [1]: ")
	storeChoice, _ := reader.ReadString('\n')
	storeChoice = strings.TrimSpace(storeChoice)

	switch storeChoice {
	case "", "1":
		return auth.StoreHome, nil
	case "2":
		return auth.StoreProject, nil
	case "3":
		return "", fmt.Errorf("keyring storage is not yet implemented")
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

func browserLogin(reader *bufio.Reader) (auth.AuthMethod, string, string, auth.CredentialStore, error) {
	for {
		code, err := generateCode()
		if err != nil {
			return "", "", "", "", err
		}

		fmt.Println()
		fmt.Println("Open this URL in your browser:")
		fmt.Println()
		fmt.Printf("  %s\n", browserLoginURL)
		fmt.Println()
		fmt.Println("Then enter this code when prompted:")
		fmt.Println()
		fmt.Printf("  \033[1m%s\033[0m\n", code) // bold
		fmt.Println()
		fmt.Println("Waiting for browser authorization...")

		orgID, apiKey, err := pollForAuth(code)
		if err != nil {
			// Timeout — prompt retry
			fmt.Println()
			fmt.Print("Code expired. Try again? [Y/n]: ")
			retry, _ := reader.ReadString('\n')
			retry = strings.TrimSpace(strings.ToLower(retry))
			if retry == "" || retry == "y" || retry == "yes" {
				continue
			}
			return "", "", "", "", fmt.Errorf("browser login cancelled")
		}

		// Parse apiKey "orgId:hex" — the full value is the api key
		// The orgId is returned separately
		parts := strings.SplitN(apiKey, ":", 2)
		if len(parts) != 2 {
			return "", "", "", "", fmt.Errorf("unexpected API key format from server")
		}
		apiKeyHex := parts[1]

		fmt.Printf("\n\033[32mAuthentication successful!\033[0m\n") // green
		fmt.Println()

		store, err := promptStore(reader)
		if err != nil {
			return "", "", "", "", err
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

func testAuth(creds *auth.Credentials) error {
	switch creds.Method {
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
		fmt.Println("VDB API: OK")
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

func runAuthVerify() error {
	creds, err := auth.LoadCredentials()
	if err != nil {
		return fmt.Errorf("no credentials found: %w\nRun 'vulnetix auth login' to authenticate", err)
	}

	fmt.Printf("Verifying credentials for org %s...\n", creds.OrgID)

	client := upload.NewClient(verifyBaseURL, creds)
	result, err := client.VerifyAuth()
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	fmt.Printf("Authentication verified successfully\n")
	fmt.Printf("  Organization: %s\n", result.OrgID)
	return nil
}

func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func init() {
	authLoginCmd.Flags().StringVar(&authMethod, "method", "", "Authentication method: apikey, sigv4 (auto-detected if omitted)")
	authLoginCmd.Flags().StringVar(&authOrgID, "org-id", "", "Organization ID (UUID)")
	authLoginCmd.Flags().StringVar(&authAPIKey, "api-key", "", "Direct API key (hex)")
	authLoginCmd.Flags().StringVar(&authSecret, "secret", "", "SigV4 secret key")
	authLoginCmd.Flags().StringVar(&authStore, "store", "home", "Credential storage: home, project, keyring")

	// Also add flags to the parent auth command for `vulnetix auth --method ...`
	authCmd.Flags().StringVar(&authMethod, "method", "", "Authentication method: apikey, sigv4 (auto-detected if omitted)")
	authCmd.Flags().StringVar(&authOrgID, "org-id", "", "Organization ID (UUID)")
	authCmd.Flags().StringVar(&authAPIKey, "api-key", "", "Direct API key (hex)")
	authCmd.Flags().StringVar(&authSecret, "secret", "", "SigV4 secret key")
	authCmd.Flags().StringVar(&authStore, "store", "home", "Credential storage: home, project, keyring")

	authVerifyCmd.Flags().StringVar(&verifyBaseURL, "base-url", upload.DefaultBaseURL, "Base URL for Vulnetix API")

	authCmd.AddCommand(authLoginCmd, authStatusCmd, authLogoutCmd, authVerifyCmd)
	rootCmd.AddCommand(authCmd)
}
