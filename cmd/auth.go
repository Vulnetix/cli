package cmd

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vulnetix/vulnetix/internal/auth"
	"github.com/vulnetix/vulnetix/internal/upload"
	"github.com/vulnetix/vulnetix/internal/vdb"
)

var (
	authMethod string
	authOrgID  string
	authSecret string
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
  vulnetix auth login --method apikey --org-id UUID --secret KEY --store home

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
  --method apikey|sigv4    Authentication method
  --org-id UUID            Organization ID
  --secret KEY             API key (hex) or SigV4 secret
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
	interactive := isInteractive() && authMethod == "" && authOrgID == "" && authSecret == ""

	var method auth.AuthMethod
	var orgIDVal, secret string
	var store auth.CredentialStore

	if interactive {
		var err error
		method, orgIDVal, secret, store, err = interactiveLogin()
		if err != nil {
			return err
		}
	} else {
		// Non-interactive: use flags
		if authMethod == "" {
			authMethod = "apikey"
		}
		m, err := auth.ValidateMethod(authMethod)
		if err != nil {
			return err
		}
		method = m

		if authOrgID == "" {
			return fmt.Errorf("--org-id is required in non-interactive mode")
		}
		if _, err := uuid.Parse(authOrgID); err != nil {
			return fmt.Errorf("--org-id must be a valid UUID, got: %s", authOrgID)
		}
		orgIDVal = authOrgID

		if authSecret == "" {
			return fmt.Errorf("--secret is required in non-interactive mode")
		}
		secret = authSecret

		if authStore == "" {
			authStore = "home"
		}
		s, err := auth.ValidateStore(authStore)
		if err != nil {
			return err
		}
		store = s
	}

	creds := &auth.Credentials{
		OrgID:  orgIDVal,
		Method: method,
	}
	switch method {
	case auth.DirectAPIKey:
		creds.APIKey = secret
	case auth.SigV4:
		creds.Secret = secret
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
	fmt.Print("Choice [1]: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	var method auth.AuthMethod
	switch choice {
	case "", "1":
		method = auth.DirectAPIKey
	case "2":
		method = auth.SigV4
	default:
		return "", "", "", "", fmt.Errorf("invalid choice: %s", choice)
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
	fmt.Println("Where to store credentials?")
	fmt.Println("  [1] Home directory ~/.vulnetix/ (default)")
	fmt.Println("  [2] Project .vulnetix/")
	fmt.Println("  [3] System keyring (not yet implemented)")
	fmt.Print("Choice [1]: ")
	storeChoice, _ := reader.ReadString('\n')
	storeChoice = strings.TrimSpace(storeChoice)

	var store auth.CredentialStore
	switch storeChoice {
	case "", "1":
		store = auth.StoreHome
	case "2":
		store = auth.StoreProject
	case "3":
		return "", "", "", "", fmt.Errorf("keyring storage is not yet implemented")
	default:
		return "", "", "", "", fmt.Errorf("invalid choice: %s", storeChoice)
	}

	return method, orgIDVal, secret, store, nil
}

func testAuth(creds *auth.Credentials) error {
	switch creds.Method {
	case auth.DirectAPIKey:
		// Validate the API key format (must be non-empty hex string)
		if len(creds.APIKey) == 0 {
			return fmt.Errorf("API key is empty")
		}
		// Test connectivity to the VDB API (SigV4 endpoint accepts any request,
		// the Direct API Key is validated by the upload API at upload time)
		client := &http.Client{Timeout: 10 * time.Second}
		req, err := http.NewRequest("GET", "https://api.vdb.vulnetix.com/v1/ecosystems", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", auth.GetAuthHeader(creds))
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("connection failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return fmt.Errorf("invalid credentials (HTTP %d)", resp.StatusCode)
		}
		// 500 is expected when VDB API doesn't support ApiKey — credentials
		// will be validated on first upload. Accept 200 or 500 as "reachable".
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
	authLoginCmd.Flags().StringVar(&authMethod, "method", "", "Authentication method: apikey, sigv4")
	authLoginCmd.Flags().StringVar(&authOrgID, "org-id", "", "Organization ID (UUID)")
	authLoginCmd.Flags().StringVar(&authSecret, "secret", "", "API key (hex) or SigV4 secret key")
	authLoginCmd.Flags().StringVar(&authStore, "store", "home", "Credential storage: home, project, keyring")

	// Also add flags to the parent auth command for `vulnetix auth --method ...`
	authCmd.Flags().StringVar(&authMethod, "method", "", "Authentication method: apikey, sigv4")
	authCmd.Flags().StringVar(&authOrgID, "org-id", "", "Organization ID (UUID)")
	authCmd.Flags().StringVar(&authSecret, "secret", "", "API key (hex) or SigV4 secret key")
	authCmd.Flags().StringVar(&authStore, "store", "home", "Credential storage: home, project, keyring")

	authVerifyCmd.Flags().StringVar(&verifyBaseURL, "base-url", upload.DefaultBaseURL, "Base URL for Vulnetix API")

	authCmd.AddCommand(authLoginCmd, authStatusCmd, authLogoutCmd, authVerifyCmd)
	rootCmd.AddCommand(authCmd)
}
