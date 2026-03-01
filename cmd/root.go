package cmd

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/vulnetix/cli/internal/auth"
	"github.com/vulnetix/cli/internal/config"
	"github.com/vulnetix/cli/internal/vdb"
)

var (
	// Command line flags
	orgID   string
	version = "1.0.0" // This will be set during build
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vulnetix",
	Short: "Vulnetix CLI - Automate vulnerability remediation",
	Long: `Vulnetix CLI is a command-line tool for vulnerability management that focuses on
automated remediation over discovery. It helps organizations prioritize and resolve
vulnerabilities efficiently.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runInfoTask()
	},
}

// runInfoTask performs an authentication healthcheck across all credential sources
func runInfoTask() error {
	fmt.Printf("Vulnetix CLI v%s\n", version)
	fmt.Printf("Platform: %s\n\n", config.DetectPlatform())

	fmt.Println("Authentication Sources:")
	fmt.Println()

	anyFound := false

	// 1. Check Direct API Key env vars
	apiKey := os.Getenv("VULNETIX_API_KEY")
	envOrgID := os.Getenv("VULNETIX_ORG_ID")
	fmt.Print("  VULNETIX_API_KEY + VULNETIX_ORG_ID (env) ... ")
	if apiKey != "" && envOrgID != "" {
		anyFound = true
		creds := &auth.Credentials{
			OrgID:  envOrgID,
			APIKey: apiKey,
			Method: auth.DirectAPIKey,
		}
		if err := verifyDirectAPIKey(creds); err != nil {
			fmt.Printf("FAIL (%s)\n", err)
		} else {
			fmt.Printf("OK (org: %s)\n", envOrgID)
		}
	} else {
		fmt.Println("not set")
	}

	// 2. Check SigV4 env vars
	vvdOrg := os.Getenv("VVD_ORG")
	vvdSecret := os.Getenv("VVD_SECRET")
	fmt.Print("  VVD_ORG + VVD_SECRET (env)               ... ")
	if vvdOrg != "" && vvdSecret != "" {
		anyFound = true
		if err := verifySigV4(vvdOrg, vvdSecret); err != nil {
			fmt.Printf("FAIL (%s)\n", err)
		} else {
			fmt.Printf("OK (org: %s)\n", vvdOrg)
		}
	} else {
		fmt.Println("not set")
	}

	// 3. Check project dotfile
	fmt.Print("  .vulnetix/credentials.json (project)      ... ")
	if creds, err := loadCredentialFile(auth.StoreProject); err == nil {
		anyFound = true
		if verr := verifyCredentials(creds); verr != nil {
			fmt.Printf("FAIL (%s)\n", verr)
		} else {
			fmt.Printf("OK (method: %s, org: %s)\n", creds.Method, creds.OrgID)
		}
	} else {
		fmt.Println("not found")
	}

	// 4. Check home directory
	homeDir, _ := os.UserHomeDir()
	homePath := filepath.Join(homeDir, ".vulnetix", "credentials.json")
	fmt.Printf("  %s (home) ... ", homePath)
	if creds, err := loadCredentialFile(auth.StoreHome); err == nil {
		anyFound = true
		if verr := verifyCredentials(creds); verr != nil {
			fmt.Printf("FAIL (%s)\n", verr)
		} else {
			fmt.Printf("OK (method: %s, org: %s)\n", creds.Method, creds.OrgID)
		}
	} else {
		fmt.Println("not found")
	}

	fmt.Println()
	if !anyFound {
		fmt.Println("No credentials configured. Run 'vulnetix auth login' to get started.")
	}
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
	if err := yaml.Unmarshal(data, &creds); err != nil {
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
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://api.vdb.vulnetix.com/v1/ecosystems", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth.GetAuthHeader(creds))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("invalid credentials")
	}
	return nil
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
	return rootCmd.Execute()
}

func init() {
	// Define flags
	rootCmd.PersistentFlags().StringVar(&orgID, "org-id", "", "Organization ID (UUID) for Vulnetix operations")

	// Add version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of Vulnetix CLI",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Vulnetix CLI v%s\n", version)
		},
	}

	rootCmd.AddCommand(versionCmd)
}
