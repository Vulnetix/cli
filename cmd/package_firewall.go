package cmd

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/pkg/auth"
	pfw "github.com/vulnetix/cli/v3/pkg/packagefirewall"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

const (
	packageFirewallDefaultProxy = "https://packages.vulnetix.com"
	vulnetixBlockStart          = "# Vulnetix Package Firewall"
	vulnetixBlockEnd            = "# End Vulnetix Package Firewall"
)

var (
	packageFirewallBaseURL  string
	packageFirewallProxyURL string
	packageFirewallDryRun   bool
)

var packageFirewallCmd = &cobra.Command{
	Use:   "package-firewall",
	Short: "Configure Vulnetix Package Firewall",
	Long:  "Configure package managers to use the Vulnetix Package Firewall.",
}

var packageFirewallGoCmd = &cobra.Command{
	Use:   "go",
	Short: "Configure Go to use Vulnetix Package Firewall",
	Long: `Configure Go to use the Vulnetix Package Firewall.

This writes Basic auth credentials to netrc, then persists GOPROXY and GOAUTH in
your shell configuration. If project config files are detected at the git root,
they are updated as well.`,
	RunE: runPackageFirewallGo,
}

var packageFirewallGoDevCmd = &cobra.Command{
	Use:   "go-dev",
	Short: "Configure pkgsite-cli to use Vulnetix Package Firewall",
	Long: `Configure pkgsite-cli to use the Vulnetix pkg.go.dev API proxy.

This writes Basic auth credentials to netrc for packages.vulnetix.com and prints
the shell alias or function needed to point pkgsite-cli at the firewall.`,
	RunE: runPackageFirewallGoDev,
}

type packageFirewallAction struct {
	Target string
	Result string
}

func runPackageFirewallGo(cmd *cobra.Command, args []string) error {
	ctx := display.FromCommand(cmd)
	t := ctx.Term

	proxyURL := strings.TrimSpace(packageFirewallProxyURL)
	if proxyURL == "" {
		proxyURL = packageFirewallDefaultProxy
	}
	proxyHost, err := parseProxyHost(proxyURL)
	if err != nil {
		return err
	}

	ctx.Logger.Info("Configuring Vulnetix Package Firewall for Go...")
	orgID, apiKey, credentialSource, err := packageFirewallAPIKey(packageFirewallBaseURL)
	if err != nil {
		return err
	}

	var actions []packageFirewallAction

	netrcPath, err := auth.NetrcPath()
	if err != nil {
		return err
	}
	result, err := upsertNetrc(netrcPath, proxyHost, orgID, apiKey, packageFirewallDryRun)
	if err != nil {
		return err
	}
	actions = append(actions, packageFirewallAction{Target: netrcPath, Result: result})

	shellActions, err := persistGoShellEnv(proxyURL, packageFirewallDryRun)
	if err != nil {
		return err
	}
	actions = append(actions, shellActions...)

	projectActions, err := persistGoProjectEnv(proxyURL, packageFirewallDryRun)
	if err != nil {
		return err
	}
	actions = append(actions, projectActions...)

	var b strings.Builder
	if packageFirewallDryRun {
		b.WriteString(display.Bold(t, "Vulnetix Package Firewall Go setup dry run") + "\n")
	} else {
		b.WriteString(display.Bold(t, "Vulnetix Package Firewall Go setup complete") + "\n")
	}
	b.WriteString(display.KeyValue(t, []display.KVPair{
		{Key: "Credential source", Value: credentialSource},
		{Key: "Organization", Value: orgID},
		{Key: "Proxy", Value: proxyURL},
		{Key: "GOAUTH", Value: "netrc"},
		{Key: "API key", Value: maskSecret(apiKey)},
	}) + "\n")
	b.WriteString("\n" + display.Subheader(t, "Actions") + "\n")
	for _, action := range actions {
		b.WriteString(fmt.Sprintf("  %s: %s\n", action.Target, action.Result))
	}
	ctx.Logger.Result(strings.TrimRight(b.String(), "\n"))
	return nil
}

func runPackageFirewallGoDev(cmd *cobra.Command, args []string) error {
	ctx := display.FromCommand(cmd)
	t := ctx.Term

	proxyURL := strings.TrimSpace(packageFirewallProxyURL)
	if proxyURL == "" {
		proxyURL = packageFirewallDefaultProxy
	}
	proxyHost, err := parseProxyHost(proxyURL)
	if err != nil {
		return err
	}
	apiURL := strings.TrimRight(proxyURL, "/") + "/go-dev/v1beta"

	ctx.Logger.Info("Configuring Vulnetix pkg.go.dev API proxy...")
	orgID, apiKey, credentialSource, err := packageFirewallAPIKey(packageFirewallBaseURL)
	if err != nil {
		return err
	}

	var actions []packageFirewallAction
	netrcPath, err := auth.NetrcPath()
	if err != nil {
		return err
	}
	result, err := upsertNetrc(netrcPath, proxyHost, orgID, apiKey, packageFirewallDryRun)
	if err != nil {
		return err
	}
	actions = append(actions, packageFirewallAction{Target: netrcPath, Result: result})

	var b strings.Builder
	if packageFirewallDryRun {
		b.WriteString(display.Bold(t, "Vulnetix pkg.go.dev API proxy dry run") + "\n")
	} else {
		b.WriteString(display.Bold(t, "Vulnetix pkg.go.dev API proxy configured") + "\n")
	}
	b.WriteString(display.KeyValue(t, []display.KVPair{
		{Key: "Credential source", Value: credentialSource},
		{Key: "Organization", Value: orgID},
		{Key: "API base URL", Value: apiURL},
		{Key: "API key", Value: maskSecret(apiKey)},
	}) + "\n")
	b.WriteString("\n" + display.Subheader(t, "Actions") + "\n")
	for _, action := range actions {
		b.WriteString(fmt.Sprintf("  %s: %s\n", action.Target, action.Result))
	}
	b.WriteString("\n" + display.Subheader(t, "pkgsite-cli setup") + "\n")
	b.WriteString("  pkgsite-cli does not persist a config file, so use one of the following:\n\n")
	b.WriteString("  Shell alias:\n")
	b.WriteString(fmt.Sprintf("    alias pkgsite-cli='pkgsite-cli -api %s'\n\n", apiURL))
	b.WriteString("  Or set for a single invocation:\n")
	b.WriteString(fmt.Sprintf("    pkgsite-cli -api %s search uuid\n\n", apiURL))
	b.WriteString("  Your netrc credentials will be used automatically for Basic auth.\n")
	ctx.Logger.Result(strings.TrimRight(b.String(), "\n"))
	return nil
}

func runPackageFirewallEcosystem(cmd *cobra.Command, eco pfw.Ecosystem) error {
	if err := pfw.RequireWriter(eco); err != nil {
		return err
	}

	ctx := display.FromCommand(cmd)
	t := ctx.Term

	proxyURL := strings.TrimSpace(packageFirewallProxyURL)
	if proxyURL == "" {
		proxyURL = packageFirewallDefaultProxy
	}
	proxyHost, err := parseProxyHost(proxyURL)
	if err != nil {
		return err
	}

	ctx.Logger.Info("Configuring Vulnetix Package Firewall for " + eco.DisplayName + "...")
	orgID, apiKey, credentialSource, err := packageFirewallAPIKey(packageFirewallBaseURL)
	if err != nil {
		return err
	}

	var actions []packageFirewallAction
	netrcPath, err := auth.NetrcPath()
	if err != nil {
		return err
	}
	result, err := upsertNetrc(netrcPath, proxyHost, orgID, apiKey, packageFirewallDryRun)
	if err != nil {
		return err
	}
	actions = append(actions, packageFirewallAction{Target: netrcPath, Result: result})

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	files, err := pfw.ConfigFiles(eco, pfw.ConfigOptions{
		HomeDir:  home,
		ProxyURL: proxyURL,
		OrgID:    orgID,
		APIKey:   apiKey,
	})
	if err != nil {
		return err
	}
	for _, file := range files {
		result, err := upsertPackageFirewallConfigFile(file, packageFirewallDryRun)
		if err != nil {
			return err
		}
		actions = append(actions, packageFirewallAction{Target: file.Path, Result: result})
	}

	var b strings.Builder
	if packageFirewallDryRun {
		b.WriteString(display.Bold(t, "Vulnetix Package Firewall "+eco.DisplayName+" setup dry run") + "\n")
	} else {
		b.WriteString(display.Bold(t, "Vulnetix Package Firewall "+eco.DisplayName+" setup complete") + "\n")
	}
	b.WriteString(display.KeyValue(t, []display.KVPair{
		{Key: "Credential source", Value: credentialSource},
		{Key: "Organization", Value: orgID},
		{Key: "Proxy", Value: pfw.ProxyURL(proxyURL, eco)},
		{Key: "API key", Value: maskSecret(apiKey)},
	}) + "\n")
	b.WriteString("\n" + display.Subheader(t, "Actions") + "\n")
	for _, action := range actions {
		b.WriteString(fmt.Sprintf("  %s: %s\n", action.Target, action.Result))
	}

	if eco.ID == "homebrew" {
		b.WriteString("\n" + display.Subheader(t, "Homebrew setup") + "\n")
		b.WriteString("  Homebrew reads these settings from environment variables.\n")
		if packageFirewallDryRun {
			b.WriteString("  After running without --dry-run, source the env file:\n")
		} else {
			b.WriteString("  Source the env file to activate the firewall:\n")
		}
		envFile := ""
		for _, a := range actions {
			if strings.HasSuffix(a.Target, "homebrew.env") {
				envFile = a.Target
				break
			}
		}
		b.WriteString(fmt.Sprintf("    source %s\n", envFile))
		b.WriteString("  Add that line to your shell profile (e.g. ~/.zshrc or ~/.bashrc) to persist it.\n")
	}

	ctx.Logger.Result(strings.TrimRight(b.String(), "\n"))
	return nil
}

func packageFirewallAPIKey(baseURL string) (orgID, apiKey, source string, err error) {
	creds, err := auth.LoadCredentials()
	if err != nil {
		return "", "", "", fmt.Errorf("authentication required: %w\nRun 'vulnetix auth login' to authenticate", err)
	}

	source = auth.CredentialSource()
	switch creds.Method {
	case auth.DirectAPIKey:
		if err := verifyPackageFirewallDirect(baseURL, creds); err != nil {
			return "", "", "", fmt.Errorf("authentication test failed: %w", err)
		}
		return creds.OrgID, creds.APIKey, source, nil
	case auth.SigV4:
		client := vdb.NewClientFromCredentials(creds)
		if baseURL != "" {
			client.BaseURL = baseURL
		}
		client.APIVersion = "/v2"
		resp, err := client.GetDerivedAPIKey()
		if err != nil {
			return "", "", "", fmt.Errorf("failed to fetch derived API key: %w", err)
		}
		return resp.OrgID, resp.APIKey, source + " (derived API key)", nil
	default:
		return "", "", "", fmt.Errorf("unsupported authentication method: %s", creds.Method)
	}
}

func verifyPackageFirewallDirect(baseURL string, creds *auth.Credentials) error {
	client := vdb.NewClientFromCredentials(creds)
	if baseURL != "" {
		client.BaseURL = baseURL
	}
	now := time.Now()
	_, err := client.GetGCVEIssuances(now.Year(), int(now.Month()), 1, 0)
	return err
}

func parseProxyHost(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return "", fmt.Errorf("--proxy-url must be an absolute URL, got %q", rawURL)
	}
	return u.Hostname(), nil
}

func upsertNetrc(path, machine, orgID, apiKey string, dryRun bool) (string, error) {
	var existing string
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to read %s: %w", path, err)
	}

	next := upsertNetrcMachine(existing, machine, orgID, apiKey)
	if dryRun {
		if existing == next {
			return "already configured", nil
		}
		return "would write netrc credentials", nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", fmt.Errorf("failed to create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(next), 0600); err != nil {
		return "", fmt.Errorf("failed to write %s: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0600); err != nil {
			return "", fmt.Errorf("failed to secure %s: %w", path, err)
		}
	}
	if existing == next {
		return "already configured", nil
	}
	return "wrote Basic auth credentials and secured permissions", nil
}

func upsertNetrcMachine(existing, machine, orgID, apiKey string) string {
	lines := strings.Split(existing, "\n")
	var kept []string
	for i := 0; i < len(lines); i++ {
		fields := strings.Fields(lines[i])
		if len(fields) >= 2 && fields[0] == "machine" && fields[1] == machine {
			i++
			for i < len(lines) {
				nextFields := strings.Fields(lines[i])
				if len(nextFields) > 0 && (nextFields[0] == "machine" || nextFields[0] == "default") {
					i--
					break
				}
				i++
			}
			continue
		}
		kept = append(kept, lines[i])
	}

	base := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	entry := fmt.Sprintf("machine %s\nlogin %s\npassword %s\n", machine, orgID, apiKey)
	if strings.TrimSpace(base) == "" {
		return entry
	}
	return base + "\n\n" + entry
}

func persistGoShellEnv(proxyURL string, dryRun bool) ([]packageFirewallAction, error) {
	if runtime.GOOS == "windows" {
		if dryRun {
			return []packageFirewallAction{
				{Target: "Windows user environment GOPROXY", Result: "would set " + proxyURL},
				{Target: "Windows user environment GOAUTH", Result: "would set netrc"},
			}, nil
		}
		if err := exec.Command("setx", "GOPROXY", proxyURL).Run(); err != nil {
			return nil, fmt.Errorf("failed to persist GOPROXY with setx: %w", err)
		}
		if err := exec.Command("setx", "GOAUTH", "netrc").Run(); err != nil {
			return nil, fmt.Errorf("failed to persist GOAUTH with setx: %w", err)
		}
		return []packageFirewallAction{
			{Target: "Windows user environment GOPROXY", Result: "set " + proxyURL},
			{Target: "Windows user environment GOAUTH", Result: "set netrc"},
		}, nil
	}

	path, shellKind, err := shellConfigPath()
	if err != nil {
		return nil, err
	}
	block := shellEnvBlock(shellKind, proxyURL)
	result, err := upsertBlockFile(path, block, dryRun)
	if err != nil {
		return nil, err
	}
	return []packageFirewallAction{{Target: path, Result: result}}, nil
}

func shellConfigPath() (path, kind string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	switch filepath.Base(os.Getenv("SHELL")) {
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish"), "fish", nil
	case "zsh":
		return filepath.Join(home, ".zshrc"), "sh", nil
	case "tcsh":
		return filepath.Join(home, ".tcshrc"), "csh", nil
	case "csh":
		return filepath.Join(home, ".cshrc"), "csh", nil
	case "bash":
		return filepath.Join(home, ".bashrc"), "sh", nil
	default:
		return filepath.Join(home, ".profile"), "sh", nil
	}
}

func shellEnvBlock(kind, proxyURL string) string {
	switch kind {
	case "fish":
		return strings.Join([]string{
			vulnetixBlockStart,
			"set -gx GOPROXY " + proxyURL,
			"set -gx GOAUTH netrc",
			vulnetixBlockEnd,
			"",
		}, "\n")
	case "csh":
		return strings.Join([]string{
			vulnetixBlockStart,
			"setenv GOPROXY " + proxyURL,
			"setenv GOAUTH netrc",
			vulnetixBlockEnd,
			"",
		}, "\n")
	default:
		return strings.Join([]string{
			vulnetixBlockStart,
			"export GOPROXY=\"" + proxyURL + "\"",
			"export GOAUTH=\"netrc\"",
			vulnetixBlockEnd,
			"",
		}, "\n")
	}
}

func persistGoProjectEnv(proxyURL string, dryRun bool) ([]packageFirewallAction, error) {
	root, err := gitRoot()
	if err != nil {
		return nil, nil
	}

	var actions []packageFirewallAction
	for _, spec := range []struct {
		name string
		body string
	}{
		{name: ".env", body: "GOPROXY=" + proxyURL + "\nGOAUTH=netrc\n"},
		{name: ".envrc", body: "export GOPROXY=\"" + proxyURL + "\"\nexport GOAUTH=\"netrc\"\n"},
		{name: "Makefile", body: "export GOPROXY=" + proxyURL + "\nexport GOAUTH=netrc\n"},
	} {
		path := filepath.Join(root, spec.name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		result, err := upsertKeyValues(path, spec.body, dryRun)
		if err != nil {
			return nil, err
		}
		actions = append(actions, packageFirewallAction{Target: path, Result: result})
	}
	return actions, nil
}

func gitRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func upsertBlockFile(path, block string, dryRun bool) (string, error) {
	var existing string
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	next := upsertManagedBlock(existing, block)
	if dryRun {
		if existing == next {
			return "already configured", nil
		}
		return "would update persistent shell config", nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(next), 0600); err != nil {
		return "", err
	}
	if existing == next {
		return "already configured", nil
	}
	return "updated persistent shell config", nil
}

func upsertPackageFirewallConfigFile(file pfw.ConfigFile, dryRun bool) (string, error) {
	var existing string
	existed := false
	if data, err := os.ReadFile(file.Path); err == nil {
		existing = string(data)
		existed = true
	} else if !os.IsNotExist(err) {
		return "", err
	}

	var next string
	switch {
	case file.Merge != nil:
		merged, err := file.Merge(existing)
		if err != nil {
			return "", err
		}
		next = merged
	case file.Structured:
		next = file.Content
	default:
		block := strings.Join([]string{
			vulnetixBlockStart,
			strings.TrimRight(file.Content, "\n"),
			vulnetixBlockEnd,
			"",
		}, "\n")
		next = upsertManagedBlock(existing, block)
	}

	if dryRun {
		if existing == next {
			return "already configured", nil
		}
		return "would update package manager config", nil
	}
	if existing == next {
		return "already configured", nil
	}
	if err := os.MkdirAll(filepath.Dir(file.Path), 0700); err != nil {
		return "", err
	}
	// Back up a real config we are merging into, so the user can restore it.
	if file.Merge != nil && existed {
		if err := os.WriteFile(file.Path+".vulnetix.bak", []byte(existing), 0600); err != nil {
			return "", fmt.Errorf("failed to back up %s: %w", file.Path, err)
		}
	}
	if err := os.WriteFile(file.Path, []byte(next), 0600); err != nil {
		return "", err
	}
	if file.Merge != nil && existed {
		return "merged firewall settings (backup written)", nil
	}
	return "updated package manager config", nil
}

func upsertManagedBlock(existing, block string) string {
	start := strings.Index(existing, vulnetixBlockStart)
	if start >= 0 {
		end := strings.Index(existing[start:], vulnetixBlockEnd)
		if end >= 0 {
			end += start + len(vulnetixBlockEnd)
			for end < len(existing) && (existing[end] == '\n' || existing[end] == '\r') {
				end++
			}
			prefix := strings.TrimRight(existing[:start], "\n")
			suffix := strings.TrimLeft(existing[end:], "\n")
			if prefix == "" {
				return block + suffix
			}
			return prefix + "\n\n" + block + suffix
		}
	}
	if strings.TrimSpace(existing) == "" {
		return block
	}
	return strings.TrimRight(existing, "\n") + "\n\n" + block
}

func upsertKeyValues(path, body string, dryRun bool) (string, error) {
	existingBytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	existing := string(existingBytes)
	next := upsertGoEnvValues(existing, body)
	if dryRun {
		if existing == next {
			return "already configured", nil
		}
		return "would update Go proxy environment values", nil
	}
	if err := os.WriteFile(path, []byte(next), 0600); err != nil {
		return "", err
	}
	if existing == next {
		return "already configured", nil
	}
	return "updated Go proxy environment values", nil
}

func upsertGoEnvValues(existing, body string) string {
	lines := strings.Split(existing, "\n")
	var kept []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isGoEnvLine(trimmed, "GOPROXY") || isGoEnvLine(trimmed, "GOAUTH") {
			continue
		}
		kept = append(kept, line)
	}
	base := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	if strings.TrimSpace(base) == "" {
		return body
	}
	return base + "\n" + body
}

func isGoEnvLine(line, key string) bool {
	return strings.HasPrefix(line, key+"=") ||
		strings.HasPrefix(line, "export "+key+"=") ||
		strings.HasPrefix(line, "setenv "+key+" ") ||
		strings.HasPrefix(line, "set -gx "+key+" ")
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

func init() {
	addPackageFirewallFlags(packageFirewallGoCmd, "Go")
	packageFirewallCmd.AddCommand(packageFirewallGoCmd)
	addPackageFirewallFlags(packageFirewallGoDevCmd, "Go pkg.go.dev API")
	packageFirewallCmd.AddCommand(packageFirewallGoDevCmd)
	for _, eco := range pfw.All() {
		if eco.Command == "go" {
			continue
		}
		eco := eco
		c := &cobra.Command{
			Use:   eco.Command,
			Short: "Configure " + eco.DisplayName + " to use Vulnetix Package Firewall",
			RunE: func(cmd *cobra.Command, args []string) error {
				return runPackageFirewallEcosystem(cmd, eco)
			},
		}
		addPackageFirewallFlags(c, eco.DisplayName)
		packageFirewallCmd.AddCommand(c)
	}
	rootCmd.AddCommand(packageFirewallCmd)
}

func addPackageFirewallFlags(cmd *cobra.Command, label string) {
	cmd.Flags().StringVar(&packageFirewallBaseURL, "base-url", vdb.DefaultBaseURL, "VDB API base URL")
	cmd.Flags().StringVar(&packageFirewallProxyURL, "proxy-url", packageFirewallDefaultProxy, "Package Firewall "+label+" proxy URL")
	cmd.Flags().BoolVar(&packageFirewallDryRun, "dry-run", false, "Show planned changes without writing files")
}
