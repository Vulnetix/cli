package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/managedfile"
	"github.com/vulnetix/cli/v3/pkg/auth"
	pfw "github.com/vulnetix/cli/v3/pkg/packagefirewall"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

const (
	packageFirewallDefaultProxy = "https://packages.vulnetix.com"
	vulnetixBlockStart          = "# Vulnetix Package Firewall"
	vulnetixBlockEnd            = "# End Vulnetix Package Firewall"
)

// pfwMarkers fence the Package Firewall's managed block. The AI Firewall uses
// its own markers, so the two can coexist in one shell rc and each uninstall
// only strips its own block.
var pfwMarkers = managedfile.Markers{Start: vulnetixBlockStart, End: vulnetixBlockEnd}

// pfwEnvKeys are the environment variables the Go setup owns in project env files.
var pfwEnvKeys = []string{"GOPROXY", "GOAUTH"}

// managedFile adapts a pfw.ConfigFile to the shared writer.
func managedFile(file pfw.ConfigFile) managedfile.File {
	return managedfile.File{
		Path:       file.Path,
		Content:    file.Content,
		Structured: file.Structured,
		Merge:      file.Merge,
		Strip:      stripMergeKeys,
	}
}

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
	base := removeNetrcMachine(existing, machine)
	entry := fmt.Sprintf("machine %s\nlogin %s\npassword %s\n", machine, orgID, apiKey)
	if strings.TrimSpace(base) == "" {
		return entry
	}
	return base + "\n\n" + entry
}

// removeNetrcMachine returns existing with the `machine <machine>` block (its
// login/password lines up to the next machine/default entry) removed. The
// returned content is trimmed of any trailing newline.
func removeNetrcMachine(existing, machine string) string {
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
	return strings.TrimRight(strings.Join(kept, "\n"), "\n")
}

func persistGoShellEnv(proxyURL string, dryRun bool) ([]packageFirewallAction, error) {
	if runtime.GOOS == "windows" {
		if dryRun {
			return []packageFirewallAction{
				{Target: "Windows user environment GOPROXY", Result: "would set " + proxyURL},
				{Target: "Windows user environment GOAUTH", Result: "would set netrc"},
			}, nil
		}
		if err := managedfile.PersistUserEnv([]managedfile.KV{
			{Key: "GOPROXY", Value: proxyURL},
			{Key: "GOAUTH", Value: "netrc"},
		}); err != nil {
			return nil, fmt.Errorf("failed to persist Go proxy environment with setx: %w", err)
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
	return managedfile.ShellConfigPath()
}

func shellEnvBlock(kind, proxyURL string) string {
	return managedfile.EnvBlock(kind, pfwMarkers, []managedfile.KV{
		{Key: "GOPROXY", Value: proxyURL},
		{Key: "GOAUTH", Value: "netrc"},
	})
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
	return managedfile.GitRoot()
}

func upsertBlockFile(path, block string, dryRun bool) (string, error) {
	changed, err := managedfile.UpsertBlockFile(path, block, pfwMarkers, dryRun)
	if err != nil {
		return "", err
	}
	switch {
	case !changed:
		return "already configured", nil
	case dryRun:
		return "would update persistent shell config", nil
	default:
		return "updated persistent shell config", nil
	}
}

func upsertPackageFirewallConfigFile(file pfw.ConfigFile, dryRun bool) (string, error) {
	out, err := managedfile.UpsertFile(managedFile(file), pfwMarkers, dryRun)
	if err != nil {
		return "", err
	}
	switch {
	case !out.Changed:
		return "already configured", nil
	case dryRun:
		return "would update package manager config", nil
	case out.BackedUp:
		return "merged firewall settings (backup written)", nil
	default:
		return "updated package manager config", nil
	}
}

func upsertManagedBlock(existing, block string) string {
	return managedfile.Upsert(existing, block, pfwMarkers)
}

// removeManagedBlock returns existing with the Vulnetix managed block (and its
// surrounding blank lines) removed. The bool reports whether a block was found.
func removeManagedBlock(existing string) (string, bool) {
	return managedfile.Remove(existing, pfwMarkers)
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
	return managedfile.UpsertEnvValues(existing, body, pfwEnvKeys)
}

// removeGoEnvValues returns existing with any GOPROXY / GOAUTH assignment lines
// removed (the reverse of upsertGoEnvValues). The bool reports whether anything
// was removed. An empty result means the file held only those values.
func removeGoEnvValues(existing string) (string, bool) {
	return managedfile.RemoveEnvValues(existing, pfwEnvKeys)
}

func maskSecret(s string) string {
	return managedfile.MaskSecret(s)
}

var (
	packageFirewallUninstallAll    bool
	packageFirewallUninstallExcept []string
	packageFirewallUninstallCreds  bool
	packageFirewallUninstallPurge  bool
)

var packageFirewallUninstallCmd = &cobra.Command{
	Use:   "uninstall [ecosystem...]",
	Short: "Remove Vulnetix Package Firewall configuration",
	Long: `Remove the configuration written by 'vulnetix package-firewall <ecosystem>'.

Name one or more ecosystems to unconfigure exactly those, or use --all for every
supported ecosystem, or --except to unconfigure all but the named ones. The shared
netrc credential (machine packages.vulnetix.com) is left in place unless
--remove-credentials (or --purge) is given, because every ecosystem authenticates
with the same entry — removing it would break any ecosystem still configured.

Requires no authentication: it operates on local files only.`,
	RunE: runPackageFirewallUninstall,
}

func runPackageFirewallUninstall(cmd *cobra.Command, args []string) error {
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

	all := packageFirewallUninstallAll || packageFirewallUninstallPurge
	removeCreds := packageFirewallUninstallCreds || packageFirewallUninstallPurge

	targets, err := resolveUninstallTargets(args, packageFirewallUninstallExcept, all)
	if err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	dryRun := packageFirewallDryRun
	ctx.Logger.Info("Removing Vulnetix Package Firewall configuration...")

	var actions []packageFirewallAction
	for _, eco := range targets {
		ecoActions, err := uninstallEcosystem(eco, home, proxyHost, dryRun)
		if err != nil {
			return err
		}
		actions = append(actions, ecoActions...)
	}

	netrcPath, err := auth.NetrcPath()
	if err != nil {
		return err
	}
	if removeCreds {
		result, err := removeNetrcCredential(netrcPath, proxyHost, dryRun)
		if err != nil {
			return err
		}
		actions = append(actions, packageFirewallAction{Target: netrcPath, Result: result})
	}

	// The netrc entry is shared. If we removed it while other ecosystems still
	// point at the firewall, those will now fail auth — warn explicitly.
	var warning string
	if removeCreds {
		if remaining := configuredEcosystems(home, proxyHost, targets); len(remaining) > 0 {
			warning = "credentials removed, but these ecosystems still point at the firewall and will now fail auth: " + strings.Join(remaining, ", ")
		}
	}

	var b strings.Builder
	if dryRun {
		b.WriteString(display.Bold(t, "Vulnetix Package Firewall uninstall dry run") + "\n")
	} else {
		b.WriteString(display.Bold(t, "Vulnetix Package Firewall uninstall complete") + "\n")
	}
	b.WriteString(display.KeyValue(t, []display.KVPair{
		{Key: "Ecosystems", Value: targetNames(targets)},
		{Key: "Proxy host", Value: proxyHost},
		{Key: "Credentials", Value: credsLabel(removeCreds)},
	}) + "\n")
	b.WriteString("\n" + display.Subheader(t, "Actions") + "\n")
	for _, action := range actions {
		b.WriteString(fmt.Sprintf("  %s: %s\n", action.Target, action.Result))
	}
	if warning != "" {
		b.WriteString("\n" + display.Subheader(t, "Warning") + "\n  " + warning + "\n")
	}
	ctx.Logger.Result(strings.TrimRight(b.String(), "\n"))
	return nil
}

// resolveEcosystem maps a command name to an ecosystem. go-dev is not in the
// registry (it writes only netrc) but is accepted as a named target.
func resolveEcosystem(name string) (pfw.Ecosystem, bool) {
	if name == "go-dev" {
		return pfw.Ecosystem{ID: "go-dev", Command: "go-dev", DisplayName: "Go pkg.go.dev API"}, true
	}
	return pfw.ByCommand(name)
}

// resolveUninstallTargets validates the selection flags (exactly one selector)
// and returns the ecosystems to unconfigure.
func resolveUninstallTargets(args, except []string, all bool) ([]pfw.Ecosystem, error) {
	selectors := 0
	if len(args) > 0 {
		selectors++
	}
	if len(except) > 0 {
		selectors++
	}
	if all {
		selectors++
	}
	if selectors == 0 {
		return nil, fmt.Errorf("select what to remove: name one or more ecosystems, or pass --all or --except")
	}
	if selectors > 1 {
		return nil, fmt.Errorf("use only one selector: ecosystem arguments, --all, or --except")
	}

	if all {
		return pfw.All(), nil
	}
	if len(except) > 0 {
		skip := map[string]bool{}
		for _, name := range except {
			eco, ok := resolveEcosystem(strings.TrimSpace(name))
			if !ok {
				return nil, fmt.Errorf("unknown ecosystem %q", name)
			}
			skip[eco.ID] = true
		}
		var out []pfw.Ecosystem
		for _, eco := range pfw.All() {
			if !skip[eco.ID] {
				out = append(out, eco)
			}
		}
		return out, nil
	}
	var out []pfw.Ecosystem
	for _, name := range args {
		eco, ok := resolveEcosystem(strings.TrimSpace(name))
		if !ok {
			return nil, fmt.Errorf("unknown ecosystem %q", name)
		}
		out = append(out, eco)
	}
	return out, nil
}

// uninstallEcosystem reverses the writes for one ecosystem, based on how each
// file was written (managed block / structured / merge). go and go-dev have
// bespoke handling; ecosystems without an automatic writer wrote nothing.
func uninstallEcosystem(eco pfw.Ecosystem, home, proxyHost string, dryRun bool) ([]packageFirewallAction, error) {
	switch eco.ID {
	case "go":
		return uninstallGo(dryRun)
	case "go-dev":
		return []packageFirewallAction{{Target: eco.DisplayName, Result: "netrc-only; pass --remove-credentials to remove the shared credential"}}, nil
	}
	if !eco.LiveWriter {
		return []packageFirewallAction{{Target: eco.DisplayName, Result: "no automatic configuration to remove"}}, nil
	}
	files, err := pfw.ConfigFiles(eco, pfw.ConfigOptions{HomeDir: home})
	if err != nil {
		return nil, err
	}
	var actions []packageFirewallAction
	for _, file := range files {
		result, err := removePackageFirewallConfigFile(file, proxyHost, dryRun)
		if err != nil {
			return nil, err
		}
		actions = append(actions, packageFirewallAction{Target: file.Path, Result: result})
	}
	return actions, nil
}

// removePackageFirewallConfigFile reverses a single config file, keyed on the
// mode configure used to write it.
func removePackageFirewallConfigFile(file pfw.ConfigFile, proxyHost string, dryRun bool) (string, error) {
	out, err := managedfile.RemoveFile(managedFile(file), pfwMarkers, proxyHost, dryRun)
	if err != nil {
		return "", err
	}
	if !out.Configured {
		// A structured file that exists but no longer points at the firewall was
		// replaced by the user; say so rather than claiming it was never set up.
		if out.Mode == managedfile.ModeStructured && out.Existed {
			return "not firewall-configured, skipped", nil
		}
		return "not configured", nil
	}
	switch {
	case out.Restored && dryRun:
		return "would restore from backup", nil
	case out.Restored:
		return "restored from backup", nil
	case out.Deleted && dryRun:
		return "would delete file", nil
	case out.Deleted:
		return "deleted file", nil
	case out.Mode == managedfile.ModeMerge && dryRun:
		return "would remove firewall keys", nil
	case out.Mode == managedfile.ModeMerge:
		return "removed firewall keys", nil
	case dryRun:
		return "would remove managed block", nil
	default:
		return "removed managed block", nil
	}
}

// stripMergeKeys removes the firewall keys folded into a merged config (paru.conf
// AurUrl/AurRpcUrl, yay config.json aururl/aurrpcurl), preserving everything else.
func stripMergeKeys(path, existing string) (string, bool) {
	if filepath.Base(path) == "config.json" { // yay
		m := map[string]json.RawMessage{}
		if err := json.Unmarshal([]byte(existing), &m); err != nil {
			return existing, false
		}
		_, a := m["aururl"]
		_, b := m["aurrpcurl"]
		if !a && !b {
			return existing, false
		}
		delete(m, "aururl")
		delete(m, "aurrpcurl")
		out, err := json.MarshalIndent(m, "", "\t")
		if err != nil {
			return existing, false
		}
		return string(out) + "\n", true
	}
	// paru.conf INI: drop AurUrl/AurRpcUrl within [options].
	lines := strings.Split(existing, "\n")
	var kept []string
	changed := false
	section := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = trimmed
			kept = append(kept, line)
			continue
		}
		if section == "[options]" && (iniLineHasKey(trimmed, "AurUrl") || iniLineHasKey(trimmed, "AurRpcUrl")) {
			changed = true
			continue
		}
		kept = append(kept, line)
	}
	if !changed {
		return existing, false
	}
	return strings.TrimRight(strings.Join(kept, "\n"), "\n") + "\n", true
}

func iniLineHasKey(line, key string) bool {
	line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
	return line == key || strings.HasPrefix(line, key+" ") || strings.HasPrefix(line, key+"=")
}

// uninstallGo reverses the Go setup: shell-rc managed block, project env files,
// and (on Windows) the persisted user environment variables.
func uninstallGo(dryRun bool) ([]packageFirewallAction, error) {
	if runtime.GOOS == "windows" {
		if dryRun {
			return []packageFirewallAction{
				{Target: "Windows user environment GOPROXY", Result: "would clear"},
				{Target: "Windows user environment GOAUTH", Result: "would clear"},
			}, nil
		}
		managedfile.ClearUserEnv(pfwEnvKeys)
		return []packageFirewallAction{
			{Target: "Windows user environment GOPROXY", Result: "cleared"},
			{Target: "Windows user environment GOAUTH", Result: "cleared"},
		}, nil
	}

	path, _, err := shellConfigPath()
	if err != nil {
		return nil, err
	}
	result, err := removeBlockFile(path, dryRun)
	if err != nil {
		return nil, err
	}
	actions := []packageFirewallAction{{Target: path, Result: result}}

	projActions, err := removeGoProjectEnv(dryRun)
	if err != nil {
		return nil, err
	}
	return append(actions, projActions...), nil
}

// removeBlockFile strips the Vulnetix managed block from a shell rc file. Unlike
// package-manager config files, a shell rc is never deleted even if left empty.
func removeBlockFile(path string, dryRun bool) (string, error) {
	found, err := managedfile.RemoveBlockFile(path, pfwMarkers, dryRun)
	if err != nil {
		return "", err
	}
	switch {
	case !found:
		return "not configured", nil
	case dryRun:
		return "would remove managed block", nil
	default:
		return "removed managed block", nil
	}
}

func removeGoProjectEnv(dryRun bool) ([]packageFirewallAction, error) {
	root, err := gitRoot()
	if err != nil {
		return nil, nil
	}
	var actions []packageFirewallAction
	for _, name := range []string{".env", ".envrc", "Makefile"} {
		path := filepath.Join(root, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		next, changed := removeGoEnvValues(string(data))
		if !changed {
			continue
		}
		if dryRun {
			actions = append(actions, packageFirewallAction{Target: path, Result: "would remove GOPROXY/GOAUTH"})
			continue
		}
		if err := os.WriteFile(path, []byte(next), 0600); err != nil {
			return nil, err
		}
		actions = append(actions, packageFirewallAction{Target: path, Result: "removed GOPROXY/GOAUTH"})
	}
	return actions, nil
}

// removeNetrcCredential removes the shared firewall machine entry from netrc.
func removeNetrcCredential(path, machine string, dryRun bool) (string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "not configured", nil
	}
	if err != nil {
		return "", err
	}
	existing := string(data)
	stripped := removeNetrcMachine(existing, machine)
	next := stripped
	if next != "" {
		next += "\n"
	}
	if next == existing {
		return "not configured", nil
	}
	if dryRun {
		return "would remove netrc credential", nil
	}
	if strings.TrimSpace(next) == "" {
		if err := os.Remove(path); err != nil {
			return "", err
		}
		return "removed netrc credential (file deleted)", nil
	}
	if err := os.WriteFile(path, []byte(next), 0600); err != nil {
		return "", err
	}
	return "removed netrc credential", nil
}

// configuredEcosystems lists ecosystems still pointing at the firewall that are
// NOT in the removed set (used to warn when the shared credential is dropped).
func configuredEcosystems(home, proxyHost string, removed []pfw.Ecosystem) []string {
	removedSet := map[string]bool{}
	for _, e := range removed {
		removedSet[e.ID] = true
	}
	var names []string
	for _, d := range pfw.Detect(home, proxyHost) {
		if d.Configured && !removedSet[d.Ecosystem.ID] {
			names = append(names, d.Ecosystem.Command)
		}
	}
	return names
}

func targetNames(targets []pfw.Ecosystem) string {
	if len(targets) == 0 {
		return "(none)"
	}
	names := make([]string, len(targets))
	for i, e := range targets {
		names[i] = e.Command
	}
	return strings.Join(names, ", ")
}

func credsLabel(remove bool) string {
	if remove {
		return "removing shared netrc entry"
	}
	return "kept (shared)"
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

	packageFirewallUninstallCmd.Flags().StringVar(&packageFirewallProxyURL, "proxy-url", packageFirewallDefaultProxy, "Package Firewall proxy URL (host to detect and strip)")
	packageFirewallUninstallCmd.Flags().BoolVar(&packageFirewallDryRun, "dry-run", false, "Show planned changes without writing files")
	packageFirewallUninstallCmd.Flags().BoolVar(&packageFirewallUninstallAll, "all", false, "Unconfigure every supported ecosystem")
	packageFirewallUninstallCmd.Flags().StringSliceVar(&packageFirewallUninstallExcept, "except", nil, "Unconfigure all supported ecosystems except these")
	packageFirewallUninstallCmd.Flags().BoolVar(&packageFirewallUninstallCreds, "remove-credentials", false, "Also remove the shared netrc credential (machine packages.vulnetix.com)")
	packageFirewallUninstallCmd.Flags().BoolVar(&packageFirewallUninstallPurge, "purge", false, "Remove the shared netrc credential and every supported ecosystem")
	packageFirewallCmd.AddCommand(packageFirewallUninstallCmd)

	rootCmd.AddCommand(packageFirewallCmd)
}

func addPackageFirewallFlags(cmd *cobra.Command, label string) {
	cmd.Flags().StringVar(&packageFirewallBaseURL, "base-url", vdb.DefaultBaseURL, "VDB API base URL")
	cmd.Flags().StringVar(&packageFirewallProxyURL, "proxy-url", packageFirewallDefaultProxy, "Package Firewall "+label+" proxy URL")
	cmd.Flags().BoolVar(&packageFirewallDryRun, "dry-run", false, "Show planned changes without writing files")
}
