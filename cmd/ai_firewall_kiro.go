package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/v3/internal/display"
	aifw "github.com/vulnetix/cli/v3/pkg/aifirewall"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/kiroauth"
	"github.com/vulnetix/cli/v3/pkg/tty"
)

// --- kiro ---

func newAiFirewallKiroCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kiro",
		Short: "Provision the Kiro sign-in the gateway uses",
		Long: `Kiro has no API key. The gateway signs in to Kiro on your organisation's
behalf with an AWS Builder ID or IAM Identity Center sign-in kept in the
secrets vault, and mints a short-lived Kiro access token from it for every
request. Clients only ever send their Vulnetix API key.`,
	}
	cmd.AddCommand(newAiFirewallKiroLoginCommand())
	return cmd
}

func newAiFirewallKiroLoginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to Kiro and store the sign-in in the secrets vault",
		Long: `Sign in to Kiro with an AWS Builder ID (the default) or an IAM Identity Center
start URL, and store the sign-in in the secrets vault as the kiro provider's
key, granted to the AI Firewall.

The sign-in registers its own AWS client, separate from the Kiro IDE's, so the
two never share a refresh token. --import reuses the sign-in the Kiro IDE or
kiro-cli already holds instead; GitHub and Google Kiro sign-ins cannot be used.

Run it again whenever requests are refused with vault_kiro_relogin: the vault
entry the AI Firewall uses is replaced with the new sign-in.`,
		Example: `  vulnetix ai-firewall kiro login
  vulnetix ai-firewall kiro login --start-url https://my-org.awsapps.com/start --region eu-central-1
  vulnetix ai-firewall kiro login --import
  vulnetix ai-firewall kiro login --owner 1b4e28ba-2fa1-11d2-883f-0016d3cca427 --expires-in-days 90`,
		Args: cobra.NoArgs,
		RunE: runAiFirewallKiroLogin,
	}
	cmd.Flags().String("start-url", "", "IAM Identity Center start URL (default: AWS Builder ID)")
	cmd.Flags().String("region", "", "AWS region of the sign-in (default us-east-1)")
	cmd.Flags().String("api-region", "", "Kiro API region (default: the profile's region, else the sign-in region)")
	cmd.Flags().String("profile-arn", "", "CodeWhisperer profile ARN to use (Identity Center)")
	cmd.Flags().Bool("import", false, "Reuse the Kiro IDE or kiro-cli sign-in instead of signing in")
	cmd.Flags().String("name", "kiro", "Name of the vault entry when one is created")
	cmd.Flags().StringSlice("owner", nil, "Only these API key owners (principal UUIDs) may use it; default every owner")
	cmd.Flags().Int("expires-in-days", 0, "Expire the vault entry after this many days (0: never)")
	cmd.Flags().Bool("no-browser", false, "Do not open a browser; print the sign-in URL only")
	addAiFirewallCommonFlags(cmd)
	return cmd
}

func runAiFirewallKiroLogin(cmd *cobra.Command, _ []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)
	creds, err := auth.LoadCredentials()
	if err != nil {
		return fmt.Errorf("authentication required: %w\nRun 'vulnetix auth login' to authenticate", err)
	}
	authz := auth.GetAuthHeader(creds)
	if !strings.HasPrefix(authz, "ApiKey ") {
		return fmt.Errorf("saving to the secrets vault needs an API key sign-in; run 'vulnetix auth login' with an API key")
	}

	startURL, _ := cmd.Flags().GetString("start-url")
	region, _ := cmd.Flags().GetString("region")
	apiRegion, _ := cmd.Flags().GetString("api-region")
	profileARN, _ := cmd.Flags().GetString("profile-arn")
	doImport, _ := cmd.Flags().GetBool("import")
	name, _ := cmd.Flags().GetString("name")
	owners, _ := cmd.Flags().GetStringSlice("owner")
	days, _ := cmd.Flags().GetInt("expires-in-days")
	noBrowser, _ := cmd.Flags().GetBool("no-browser")
	if days < 0 {
		return fmt.Errorf("--expires-in-days must not be negative")
	}

	bg := context.Background()
	var login kiroauth.Login
	if doImport {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		l, src, err := kiroauth.Import(home)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("no Kiro sign-in found (looked for %s); sign in to Kiro first, or run without --import", src)
			}
			return err
		}
		ctx.Logger.Warnf("Importing the sign-in from %s: the gateway and that tool will share one refresh token", src)
		login = l
		if apiRegion != "" {
			if !kiroauth.ValidRegion(apiRegion) {
				return fmt.Errorf("invalid Kiro API region %q", apiRegion)
			}
			login.APIRegion = apiRegion
		}
	} else {
		d := kiroauth.DeviceLogin{StartURL: startURL, Region: region, APIRegion: apiRegion}
		grant, err := d.Start(bg)
		if err != nil {
			return err
		}
		// The prompt goes to stderr so --output json keeps stdout clean.
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Sign in to Kiro with AWS")
		fmt.Fprintln(os.Stderr)
		opened := false
		if !noBrowser && tty.StderrIsTerminal() {
			opened = openBrowser(grant.BrowseURL()) == nil
		}
		if opened {
			fmt.Fprintln(os.Stderr, "Opened your browser. If it did not appear, open this URL:")
		} else {
			fmt.Fprintln(os.Stderr, "Open this URL in a browser:")
		}
		fmt.Fprintf(os.Stderr, "\n  %s\n\n", grant.BrowseURL())
		fmt.Fprintln(os.Stderr, "Verify this code matches the one shown in your browser:")
		fmt.Fprintf(os.Stderr, "\n  %s\n\n", grant.UserCode)
		fmt.Fprintln(os.Stderr, "Waiting for the sign-in to be approved...")
		login, err = d.Poll(bg, grant)
		if err != nil {
			return err
		}
	}

	login, profiles, err := kiroauth.ResolveProfile(bg, nil, login, profileARN, kiroauth.Endpoints{})
	if err != nil {
		if errors.Is(err, kiroauth.ErrReloginRequired) {
			return err
		}
		ctx.Logger.Warnf("Could not list Kiro profiles (%v); storing the sign-in without one", err)
	}
	if len(profiles) > 0 {
		p, err := chooseKiroProfile(profiles)
		if err != nil {
			return err
		}
		login = login.WithProfile(p)
	}

	vc := aifw.VaultClient{BaseURL: webBaseURL(), Authorization: authz}
	entry, created, err := saveKiroLogin(bg, vc, login, name, owners, days)
	if err != nil {
		return err
	}

	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(map[string]any{
			"provider":   aifw.KiroSlug,
			"entry":      entry,
			"created":    created,
			"region":     login.Region,
			"apiRegion":  login.APIRegionOrDefault(),
			"profileArn": login.ProfileARN,
		})
	}
	verb := "Replaced"
	if created {
		verb = "Stored"
	}
	t := ctx.Term
	ctx.Logger.Result(display.CheckMark(t) + " " + display.Success(t, verb+" the Kiro sign-in in the secrets vault"))
	pairs := []display.KVPair{
		{Key: "Entry", Value: entry.Name},
		{Key: "Version", Value: strconv.Itoa(entry.Version)},
		{Key: "Refresh token", Value: "…" + entry.Last4},
		{Key: "API region", Value: login.APIRegionOrDefault()},
	}
	if login.ProfileARN != "" {
		pairs = append(pairs, display.KVPair{Key: "Profile", Value: login.ProfileARN})
	}
	ctx.Logger.Result(display.KeyValue(t, pairs))
	ctx.Logger.Result("Point belai's kiro provider at the Vulnetix AI Firewall, or call " +
		aifw.DefaultGatewayURL + "/kiro/" + creds.OrgID + "/v1 with your Vulnetix API key.")
	return nil
}

// saveKiroLogin replaces the value of the vault entry that already serves Kiro
// to the AI firewall, so a fresh sign-in keeps its grants and history, or
// creates one.
func saveKiroLogin(ctx context.Context, vc aifw.VaultClient, login kiroauth.Login, name string, owners []string, days int) (aifw.VaultEntry, bool, error) {
	entries, err := vc.Entries(ctx)
	if err != nil {
		return aifw.VaultEntry{}, false, err
	}
	for _, e := range entries {
		if e.Kind == aifw.VaultKindProvider && e.Provider == aifw.KiroSlug && e.ServesFirewall() {
			out, err := vc.Replace(ctx, e.ID, login.Encode())
			return out, false, err
		}
	}
	grant := aifw.VaultGrant{Surface: aifw.VaultSurfaceFirewall, Effect: "allow", All: len(owners) == 0}
	for _, o := range owners {
		if o = strings.ToLower(strings.TrimSpace(o)); o != "" {
			grant.IDs = append(grant.IDs, o)
		}
	}
	in := aifw.VaultSave{
		Kind:     aifw.VaultKindProvider,
		Provider: aifw.KiroSlug,
		Name:     name,
		Value:    login.Encode(),
		Grants:   []aifw.VaultGrant{grant},
	}
	if days > 0 {
		in.ExpiresAt = time.Now().Add(time.Duration(days) * 24 * time.Hour).UnixMilli()
	}
	out, err := vc.Create(ctx, in)
	return out, true, err
}

// chooseKiroProfile asks which profile to use when the account has several. It
// will not guess: without a terminal to ask on, the choices are listed and
// --profile-arn picks one.
func chooseKiroProfile(profiles []kiroauth.Profile) (kiroauth.Profile, error) {
	if !tty.StderrIsTerminal() {
		var b strings.Builder
		b.WriteString("this account has several Kiro profiles; choose one with --profile-arn:")
		for _, p := range profiles {
			fmt.Fprintf(&b, "\n  %s  %s", p.ARN, p.Name)
		}
		return kiroauth.Profile{}, errors.New(b.String())
	}
	fmt.Fprintln(os.Stderr, "\nThis account has several Kiro profiles:")
	for i, p := range profiles {
		fmt.Fprintf(os.Stderr, "  %d) %s  %s\n", i+1, p.Name, p.ARN)
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprintf(os.Stderr, "Profile [1-%d]: ", len(profiles))
		line, err := reader.ReadString('\n')
		if n, convErr := strconv.Atoi(strings.TrimSpace(line)); convErr == nil && n >= 1 && n <= len(profiles) {
			return profiles[n-1], nil
		}
		if err != nil {
			return kiroauth.Profile{}, errors.New("no profile chosen; pass --profile-arn")
		}
	}
}
