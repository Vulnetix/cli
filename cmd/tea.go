package cmd

// The `tea` command group speaks the OWASP Transparency Exchange API.
//
// Two halves of one API. The consumption operations read any conformant
// server — ours or a supplier's — and the publication operations create the
// objects those consumers read. They live under one command because they are
// one API at one root; splitting them would mean telling the CLI twice which
// server it is talking to.
//
// `tea release` is the reason most of this exists: after a GitHub release
// finishes, one command should publish everything about it. Doing that by hand
// is five API calls in a fixed order, and a release pipeline that gets the
// order wrong publishes a collection with no artifacts in it.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/tea"
)

func newTeaCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tea",
		Short: "Publish to and read from the Transparency Exchange API",
		Long: `Work with the OWASP Transparency Exchange API (TEA).

TEA turns transparency data from something you email to something a consumer
resolves: they start from one identifier, follow DNS to a discovery document,
and walk a standard object graph to the exact artifact they need.

    discover    resolve a domain or TEI to a TEA server
    products    list or search the products a server publishes
    components  list or search the components a server publishes
    product     read one product and its releases
    collection  read the artifacts published for a release
    resolve     resolve a TEI to the object it names

    publish       create products, releases, collections and artifacts
    distribution  declare where a release can actually be obtained
    share         control who may read a published object
    release       publish everything about a release in one command

Two catalogues are built in. The default, first-party, is Vulnetix's own
server: it lists the public records without any login. The public catalogue
(--catalogue public) is the open source one, the most starred GitHub projects.
It needs a credential, and when you are not logged in the CLI uses the shared
community credential, so no login is needed to read it.

Publishing needs your own credentials and always targets your own
organisation's server.`,
	}

	cmd.PersistentFlags().String("server", tea.DefaultServer,
		"TEA server root URL (a supplier's server works for every read)")
	cmd.PersistentFlags().String("catalogue", tea.CatalogueFirstParty,
		"which built-in catalogue to read: "+strings.Join(tea.Catalogues, " or ")+" (not combinable with --server)")
	cmd.PersistentFlags().Bool("json", false, "emit raw JSON rather than a table")

	cmd.AddCommand(
		newTeaDiscoverCommand(),
		newTeaProductsCommand(),
		newTeaComponentsCommand(),
		newTeaProductCommand(),
		newTeaCollectionCommand(),
		newTeaResolveCommand(),
		newTeaPublishCommand(),
		newTeaDistributionCommand(),
		newTeaShareCommand(),
		newTeaReleaseCommand(),
	)
	return cmd
}

func init() {
	rootCmd.AddCommand(newTeaCommand())
}

// teaClient builds a client for the selected server.
//
// Credentials are optional and their absence is not an error: a public
// catalogue is readable without them, and refusing to run would make the CLI
// useless for reading somebody else's open transparency log. A write against a
// server that does not know the caller is refused by that server, which is the
// right place for that decision.
//
// This is the client for writes, and for the reads that predate catalogues. It
// honours --server and refuses --catalogue public, which is read only, and it
// never falls back to the community credential: a write must be attributable to
// the person who made it.
func teaClient(cmd *cobra.Command) *tea.Client {
	sel, err := teaSelect(cmd, false)
	if err != nil {
		return &tea.Client{Err: err}
	}
	if sel.Public && catalogueFlag(cmd) == tea.CataloguePublic {
		return &tea.Client{Err: fmt.Errorf("--catalogue public is read only: " +
			"publishing targets your own organisation's server")}
	}
	return teaNewClient(sel)
}

// teaVerbose reports whether diagnostics were asked for. A variable so a test
// can set it without depending on how the root command parses -v.
var teaVerbose = func() bool { return verbose && !silent }

// teaTransport, when set, carries every tea request. Production leaves it nil;
// the tests use it to reach the fixed public root URL without the network.
var teaTransport http.RoundTripper

func teaNewClient(sel *teaSelection) *tea.Client {
	c := tea.New(sel.Server, sel.Creds)
	if teaTransport != nil {
		c.HTTP.Transport = teaTransport
	}
	return c
}

// teaReadClient builds a client for a read command. On the public catalogue root
// it falls back to the community credential when nothing is stored.
func teaReadClient(cmd *cobra.Command) (*tea.Client, error) {
	sel, err := teaSelect(cmd, true)
	if err != nil {
		return nil, err
	}
	if sel.Source == teaCredCommunity && teaVerbose() {
		fmt.Fprintln(os.Stderr, "tea: using the community credential")
	}
	return teaNewClient(sel), nil
}

// Where the credential a tea request carries came from.
const (
	teaCredNone      = "none"
	teaCredStored    = "stored"
	teaCredCommunity = "community"
)

// teaSelection is the resolved target of one tea invocation.
type teaSelection struct {
	Server string
	// Public is true when Server is the open source catalogue root.
	Public bool
	Creds  *auth.Credentials
	Source string
}

func catalogueFlag(cmd *cobra.Command) string {
	v, _ := cmd.Flags().GetString("catalogue")
	return strings.ToLower(strings.TrimSpace(v))
}

// teaSelect works out which root a command reads and which credential it sends.
//
// Stored credentials always win. The community credential is added only for the
// open source catalogue root: the same key sent to the first party root does not
// give the anonymous public view, it returns the community organisation's own
// catalogue, which is a different set of objects. The first party root and any
// custom --server therefore never see it.
func teaSelect(cmd *cobra.Command, allowCommunity bool) (*teaSelection, error) {
	serverFlag := cmd.Flags().Lookup("server")
	catalogueFl := cmd.Flags().Lookup("catalogue")
	serverSet := serverFlag != nil && serverFlag.Changed
	catalogueSet := catalogueFl != nil && catalogueFl.Changed

	if serverSet && catalogueSet {
		return nil, fmt.Errorf("use either --server or --catalogue, not both: " +
			"--server names a root URL and --catalogue names one of the built-in roots")
	}

	server := tea.DefaultServer
	if serverFlag != nil {
		server = serverFlag.Value.String()
	}
	if catalogueSet {
		root, err := tea.ServerForCatalogue(catalogueFl.Value.String())
		if err != nil {
			return nil, err
		}
		server = root
	}
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	if server == "" {
		server = tea.DefaultServer
	}

	sel := &teaSelection{Server: server, Public: tea.IsPublicServer(server), Source: teaCredNone}
	if creds, err := auth.LoadCredentials(); err == nil && creds != nil {
		sel.Creds, sel.Source = creds, teaCredStored
	} else if allowCommunity && sel.Public {
		sel.Creds, sel.Source = auth.CommunityCredentials(), teaCredCommunity
	}
	return sel, nil
}

func teaJSONFlag(cmd *cobra.Command) bool {
	v, _ := cmd.Flags().GetBool("json")
	return v
}

func teaPrintJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// teaFail reports a TEA error in the terms the API used.
//
// The codes are the interface a pipeline branches on, so they are printed
// rather than flattened into prose — and ACCESS_WIDENS_PARENT in particular
// refers to an object the user may not be looking at, so it says which.
func teaFail(err error) error {
	var apiErr *tea.Error
	if ok := asTeaError(err, &apiErr); !ok {
		return err
	}
	if apiErr.Status == http.StatusUnauthorized {
		return fmt.Errorf("%w\n\nThe server requires valid credentials. "+
			"Run `vulnetix auth login`, or set VULNETIX_API_KEY and VULNETIX_ORG_ID", err)
	}
	switch apiErr.Code {
	case "ACCESS_WIDENS_PARENT":
		return fmt.Errorf("%w\n\nAn object cannot be more visible than the one it belongs to. "+
			"Loosen the parent first, or leave this object to inherit it", err)
	case "FORBIDDEN":
		return fmt.Errorf("%w\n\nPublishing requires a Pro plan and an API key for the publishing organisation", err)
	case "CHECKSUM_MISMATCH":
		return fmt.Errorf("%w\n\nThe uploaded bytes did not match their digest — the transfer was truncated or the file changed mid-upload", err)
	}
	return err
}

// teaFailFor is teaFail with the context of the invocation, so a 401 can say
// what was sent and to which root. The answer differs: the public catalogue
// rejects a stored key that has gone stale, and a server that was sent nothing
// simply requires credentials.
func teaFailFor(cmd *cobra.Command, err error) error {
	var apiErr *tea.Error
	if !asTeaError(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		return teaFail(err)
	}
	sel, selErr := teaSelect(cmd, true)
	if selErr != nil {
		return teaFail(err)
	}
	switch {
	case sel.Public && sel.Source == teaCredStored:
		return fmt.Errorf("%w\n\nThe public catalogue rejected your API key. "+
			"Run `vulnetix auth login` to sign in again", err)
	case sel.Public && sel.Source == teaCredCommunity:
		return fmt.Errorf("%w\n\nThe public catalogue rejected the built-in community credential. "+
			"Run `vulnetix auth login` to use your own", err)
	case sel.Source == teaCredStored:
		return fmt.Errorf("%w\n\n%s rejected your credentials. "+
			"Run `vulnetix auth login` to sign in again", err, sel.Server)
	default:
		return fmt.Errorf("%w\n\n%s requires credentials and none were found. "+
			"Run `vulnetix auth login`, or set VULNETIX_API_KEY and VULNETIX_ORG_ID", err, sel.Server)
	}
}

func asTeaError(err error, out **tea.Error) bool {
	for e := err; e != nil; {
		if te, ok := e.(*tea.Error); ok {
			*out = te
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

func teaContext(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	// cmd.Context() is only non-nil once cobra's Execute() has run; it backfills
	// context.Background() itself. Called directly, as tests that build a command
	// with newTeaReleaseCommand() and never execute it do, it is nil, and
	// context.WithTimeout on a nil parent panics rather than erroring.
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, 10*time.Minute)
}

// ── Consumption ─────────────────────────────────────────────────────────────

func newTeaDiscoverCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "discover <domain|url|tei>",
		Short: "Resolve a domain or TEI to a TEA server",
		Long: `Follow the specification's discovery sequence: read the domain out of what
you supply, fetch https://<domain>/.well-known/tea, and report the endpoints it
advertises along with the root a client should use.

Accepts a bare domain, a URL, or a TEI — the three forms anyone actually has to
hand.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()

			doc, wellKnown, err := tea.Discover(ctx, args[0])
			if err != nil {
				return err
			}
			root := tea.RootFrom(doc)

			if teaJSONFlag(cmd) {
				return teaPrintJSON(map[string]any{
					"wellKnownUrl": wellKnown,
					"endpoints":    doc.Endpoints,
					"root":         root,
				})
			}
			fmt.Printf("discovery  %s\n", wellKnown)
			for _, e := range doc.Endpoints {
				fmt.Printf("endpoint   %s  versions %s\n", e.URL, strings.Join(e.Versions, ", "))
			}
			fmt.Printf("root       %s\n", root)
			return nil
		},
	}
}

// products and components live in tea_search.go.

func newTeaProductCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "product <uuid>",
		Short: "Read a product and its releases",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()

			c, err := teaReadClient(cmd)
			if err != nil {
				return err
			}
			product, err := c.Product(ctx, args[0])
			if err != nil {
				return teaFailFor(cmd, err)
			}
			releases, err := c.ProductReleases(ctx, args[0])
			if err != nil {
				return teaFailFor(cmd, err)
			}
			if teaJSONFlag(cmd) {
				return teaPrintJSON(map[string]any{"product": product, "releases": releases.Results})
			}
			fmt.Printf("%s\n", product.Name)
			for _, id := range product.Identifiers {
				fmt.Printf("  %-5s %s\n", id.IDType, id.IDValue)
			}
			fmt.Printf("\nreleases (%d)\n", len(releases.Results))
			for _, r := range releases.Results {
				pre := ""
				if r.PreRelease {
					pre = "  (pre-release)"
				}
				fmt.Printf("  %-24s %s%s\n", r.Version, r.UUID, pre)
			}
			return nil
		},
	}
}

func newTeaCollectionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "collection <release-uuid>",
		Short: "Read the artifacts published for a release",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()

			c, err := teaReadClient(cmd)
			if err != nil {
				return err
			}
			col, err := c.LatestCollection(ctx, args[0])
			if err != nil {
				return teaFailFor(cmd, err)
			}
			if teaJSONFlag(cmd) {
				return teaPrintJSON(col)
			}
			reason := ""
			if col.UpdateReason != nil {
				reason = col.UpdateReason.Type
			}
			fmt.Printf("collection v%d  %s\n", col.Version, reason)
			for _, a := range col.Artifacts {
				fmt.Printf("\n  %s  [%s]\n", a.Name, a.Type)
				for _, f := range a.Formats {
					fmt.Printf("    %s\n", f.MediaType)
					if f.URL != "" {
						fmt.Printf("      url       %s\n", f.URL)
					}
					if f.SignatureURL != "" {
						fmt.Printf("      signature %s\n", f.SignatureURL)
					}
					for _, s := range f.Checksums {
						fmt.Printf("      %-9s %s\n", s.AlgType, s.AlgValue)
					}
				}
			}
			return nil
		},
	}
}

func newTeaResolveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "resolve <tei>",
		Short: "Resolve a TEI to the object it names",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()

			c, err := teaReadClient(cmd)
			if err != nil {
				return err
			}
			out, err := c.ResolveTEI(ctx, args[0])
			if err != nil {
				return teaFailFor(cmd, err)
			}
			if teaJSONFlag(cmd) {
				return teaPrintJSON(out)
			}
			if len(out) == 0 {
				fmt.Println("no server resolves that identifier")
				return nil
			}
			for _, d := range out {
				fmt.Printf("release    %s\n", d.ProductReleaseUUID)
				for _, s := range d.Servers {
					fmt.Printf("  server   %s  versions %s\n", s.RootURL, strings.Join(s.Versions, ", "))
				}
			}
			return nil
		},
	}
}
