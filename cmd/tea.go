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
    products    list products a server publishes
    product     read one product and its releases
    collection  read the artifacts published for a release
    resolve     resolve a TEI to the object it names

    publish       create products, releases, collections and artifacts
    distribution  declare where a release can actually be obtained
    share         control who may read a published object
    release       publish everything about a release in one command

Reading a public catalogue needs no credentials. Publishing does, and always
targets your own organisation's server.`,
	}

	cmd.PersistentFlags().String("server", tea.DefaultServer,
		"TEA server root URL (a supplier's server works for every read)")
	cmd.PersistentFlags().Bool("json", false, "emit raw JSON rather than a table")

	cmd.AddCommand(
		newTeaDiscoverCommand(),
		newTeaProductsCommand(),
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
func teaClient(cmd *cobra.Command) *tea.Client {
	server, _ := cmd.Flags().GetString("server")
	creds, err := auth.LoadCredentials()
	if err != nil {
		creds = nil
	}
	return tea.New(server, creds)
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

func newTeaProductsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "products",
		Short: "List the products a TEA server publishes",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()

			limit, _ := cmd.Flags().GetInt("limit")
			page, err := teaClient(cmd).Products(ctx, limit, "")
			if err != nil {
				return teaFail(err)
			}
			if teaJSONFlag(cmd) {
				return teaPrintJSON(page)
			}
			for _, p := range page.Results {
				fmt.Printf("%s  %s\n", p.UUID, p.Name)
			}
			if page.HasNext {
				fmt.Fprintf(os.Stderr, "\n(more available; raise --limit or page with the API)\n")
			}
			return nil
		},
	}
	cmd.Flags().Int("limit", 50, "how many products to list")
	return cmd
}

func newTeaProductCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "product <uuid>",
		Short: "Read a product and its releases",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()

			c := teaClient(cmd)
			product, err := c.Product(ctx, args[0])
			if err != nil {
				return teaFail(err)
			}
			releases, err := c.ProductReleases(ctx, args[0])
			if err != nil {
				return teaFail(err)
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

			col, err := teaClient(cmd).LatestCollection(ctx, args[0])
			if err != nil {
				return teaFail(err)
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

			out, err := teaClient(cmd).ResolveTEI(ctx, args[0])
			if err != nil {
				return teaFail(err)
			}
			return teaPrintJSON(out)
		},
	}
}
