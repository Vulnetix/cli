package cmd

// Publication commands, and the one-shot `tea release` a pipeline calls.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/pkg/tea"
)

func newTeaPublishCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Create products, releases, collections and artifacts",
		Long: `Publish objects to your organisation's transparency log.

The object graph is not incidental: a product holds releases, a release has
exactly one collection, and a collection holds the artifacts. Each command
below takes the parent it belongs to.

For a release that has just been cut, ` + "`tea release`" + ` does all of this in one
command instead.`,
	}
	cmd.AddCommand(
		newTeaPublishProductCommand(),
		newTeaPublishReleaseCommand(),
		newTeaPublishCollectionCommand(),
		newTeaPublishArtifactCommand(),
		newTeaPublicationsCommand(),
	)
	return cmd
}

func newTeaPublishProductCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "product <name>",
		Short: "Register a product",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()

			purl, _ := cmd.Flags().GetString("purl")
			var ids []tea.Identifier
			if purl != "" {
				ids = append(ids, tea.Identifier{IDType: "PURL", IDValue: purl})
			}

			// Keyed on the name, so re-running the same publish is a no-op
			// rather than a second product. A pipeline that retries after a
			// timeout must not leave a duplicate for a consumer to find.
			p, err := teaClient(cmd).CreateProduct(ctx, args[0], ids, "cli-product-"+args[0])
			if err != nil {
				return teaFail(err)
			}
			if teaJSONFlag(cmd) {
				return teaPrintJSON(p)
			}
			fmt.Printf("%s  %s\n", p.UUID, p.Name)
			fmt.Fprintln(os.Stderr, "\nPrivate until you say otherwise: vulnetix tea share "+p.UUID+" --visibility public")
			return nil
		},
	}
	cmd.Flags().String("purl", "", "Package URL identifying the product")
	return cmd
}

func newTeaPublishReleaseCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "release <product-uuid> <version>",
		Short: "Publish a release of a product",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()

			date, _ := cmd.Flags().GetString("date")
			pre, _ := cmd.Flags().GetBool("pre-release")

			r, err := teaClient(cmd).CreateProductRelease(ctx, args[0], args[1], date, pre,
				"cli-release-"+args[0]+"-"+args[1])
			if err != nil {
				return teaFail(err)
			}
			if teaJSONFlag(cmd) {
				return teaPrintJSON(r)
			}
			fmt.Printf("%s  %s\n", r.UUID, args[1])
			return nil
		},
	}
	cmd.Flags().String("date", "", "release date (RFC3339); defaults to now")
	cmd.Flags().Bool("pre-release", false, "mark the release as a pre-release")
	return cmd
}

func newTeaPublishCollectionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "collection <release-uuid>",
		Short: "Publish the next collection version for a release",
		Long: `Publish a new version of a release's collection.

An update reason is required by the server. A collection whose contents change
without saying why is indistinguishable, to a consumer, from one that was
tampered with.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()

			reason, _ := cmd.Flags().GetString("reason")
			comment, _ := cmd.Flags().GetString("comment")

			col, err := teaClient(cmd).PublishCollection(ctx, args[0],
				tea.UpdateReason{Type: reason, Comment: comment})
			if err != nil {
				return teaFail(err)
			}
			if teaJSONFlag(cmd) {
				return teaPrintJSON(col)
			}
			fmt.Printf("collection v%d\n", col.Version)
			return nil
		},
	}
	cmd.Flags().String("reason", "INITIAL_RELEASE",
		"why this version was published (INITIAL_RELEASE, ARTIFACT_ADDED, ARTIFACT_UPDATED, VEX_UPDATED, ARTIFACT_REMOVED)")
	cmd.Flags().String("comment", "", "free-text note recorded with the reason")
	return cmd
}

func newTeaPublishArtifactCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "artifact <collection-uuid> <file>",
		Short: "Publish an artifact and upload its content",
		Long: `Register an artifact in a collection and upload its bytes.

The file's SHA-256 is computed locally and sent as Content-Digest. The server
verifies it before storing anything, so a truncated upload fails loudly rather
than being published under a checksum saying it arrived intact.

The name, media type and artifact type are derived from the file unless given.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()

			collection, path := args[0], args[1]
			name, _ := cmd.Flags().GetString("name")
			mediaType, _ := cmd.Flags().GetString("media-type")
			artifactType, _ := cmd.Flags().GetString("type")

			if name == "" {
				name = filepath.Base(path)
			}
			if mediaType == "" {
				mediaType = tea.MediaTypeForFile(path)
			}
			if artifactType == "" {
				artifactType = tea.ArtifactTypeForFile(path)
			}

			c := teaClient(cmd)
			art, err := c.CreateArtifact(ctx, collection, name, artifactType,
				[]tea.Format{{MediaType: mediaType}}, "cli-artifact-"+collection+"-"+name)
			if err != nil {
				return teaFail(err)
			}
			res, err := c.UploadArtifactFile(ctx, art.UUID, 0, path, mediaType)
			if err != nil {
				return teaFail(err)
			}
			if teaJSONFlag(cmd) {
				return teaPrintJSON(res)
			}
			fmt.Printf("%s  %s  [%s]\n", art.UUID, name, artifactType)
			return nil
		},
	}
	cmd.Flags().String("name", "", "artifact name; defaults to the file name")
	cmd.Flags().String("media-type", "", "media type; derived from the file when omitted")
	cmd.Flags().String("type", "", "TEA artifact type; derived from the file when omitted")
	return cmd
}

func newTeaPublicationsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List what your organisation has published, and who can read it",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()

			products, err := teaClient(cmd).Publications(ctx)
			if err != nil {
				return teaFail(err)
			}
			if teaJSONFlag(cmd) {
				return teaPrintJSON(products)
			}
			for _, p := range products {
				fmt.Printf("%-38v %-10v %v releases  %v\n",
					p["uuid"], p["visibility"], p["releases"], p["name"])
			}
			return nil
		},
	}
}

// ── Sharing ─────────────────────────────────────────────────────────────────

func newTeaShareCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "share <uuid>",
		Short: "Show or change who may read a published object",
		Long: `Read or set an object's access policy.

With no flags this reports the policy in force, including what the object
inherits and from where — the difference between what an object declares and
what it effectively has is where accidental disclosure hides.

  --visibility private   only your organisation
  --visibility shared    plus the organisations named with --org
  --visibility public    anyone, unauthenticated

Public cannot be undone. Setting an object back to private later stops new
readers; it does not recall anything already fetched.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := teaContext(cmd)
			defer cancel()

			c := teaClient(cmd)
			visibility, _ := cmd.Flags().GetString("visibility")

			if visibility == "" {
				status, err := c.AccessPolicy(ctx, args[0])
				if err != nil {
					return teaFail(err)
				}
				if teaJSONFlag(cmd) {
					return teaPrintJSON(status)
				}
				fmt.Printf("effective  %s\n", status.Effective.Visibility)
				if status.Declared == nil {
					where := status.InheritedFrom
					if where == "" {
						where = "the default"
					}
					fmt.Printf("declared   nothing — inherited from %s\n", where)
				} else {
					fmt.Printf("declared   %s\n", status.Declared.Visibility)
				}
				for _, g := range status.Effective.SharedWith {
					fmt.Printf("shared     %s %s\n", g.OrganizationUUID, g.OrganizationName)
				}
				return nil
			}

			orgs, _ := cmd.Flags().GetStringSlice("org")
			if visibility == "shared" && len(orgs) == 0 {
				return fmt.Errorf("--visibility shared needs at least one --org: " +
					"a shared policy with nobody named says one thing and does another")
			}
			grants := make([]tea.ShareGrant, 0, len(orgs))
			for _, o := range orgs {
				grants = append(grants, tea.ShareGrant{OrganizationUUID: strings.TrimSpace(o)})
			}

			status, err := c.SetAccessPolicy(ctx, args[0], tea.AccessPolicy{
				Visibility: visibility,
				SharedWith: grants,
			})
			if err != nil {
				return teaFail(err)
			}
			if teaJSONFlag(cmd) {
				return teaPrintJSON(status)
			}
			fmt.Printf("effective  %s\n", status.Effective.Visibility)
			return nil
		},
	}
	cmd.Flags().String("visibility", "", "private, shared or public; omit to read the current policy")
	cmd.Flags().StringSlice("org", nil, "organisation UUID to share with (repeatable)")
	return cmd
}
