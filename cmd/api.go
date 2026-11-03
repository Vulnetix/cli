package cmd

// `vulnetix api` — find an organisation's OpenAPI and Swagger descriptions and
// upload them for the attack surface feature (AESM).
//
//	vulnetix api discover [path]   find spec files in a working tree and upload them
//	vulnetix api upload <file>     upload one spec file
//
// Finding specs in files needs no network. The command never sends a request
// to a host; it reads files and uploads what it found to /v2/cli.api-specs,
// where the server re-reads each document through the shared vdb-openapi
// module. The spec inventory then appears on /resolve/api-specs and its routes
// correlate on finding pages.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/v4/internal/apispecs"
	"github.com/vulnetix/cli/v4/pkg/auth"
	"github.com/vulnetix/cli/v4/pkg/vdb"
)

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Find and upload OpenAPI and Swagger descriptions",
	Long:  "Discover the OpenAPI and Swagger descriptions in a repository and upload them so Vulnetix can inventory your API surface and correlate it with findings.",
}

var apiDiscoverCmd = &cobra.Command{
	Use:   "discover [path]",
	Short: "Find spec files in a working tree and upload them",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runAPIDiscover,
}

var apiUploadCmd = &cobra.Command{
	Use:   "upload <file>",
	Short: "Upload one OpenAPI or Swagger file",
	Args:  cobra.ExactArgs(1),
	RunE:  runAPIUpload,
}

func init() {
	apiDiscoverCmd.Flags().Bool("no-upload", false, "find and print the specs without uploading them")
	apiCmd.AddCommand(apiDiscoverCmd)
	apiCmd.AddCommand(apiUploadCmd)
	rootCmd.AddCommand(apiCmd)
}

func runAPIDiscover(cmd *cobra.Command, args []string) error {
	root := "."
	if len(args) == 1 {
		root = args[0]
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	found, err := apispecs.Discover(abs)
	if err != nil {
		return fmt.Errorf("discover specs: %w", err)
	}
	if len(found) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No OpenAPI or Swagger descriptions found.")
		return nil
	}
	for _, f := range found {
		fmt.Fprintln(cmd.OutOrStdout(), apispecs.Summary(f))
	}
	noUpload, _ := cmd.Flags().GetBool("no-upload")
	if noUpload {
		return nil
	}
	return uploadSpecs(cmd, found)
}

func runAPIUpload(cmd *cobra.Command, args []string) error {
	path := args[0]
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return uploadSpecs(cmd, []apispecs.Found{{Path: filepath.Base(path), Raw: data}})
}

// uploadSpecs sends the found specs to /v2/cli.api-specs under the caller's
// credentials. Community credentials cannot upload: the feature needs a
// signed-in organisation.
func uploadSpecs(cmd *cobra.Command, found []apispecs.Found) error {
	creds, err := auth.LoadCredentials()
	if err != nil || creds == nil || auth.IsCommunity(creds) {
		return fmt.Errorf("uploading API specs needs a signed-in organisation; run 'vulnetix auth login'")
	}
	env := envForCli()
	req := vdb.CliApiSpecsRequest{Specs: make([]vdb.CliApiSpec, 0, len(found))}
	if env.Git != nil {
		req.CommitSha = env.Git.Commit
	}
	for _, f := range found {
		req.Specs = append(req.Specs, vdb.CliApiSpec{Path: f.Path, Content: string(f.Raw)})
	}
	client := vdb.NewClientFromCredentials(creds)
	client.APIVersion = "/v2"
	client.HTTPClient.Timeout = 120 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	resp, err := client.CliApiSpecs(ctx, env, req)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	if resp != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Uploaded %d, rejected %d.\n", resp.Data.Accepted, resp.Data.Rejected)
	}
	return nil
}
