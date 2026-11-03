package cmd

// `vulnetix surface liveness` — check that the organisation's registered routes,
// operations and hosts still answer, from inside the customer network.
//
// The command runs on the customer's own infrastructure, so it may reach
// internal hosts Vulnetix's own checker never would. It reads the targets from
// the attack surface, sends only safe requests (GET or HEAD, or OPTIONS for a
// method that is not idempotent), with no credentials and no request body, and
// reports what answered. The verdicts are the server's; this only observes.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Vulnetix/vdb-openapi/route"
	"github.com/vulnetix/cli/v4/pkg/auth"
	"github.com/vulnetix/cli/v4/pkg/vdb"
)

var surfaceCmd = &cobra.Command{
	Use:   "surface",
	Short: "Check and report on your external attack surface",
}

var surfaceLivenessCmd = &cobra.Command{
	Use:   "liveness",
	Short: "Check that registered routes and hosts still answer, from inside your network",
	RunE:  runSurfaceLiveness,
}

func init() {
	surfaceLivenessCmd.Flags().String("repo", "", "limit the check to one repository (owner/name)")
	surfaceLivenessCmd.Flags().String("scheme", "https", "scheme to reach hosts with")
	surfaceCmd.AddCommand(surfaceLivenessCmd)
	rootCmd.AddCommand(surfaceCmd)
}

func runSurfaceLiveness(cmd *cobra.Command, _ []string) error {
	creds, err := auth.LoadCredentials()
	if err != nil || creds == nil || auth.IsCommunity(creds) {
		return fmt.Errorf("liveness needs a signed-in organisation; run 'vulnetix auth login'")
	}
	repo, _ := cmd.Flags().GetString("repo")
	scheme, _ := cmd.Flags().GetString("scheme")
	env := envForCli()

	client := vdb.NewClientFromCredentials(creds)
	client.APIVersion = "/v2"
	client.HTTPClient.Timeout = 60 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	targetsResp, err := client.CliSurfaceTargets(ctx, env, repo)
	if err != nil {
		return fmt.Errorf("read targets: %w", err)
	}
	targets := targetsResp.Data.Targets
	if len(targets) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No registered routes or hosts to check.")
		return nil
	}

	// A plain client with no redirect following and no stored credentials: a
	// liveness check reports what the endpoint itself answers, not where it
	// would send us.
	probe := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}

	obs := make([]vdb.CliSurfaceObservation, 0, len(targets))
	for _, t := range targets {
		if t.Host == "" {
			continue
		}
		url, method, ok := livenessRequest(scheme, t)
		if !ok {
			continue
		}
		start := time.Now()
		o := vdb.CliSurfaceObservation{
			Host: t.Host, Method: method, PathTemplate: t.PathTemplate,
			ObservedBy: "cli_liveness", At: time.Now().UnixMilli(),
		}
		req, reqErr := http.NewRequestWithContext(ctx, method, url, nil)
		if reqErr != nil {
			continue
		}
		req.Header.Set("User-Agent", "Vulnetix-CLI-Liveness/1")
		resp, doErr := probe.Do(req)
		o.LatencyMs = int(time.Since(start).Milliseconds())
		if doErr != nil {
			o.Status = 0 // unreachable
		} else {
			o.Status = resp.StatusCode
			o.AuthChallenge = resp.Header.Get("WWW-Authenticate")
			resp.Body.Close()
		}
		obs = append(obs, o)
	}

	if len(obs) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "Nothing checkable (no fillable paths).")
		return nil
	}
	if _, err := client.CliSurfaceObservations(ctx, env, vdb.CliSurfaceObservationsRequest{Observations: obs}); err != nil {
		return fmt.Errorf("report observations: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Checked and reported %d endpoint%s.\n", len(obs), plural1(len(obs)))
	return nil
}

// livenessRequest builds the concrete URL and safe method for a target. A route
// or operation path with a {param} is filled with a neutral placeholder; a
// method that is not idempotent is checked with OPTIONS, never sent for real.
func livenessRequest(scheme string, t vdb.CliSurfaceTarget) (url, method string, ok bool) {
	path := "/"
	if t.PathTemplate != "" {
		path = strings.ReplaceAll(t.PathTemplate, route.Param, "1")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	method = strings.ToUpper(strings.TrimSpace(t.Method))
	switch method {
	case "", "GET", "ANY":
		method = "GET"
	case "HEAD", "OPTIONS":
		// keep
	default:
		// POST, PUT, PATCH, DELETE: never sent for real; ask with OPTIONS.
		method = "OPTIONS"
	}
	return scheme + "://" + t.Host + path, method, true
}

func plural1(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
