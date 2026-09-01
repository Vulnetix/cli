package lsp

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// Retry policy for a batch that fails transiently.
//
// The halving is the important half. A gateway timeout on a batch is usually
// about how much work the batch asked for rather than about the service being
// down, so repeating the same request at the same size mostly reproduces the
// same timeout. Splitting it turns one failure into two smaller questions, and
// a workspace with a hundred dependencies degrades into slower answers rather
// than no answer.
const (
	scaMinChunkSize   = 4
	scaMaxRetryRounds = 3
	scaBackoffBase    = 500 * time.Millisecond
	scaBackoffMax     = 4 * time.Second
)

// scaBatchResult is one successful batch response.
type scaBatchResult struct {
	Components []any
	Vulns      []any
	Insights   []vdb.CliPackageInsight
	Meta       vdb.CliResponseMeta
}

// sendBatches issues the cli.sca requests for a purl set, halving and retrying
// any batch that fails transiently.
//
// Returns whatever succeeded plus the first error, rather than failing the
// whole pass on one bad batch: a partial dependency picture is worth showing,
// and the alternative is an empty Problems panel that reads as a clean repo.
// The caller decides what to do when nothing at all came back.
func (e *scaEngine) sendBatches(
	ctx context.Context,
	client *vdb.Client,
	purls []string,
	opts vdb.CliSCAOptions,
) ([]scaBatchResult, error) {
	type pending struct {
		purls []string
		round int
	}

	queue := make([]pending, 0, 4)
	for _, chunk := range chunkStrings(purls, scaChunkSize) {
		queue = append(queue, pending{purls: chunk})
	}

	var results []scaBatchResult
	var firstErr error

	for len(queue) > 0 {
		job := queue[0]
		queue = queue[1:]

		if ctx.Err() != nil {
			return results, ctx.Err()
		}

		result, err := e.sendOne(ctx, client, job.purls, opts)
		if err == nil {
			results = append(results, result)
			continue
		}
		if firstErr == nil {
			firstErr = err
		}

		// Terminal failures are not worth splitting: a bad request stays bad at
		// any size, and retrying an auth failure just spends the user's quota.
		if !isTransientSCAErr(err) || job.round >= scaMaxRetryRounds || len(job.purls) <= scaMinChunkSize {
			e.log("sca: batch of %d package(s) failed: %v", len(job.purls), err)
			continue
		}

		half := (len(job.purls) + 1) / 2
		e.log("sca: batch of %d package(s) failed transiently, splitting into %d",
			len(job.purls), half)

		select {
		case <-time.After(backoffFor(job.round)):
		case <-ctx.Done():
			return results, ctx.Err()
		}

		for _, chunk := range chunkStrings(job.purls, half) {
			queue = append(queue, pending{purls: chunk, round: job.round + 1})
		}
	}

	if len(results) == 0 {
		if firstErr == nil {
			firstErr = errors.New("no response")
		}
		return nil, firstErr
	}
	return results, firstErr
}

// sendOne issues a single batch.
func (e *scaEngine) sendOne(
	ctx context.Context,
	client *vdb.Client,
	purls []string,
	opts vdb.CliSCAOptions,
) (scaBatchResult, error) {
	reqCtx, cancel := context.WithTimeout(ctx, scaRequestTimeout())
	defer cancel()

	resp, err := client.CliSCAWithContext(reqCtx, e.env(), vdb.CliSCARequest{
		Purls:   purls,
		Options: opts,
	})
	if err != nil {
		return scaBatchResult{}, err
	}

	e.recordPlan(client)
	e.recordTier(resp.Meta)

	out := scaBatchResult{Meta: resp.Meta, Insights: resp.Data.PackageInsights}
	if cs, ok := resp.Data.CycloneDX["components"].([]any); ok {
		out.Components = cs
	}
	if vs, ok := resp.Data.CycloneDX["vulnerabilities"].([]any); ok {
		out.Vulns = vs
	}
	return out, nil
}

// isTransientSCAErr classifies a batch failure, mirroring the scan command so
// the editor and the terminal give up at the same points.
//
// Retryable: 429, any 5xx, and transport-level failures including timeouts.
// Terminal: the rest of the 4xx range, which is a request the server
// understood and rejected, and decode errors, which will not decode next time
// either.
func isTransientSCAErr(err error) bool {
	if err == nil {
		return false
	}

	var apiErr *vdb.CliAPIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500
	}
	var notFound *vdb.NotFoundError
	if errors.As(err, &notFound) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// A cancelled context is the user moving on, not a failure to retry.
	if errors.Is(err, context.Canceled) {
		return false
	}
	return strings.Contains(err.Error(), "failed to execute request")
}

// backoffFor is capped exponential backoff between split rounds.
func backoffFor(round int) time.Duration {
	if round < 0 {
		round = 0
	}
	d := scaBackoffBase << round
	if d > scaBackoffMax {
		return scaBackoffMax
	}
	return d
}
