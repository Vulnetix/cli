package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vulnetix/cli/v4/internal/gitctx"
	"github.com/vulnetix/cli/v4/internal/suppress"
	"github.com/vulnetix/cli/v4/pkg/vdb"
)

// VEX documents the CLI read or wrote are sent to /v2/cli.vex-ingest, where the
// server stores each one and turns its false-positive and won't-fix statements
// into suppression rules. The CLI does not classify statements: it sends the
// exact bytes and reports what the server did.
//
// Sending is best effort. An unauthenticated run sends nothing, and a failed
// send is a warning: a scan never fails because ingest did.

// vexRawDocument is one document as read from disk or rendered in memory.
type vexRawDocument struct {
	Path string
	Data []byte
}

// vexIngestInput is one call's worth of documents and their context.
type vexIngestInput struct {
	Origin string
	Docs   []vexRawDocument
	Git    *gitctx.GitContext
	// ScannerRunUuid and SnapshotUuid tie the documents to this run's findings
	// when the run persisted any.
	ScannerRunUuid string
	SnapshotUuid   string
	// Warn receives one line per problem and the summary. Nil means stderr.
	Warn io.Writer
}

// vexIngestTimeout bounds one request; a slow backend costs the ingest, never
// the command.
const vexIngestTimeout = 60 * time.Second

// vexIngestAllowed reports whether this run may send documents. A test swaps
// it to keep runs offline.
var vexIngestAllowed = func() bool { return !isUnauthenticatedScan() }

// ensureVDBCredentials loads the stored credentials for a command whose cobra
// hooks never did (upload, bom enrich, vex apply, triage). Called from a
// command's RunE only, never from the shared helpers, so a test that drives a
// pipeline function directly cannot pick up the developer's real credentials.
func ensureVDBCredentials() {
	if vdbCreds == nil {
		_ = resolveVDBCredentials(false)
	}
}

// readVEXFiles reads paths into raw documents, skipping any that cannot be read.
func readVEXFiles(paths []string) []vexRawDocument {
	out := make([]vexRawDocument, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		out = append(out, vexRawDocument{Path: p, Data: data})
	}
	return out
}

// vexIngestPath is the path sent with a document: relative to the repository
// root when the file is inside it, so two machines name it the same way, else
// the base name, so no local directory layout leaves the machine.
func vexIngestPath(path, repoRoot string) string {
	if repoRoot != "" {
		if abs, err := filepath.Abs(path); err == nil {
			if rel, err := filepath.Rel(repoRoot, abs); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return filepath.ToSlash(rel)
			}
		}
	}
	return filepath.Base(path)
}

// buildVEXIngestRequests turns the input into requests within the server's
// limits. It returns the notes for documents it left out (not VEX, too large).
func buildVEXIngestRequests(in vexIngestInput) ([]vdb.CliVexIngestRequest, []string) {
	var (
		notes []string
		docs  []vdb.CliVexDocument
		root  string
	)
	base := vdb.CliVexIngestRequest{
		Origin:                in.Origin,
		ScannerRunUuid:        in.ScannerRunUuid,
		IngestionSnapshotUuid: in.SnapshotUuid,
	}
	if in.Git != nil {
		root = in.Git.RepoRootPath
		base.RepositoryFullName = suppress.RepoFullName(in.Git.RemoteURLs)
		base.GitCommit = in.Git.CurrentCommit
	}

	seen := map[string]bool{}
	for _, d := range in.Docs {
		name := vexIngestPath(d.Path, root)
		if len(d.Data) > vdb.VexIngestMaxDocumentBytes {
			notes = append(notes, fmt.Sprintf("%s is over the %d MiB limit and was not sent", name, vdb.VexIngestMaxDocumentBytes>>20))
			continue
		}
		format := vexIngestFormat(d.Data)
		if format == "" {
			notes = append(notes, fmt.Sprintf("%s is not OpenVEX, CycloneDX or CSAF and was not sent", name))
			continue
		}
		sum := sha256.Sum256(d.Data)
		digest := hex.EncodeToString(sum[:])
		if seen[digest] {
			continue
		}
		seen[digest] = true
		docs = append(docs, vdb.CliVexDocument{
			Path:    name,
			Format:  format,
			Sha256:  digest,
			Content: base64.StdEncoding.EncodeToString(d.Data),
		})
	}

	var reqs []vdb.CliVexIngestRequest
	for start := 0; start < len(docs); start += vdb.VexIngestMaxDocuments {
		end := start + vdb.VexIngestMaxDocuments
		if end > len(docs) {
			end = len(docs)
		}
		r := base
		r.Documents = docs[start:end]
		reqs = append(reqs, r)
	}
	return reqs, notes
}

// ingestVEX sends the documents and prints what the server did. Never fails
// the caller: every problem is a warning.
func ingestVEX(ctx context.Context, in vexIngestInput) []vdb.CliVexIngestResult {
	if len(in.Docs) == 0 || !vexIngestAllowed() {
		return nil
	}
	w := in.Warn
	if w == nil {
		w = os.Stderr
	}
	reqs, notes := buildVEXIngestRequests(in)
	for _, n := range notes {
		fmt.Fprintf(w, "  VEX not sent: %s\n", n)
	}
	if len(reqs) == 0 {
		return nil
	}
	client := newCliClient()
	if client == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	env := envForCliWithGit(in.Git)

	var results []vdb.CliVexIngestResult
	for _, req := range reqs {
		callCtx, cancel := context.WithTimeout(ctx, vexIngestTimeout)
		resp, err := client.CliVexIngest(callCtx, env, req)
		cancel()
		if err != nil {
			fmt.Fprintf(w, "  warning: could not send %d VEX document(s) to Vulnetix: %v\n", len(req.Documents), err)
			continue
		}
		results = append(results, resp.Data.Documents...)
	}
	reportVEXIngest(w, results)
	return results
}

// reportVEXIngest prints one line for the batch and one per document error.
func reportVEXIngest(w io.Writer, results []vdb.CliVexIngestResult) {
	if len(results) == 0 {
		return
	}
	var created, pending, linked, applied int
	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(w, "  warning: Vulnetix did not ingest %s: %s\n", r.Path, r.Error)
			continue
		}
		created += len(r.Created)
		pending += len(r.Pending)
		linked += len(r.Linked)
		applied += r.Applied
	}
	if silent {
		return
	}
	fmt.Fprintf(w, "  VEX sent to Vulnetix: %d document(s), %d rule(s) created, %d waiting for review, %d linked, %d finding(s) suppressed\n",
		len(results), created, pending, linked, applied)
}
