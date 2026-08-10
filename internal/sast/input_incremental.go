package sast

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/vulnetix/cli/v3/internal/secretscan"
)

// Overlay returns a shallow copy of base whose FileContents holds exactly the
// documents in docs.
//
// This is the keystroke path. A full BuildScanInput walk plus content load
// costs a filesystem traversal and a read of every file; on an edit only one
// file changed, and the editor already has its text, including the parts not
// yet written to disk.
//
// FileSet and DirsByLanguage are shared with base rather than copied. Rules
// that ask whether a path exists, or which languages a directory contains,
// still see the whole repository, so a rule keyed on "there is a Dockerfile
// here" behaves the same as in a full scan. Both maps are treated as read-only
// by evaluation, and a prepared query evaluates concurrently against them.
//
// Known limitation, and the reason this is not used on every trigger: a rule
// that correlates the contents of two files sees only the overlaid ones, so it
// can under-report. The corpus is per-file today (rules iterate
// input.file_contents and examine one entry at a time), but nothing structurally
// enforces that. Save and workspace scans therefore evaluate real content, and
// overlay is confined to the path where latency actually matters.
func Overlay(base *ScanInput, docs map[string]string) *ScanInput {
	if base == nil {
		return &ScanInput{
			FileSet:        map[string]bool{},
			DirsByLanguage: map[string][]string{},
			FileContents:   maps.Clone(docs),
		}
	}

	contents := make(map[string]string, len(docs))
	maps.Copy(contents, docs)

	// A document open in the editor may be new, so make sure path-existence
	// rules can see it. FileSet is shared, so it cannot be mutated: copy only
	// when there is genuinely something to add.
	fileSet := base.FileSet
	missing := false
	for path := range docs {
		if !base.FileSet[path] {
			missing = true
			break
		}
	}
	if missing {
		fileSet = make(map[string]bool, len(base.FileSet)+len(docs))
		maps.Copy(fileSet, base.FileSet)
		for path := range docs {
			fileSet[path] = true
		}
	}

	return &ScanInput{
		FileSet:        fileSet,
		DirsByLanguage: base.DirsByLanguage,
		FileContents:   contents,
		ScanRoot:       base.ScanRoot,
	}
}

// OverlayOnto returns a copy of base with docs merged over its existing
// contents, rather than replacing them.
//
// Used on save, where the point is to evaluate the whole repository with the
// editor's version of the dirty buffers in place of what is on disk.
func OverlayOnto(base *ScanInput, docs map[string]string) *ScanInput {
	if base == nil {
		return Overlay(nil, docs)
	}
	merged := make(map[string]string, len(base.FileContents)+len(docs))
	maps.Copy(merged, base.FileContents)
	maps.Copy(merged, docs)

	out := Overlay(base, merged)
	return out
}

// ctxCheckInterval is how many files are processed between cancellation
// checks during a content load. Checking every file costs an atomic load per
// iteration; every 256 bounds the response to a cancel at well under a
// millisecond while keeping the loop essentially free.
const ctxCheckInterval = 256

// BuildScanInputContext is BuildScanInputWithOptions with cancellation.
//
// filepath.WalkDir does not honour a context, so a workspace scan of a large
// repository cannot be interrupted: the walk runs to completion regardless of
// whether anyone still wants the answer. In a CLI that is invisible. In a
// language server it means a cancelled scan keeps a core busy, and a shutdown
// waits for a traversal nobody is reading.
//
// Returns ctx.Err() when cancelled, so a caller can distinguish "cancelled"
// from "failed".
func BuildScanInputContext(ctx context.Context, rootPath string, opts BuildOptions) (*ScanInput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// The walk is delegated rather than reimplemented, so the two entry points
	// cannot drift in what they include or exclude. Interrupting
	// filepath.WalkDir from outside is not possible, so the walk runs on its
	// own goroutine and the caller stops waiting when ctx is done.
	//
	// The trade-off is explicit: a cancelled walk is abandoned rather than
	// halted, so it still finishes in the background. That is bounded by the
	// walk itself, touches nothing the caller can observe, and buys the caller
	// an immediate return. Stopping the walk mid-flight would mean owning a
	// copy of WalkDir.
	type result struct {
		input *ScanInput
		err   error
	}
	done := make(chan result, 1)

	go func() {
		input, err := BuildScanInputWithOptions(rootPath, opts)
		done <- result{input, err}
	}()

	select {
	case <-ctx.Done():
		// The walk goroutine finishes on its own and its result is discarded.
		// It touches nothing the caller can observe, and abandoning it is
		// bounded by the walk itself rather than by anything unbounded.
		return nil, ctx.Err()
	case r := <-done:
		return r.input, r.err
	}
}

// LoadContentsResult reports what a content load actually managed to read.
//
// "No findings" and "did not look" must never be indistinguishable, so a load
// that stopped early says so rather than leaving the caller to infer it from a
// suspiciously small map.
type LoadContentsResult struct {
	// Loaded is the number of files whose content was read.
	Loaded int
	// SkippedTooLarge is the number of files over the per-file cap.
	SkippedTooLarge int
	// SkippedBinary is the number of binary files skipped entirely.
	SkippedBinary int
	// SkippedUnreadable is the number of files that could not be read.
	SkippedUnreadable int
	// TruncatedAtBudget is true when the aggregate byte budget was exhausted
	// and files were left unread as a result.
	TruncatedAtBudget bool
	// TotalBytes is how much file content was held.
	TotalBytes int64
}

// Degradations renders the result as human-readable notices, empty when the
// load was complete.
func (r LoadContentsResult) Degradations() []string {
	var out []string
	if n := r.SkippedTooLarge; n > 0 {
		out = append(out, plural(n, "file", "was", "were")+" not content-scanned (over the per-file size cap)")
	}
	if n := r.SkippedUnreadable; n > 0 {
		out = append(out, plural(n, "file", "was", "were")+" not content-scanned (unreadable)")
	}
	if r.TruncatedAtBudget {
		out = append(out, "the scan reached its memory budget and stopped loading file content; results are partial")
	}
	return out
}

func plural(n int, noun, singular, pluralVerb string) string {
	verb := singular
	suffix := ""
	if n != 1 {
		verb = pluralVerb
		suffix = "s"
	}
	return strconv.Itoa(n) + " " + noun + suffix + " " + verb
}

// LoadFileContentsBudgeted is LoadFileContentsWithOptions with an aggregate
// byte ceiling and cancellation.
//
// LoadFileContentsWithOptions caps each file at MaxFileSize but nothing caps
// the total, so a repository with enough files below the per-file cap can
// allocate several gigabytes. A CLI process exits afterwards and nobody
// notices; a long-lived language server holding that is a memory leak with a
// filesystem as its source.
//
// Files are loaded in sorted order so that the same repository truncates at the
// same point on every run, which keeps a truncated scan reproducible rather
// than dependent on map iteration order.
func LoadFileContentsBudgeted(ctx context.Context, input *ScanInput, opts LoadOptions, maxTotalBytes int64) (LoadContentsResult, error) {
	var res LoadContentsResult

	if input.FileContents == nil {
		input.FileContents = make(map[string]string)
	}

	paths := make([]string, 0, len(input.FileSet))
	for relPath := range input.FileSet {
		paths = append(paths, relPath)
	}
	slices.Sort(paths)

	for i, relPath := range paths {
		if i%ctxCheckInterval == 0 {
			if err := ctx.Err(); err != nil {
				return res, err
			}
		}

		absPath := filepath.Join(input.ScanRoot, filepath.FromSlash(relPath))
		info, err := os.Stat(absPath)
		if err != nil {
			res.SkippedUnreadable++
			continue
		}
		if info.Size() == 0 {
			continue
		}
		if opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
			res.SkippedTooLarge++
			continue
		}
		if maxTotalBytes > 0 && res.TotalBytes+info.Size() > maxTotalBytes {
			// Stop rather than skip-and-continue: continuing would load every
			// remaining small file and report a budget that was silently
			// exceeded in aggregate anyway.
			res.TruncatedAtBudget = true
			break
		}

		data, err := os.ReadFile(absPath)
		if err != nil {
			res.SkippedUnreadable++
			continue
		}

		if looksBinary(data) {
			if opts.IgnoreBinaries {
				res.SkippedBinary++
				continue
			}
			insight := secretscan.InspectBinary(relPath, data, secretscan.InspectOptions{
				IncludeStrings:  true,
				MinStringLength: opts.MinStringLength,
			})
			if insight.StringsKey != "" && insight.StringsVal != "" {
				input.FileContents[insight.StringsKey] = insight.StringsVal
				res.TotalBytes += int64(len(insight.StringsVal))
			}
			if insight.EXIFKey != "" {
				input.FileContents[insight.EXIFKey] = insight.EXIFVal
				res.TotalBytes += int64(len(insight.EXIFVal))
			}
			continue
		}

		input.FileContents[relPath] = string(data)
		res.TotalBytes += info.Size()
		res.Loaded++

		// Base64 in a Kubernetes Secret is not encryption, and would otherwise
		// evade every line-regex rule. Mirrors LoadFileContentsWithOptions.
		if strings.HasSuffix(relPath, ".yaml") || strings.HasSuffix(relPath, ".yml") {
			for k, v := range secretscan.ExpandKubernetesSecrets(relPath, input.FileContents[relPath]) {
				if _, exists := input.FileContents[k]; !exists {
					input.FileContents[k] = v
					res.TotalBytes += int64(len(v))
				}
			}
		}
	}

	return res, nil
}
