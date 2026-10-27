package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/vulnetix/cli/v3/internal/ecosystems"
	"github.com/vulnetix/malscan-engine/badnet"
	"github.com/vulnetix/malscan-engine/iocscan"
)

// One install target (a project's node_modules) is one engine walk, and the
// walk matches every line of every file on one core: most of a malscan run on
// a large dependency tree. iocscanSplit gives the same report from one walk
// per top-level entry of the target, run on every core.
//
// That is the same report because of what the engine reads from a file's path
// relative to the target: it classifies a file by whole path segments (a
// /test/ or /dist/ directory) and by its name, so a file under
// <target>/<entry>/ is classified alike whether the walk starts at <target> or
// at <entry>, unless <entry> is itself one of those segments. A target with
// such an entry, or a depth limit (which counts from the walk's root), is
// walked whole as before. Evidence is concatenated in the order the single
// walk visits entries (filepath.WalkDir: by name), RelPath is put back
// relative to the target, and the indicator set is built once, exactly as
// iocscan.Scan builds it, and shared. TestIOCScanSplitMatchesWholeWalk checks
// the result against iocscan.Scan.

// malscanTierSegments are the directory names the engine (malscan-engine
// v0.6.1 iocFileTier) classifies a path by. An entry named one of these is
// classified differently when it is the walk's root, so its target is not
// split. TestMalscanEnginePinnedForSplit fails when the engine is bumped, to
// make this list be checked against the new engine.
var malscanTierSegments = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "__fixtures__": true, "fixtures": true,
	"spec": true, "__mocks__": true,
	"example": true, "examples": true, "sample": true, "samples": true, "demo": true, "demos": true,
	"dist": true,
}

// iocscanSplit is iocscanTarget, walking the target's top-level entries
// concurrently when that gives the same report.
func iocscanSplit(target ecosystems.Target, opts malscanOptions) (*iocscan.Report, error) {
	entries, ok := splittableEntries(target.Path, opts)
	if !ok {
		return iocscanTarget(target, opts)
	}
	set, warnings, err := loadIOCSet(target, opts)
	if err != nil {
		return &iocscan.Report{Warnings: warnings}, err
	}
	rep := scanEntries(target.Path, entries, opts, set)
	rep.Warnings = warnings
	return rep, nil
}

// splittableEntries is the target's top-level entries, sorted by name as the
// walk visits them, or false when the target must be walked whole.
func splittableEntries(root string, opts malscanOptions) ([]os.DirEntry, bool) {
	if opts.Depth > 0 {
		return nil, false
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, false
	}
	dirs := 0
	for _, e := range entries {
		if e.IsDir() {
			if malscanTierSegments[strings.ToLower(e.Name())] {
				return nil, false
			}
			dirs++
		}
	}
	return entries, dirs > 1
}

// loadIOCSet builds the indicator set as iocscan.Scan does for these options:
// the ecosystem's feeds, then the embedded badnet blocklist and any runtime
// badnet overlay.
func loadIOCSet(target ecosystems.Target, opts malscanOptions) (*iocscan.IndicatorSet, []iocscan.Warning, error) {
	set, warnings, err := (&iocscan.FeedLoader{}).Load(target.EngineSlug)
	if err != nil {
		return nil, warnings, err
	}
	set.AddBadnetSet(badnet.New())
	if opts.BadnetDir != "" {
		if overlay, lerr := badnet.LoadDir(opts.BadnetDir); lerr == nil {
			set.AddBadnetSet(overlay)
		} else {
			warnings = append(warnings, iocscan.Warning{
				Code: "badnet-overlay", Message: "runtime badnet definitions: " + lerr.Error()})
		}
	}
	return set, warnings, nil
}

// scanEntries walks each top-level directory of root as its own root, and the
// files directly in root in one walk that descends nowhere, and joins the
// results in walk order.
func scanEntries(root string, entries []os.DirEntry, opts malscanOptions, set *iocscan.IndicatorSet) *iocscan.Report {
	skip := ecosystems.ScanSkipDirs()
	skipped := map[string]bool{}
	for _, s := range skip {
		skipped[s] = true
	}
	base := func(r string, dirs []string) iocscan.Options {
		return iocscan.Options{
			Root:           r,
			Set:            set,
			BinaryAnalysis: opts.BinaryAnalysis,
			ContextLines:   iocscan.DefaultContextLines,
			MaxFileSize:    opts.MaxFileSize,
			SkipDirs:       dirs,
		}
	}

	// unit i is entries[i]; the root's own files are one walk, split back
	// out by file name below.
	var dirIdx []int
	var allDirs []string
	for i, e := range entries {
		if e.IsDir() {
			allDirs = append(allDirs, e.Name())
			if !skipped[e.Name()] {
				dirIdx = append(dirIdx, i)
			}
		}
	}
	reports := make([]*iocscan.Report, len(entries))
	var rootFiles *iocscan.Report

	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, runtime.GOMAXPROCS(0)))
	run := func(f func()) {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			f()
		}()
	}
	run(func() {
		rootFiles, _ = iocscan.Scan(base(root, append(slices.Clone(skip), allDirs...)))
	})
	for _, i := range dirIdx {
		run(func() {
			reports[i], _ = iocscan.Scan(base(filepath.Join(root, entries[i].Name()), skip))
		})
	}
	wg.Wait()

	out := &iocscan.Report{IndicatorCount: set.Len()}
	byFile := map[string][]iocscan.Evidence{}
	if rootFiles != nil {
		out.FilesScanned += rootFiles.FilesScanned
		for _, ev := range rootFiles.Evidence {
			byFile[ev.RelPath] = append(byFile[ev.RelPath], ev)
		}
	}
	for i, e := range entries {
		if !e.IsDir() {
			out.Evidence = append(out.Evidence, byFile[e.Name()]...)
			continue
		}
		r := reports[i]
		if r == nil {
			continue
		}
		out.FilesScanned += r.FilesScanned
		for _, ev := range r.Evidence {
			ev.RelPath = filepath.Join(e.Name(), ev.RelPath)
			out.Evidence = append(out.Evidence, ev)
		}
	}
	return out
}
