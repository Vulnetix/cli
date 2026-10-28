package cmd

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/v3/internal/dockerfrom"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// maxContainerSourceFiles matches the server's cap on one request.
const maxContainerSourceFiles = 500

// skippedSourceDirs are trees no image is built from.
var skippedSourceDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".vulnetix": true, ".terraform": true}

// isContainerfile reports whether a file name is a Dockerfile or Containerfile
// by the names docker build and podman build look for, and the usual variants.
func isContainerfile(name string) bool {
	n := strings.ToLower(name)
	return n == "dockerfile" || n == "containerfile" ||
		strings.HasPrefix(n, "dockerfile.") || strings.HasPrefix(n, "containerfile.") ||
		strings.HasSuffix(n, ".dockerfile") || strings.HasSuffix(n, ".containerfile")
}

// collectContainerSources reads every Dockerfile under root.
func collectContainerSources(root string) []vdb.CliContainerSourceFile {
	var out []vdb.CliContainerSourceFile
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && skippedSourceDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !isContainerfile(d.Name()) || len(out) >= maxContainerSourceFiles {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		stages := dockerfrom.Parse(f)
		f.Close()
		if len(stages) == 0 {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		out = append(out, vdb.CliContainerSourceFile{Path: filepath.ToSlash(rel), Stages: toSourceStages(stages)})
		return nil
	})
	return out
}

func toSourceStages(stages []dockerfrom.Stage) []vdb.CliContainerSourceStage {
	out := make([]vdb.CliContainerSourceStage, 0, len(stages))
	for _, s := range stages {
		st := vdb.CliContainerSourceStage{
			Index: s.Index, Name: s.Name, Line: s.Line, RawRef: s.RawRef, ResolvedRef: s.ResolvedRef,
			FromStage: s.FromStage, Platform: s.Platform, IsFinal: s.IsFinal, UnresolvedArgs: s.UnresolvedArgs,
		}
		for _, in := range s.Installs {
			ci := vdb.CliContainerSourceInstall{Line: in.Line, Manager: in.Manager}
			for _, p := range in.Packages {
				ci.Packages = append(ci.Packages, vdb.CliContainerSourcePackage{Name: p.Name, Spec: p.Spec})
			}
			st.Installs = append(st.Installs, ci)
		}
		out = append(out, st)
	}
	return out
}

// postContainerSources records each Dockerfile FROM and install line so the
// container curation page can name the line to change. It is a side record of
// `vulnetix containers`: errors are reported and never change the exit code.
func postContainerSources(cmd *cobra.Command) {
	if vdbCreds == nil {
		return
	}
	root, _ := cmd.Flags().GetString("path")
	if root == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return
	}
	files := collectContainerSources(abs)
	if len(files) == 0 {
		return
	}
	client := vdb.NewClientFromCredentials(vdbCreds)
	client.NoCache = true
	resp, err := client.CliContainerSources(vdb.SnapshotEnv(abs, version, commit, buildDate), vdb.CliContainerSourcesRequest{Files: files})
	if err != nil {
		cmd.PrintErrf("Dockerfile sources not recorded: %v\n", err)
		return
	}
	if resp.Data.Persisted {
		cmd.PrintErrf("Recorded %d Dockerfile stage(s) and %d install line(s) for container curation.\n", resp.Data.Stages, resp.Data.Installs)
	}
}
