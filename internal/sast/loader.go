package sast

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	git "github.com/go-git/go-git/v5"
)

// FetchRuleRepo clones or pulls a rule repository into the system cache.
// Returns the local cache path. Prints progress to w.
func FetchRuleRepo(registry string, ref RuleRef, w io.Writer) (string, error) {
	cacheDir, err := CacheDir(ref)
	if err != nil {
		return "", err
	}

	cloneURL := ResolveURL(registry, ref)

	// Try to open an existing cached clone and pull.
	if repo, oerr := git.PlainOpen(cacheDir); oerr == nil {
		wt, werr := repo.Worktree()
		if werr != nil {
			return "", fmt.Errorf("open worktree %s: %w", cacheDir, werr)
		}
		err = wt.Pull(&git.PullOptions{Depth: 1})
		if err != nil && err != git.NoErrAlreadyUpToDate {
			// Pull failed — remove cache and re-clone below.
			os.RemoveAll(cacheDir)
		} else {
			return cacheDir, nil
		}
	}

	// Clone fresh.
	if err := os.MkdirAll(filepath.Dir(cacheDir), 0o755); err != nil {
		return "", fmt.Errorf("mkdir cache: %w", err)
	}
	_, err = git.PlainClone(cacheDir, false, &git.CloneOptions{
		URL:   cloneURL,
		Depth: 1,
	})
	if err != nil {
		os.RemoveAll(cacheDir)
		return "", fmt.Errorf("rules registry not found: %s/%s: %w", ref.Org, ref.Repo, err)
	}

	return cacheDir, nil
}

// LoadAllModules loads default embedded rules and any external --rule repos.
// If disableDefault is true, embedded rules are skipped.
// Returns map[filename]source for all loaded .rego files.
func LoadAllModules(
	defaultFS embed.FS,
	disableDefault bool,
	ruleRefs []RuleRef,
	registry string,
	w io.Writer,
) (map[string]string, error) {
	modules := make(map[string]string)

	// Load embedded default rules.
	if !disableDefault {
		err := fs.WalkDir(defaultFS, "rules", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".rego") {
				return nil
			}
			data, rerr := defaultFS.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			modules[path] = string(data)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("load default rules: %w", err)
		}
	}

	// Load external rule repos.
	for _, ref := range ruleRefs {
		cacheDir, err := FetchRuleRepo(registry, ref, w)
		if err != nil {
			fmt.Fprintf(w, "Warning: %v\n", err)
			continue
		}

		n := 0
		rulesDir := filepath.Join(cacheDir, "rules")
		err = filepath.WalkDir(rulesDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable entries
			}
			if d.IsDir() || !strings.HasSuffix(path, ".rego") {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			relPath, _ := filepath.Rel(cacheDir, path)
			key := ref.Org + "/" + ref.Repo + "/" + filepath.ToSlash(relPath)
			modules[key] = string(data)
			n++
			return nil
		})
		if err != nil {
			fmt.Fprintf(w, "Warning: walking rules in %s/%s: %v\n", ref.Org, ref.Repo, err)
			continue
		}
		fmt.Fprintf(w, "Imported %d rules from %s/%s\n", n, ref.Org, ref.Repo)
	}

	return modules, nil
}
