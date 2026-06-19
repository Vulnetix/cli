package fix

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// installCommandTimeout bounds a single install command. It must accommodate one
// full dependency re-resolution (e.g. `go mod tidy` / `npm install`) which, on a
// slow/cooldown-prone module proxy, can take several minutes — so it is generous.
const installCommandTimeout = 10 * time.Minute

func RunInstall(ctx context.Context, batches []FixBatch, dryRun bool, w io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if w == nil {
		w = io.Discard
	}
	seen := map[string]bool{}
	for _, b := range batches {
		// Batchable ecosystems (Go) collapse all fixes in this directory into ONE
		// install command (e.g. `go get m1@v m2@v … && go mod tidy`) so the
		// expensive dependency re-resolution runs once, not once per fix.
		if cmd, ok := batchInstallCommand(b); ok {
			if err := runInstallCommand(ctx, b.Dir, cmd, dryRun, w, seen); err != nil {
				return fmt.Errorf("%s failed in %s: %w", cmd, b.Dir, err)
			}
			continue
		}
		for _, p := range b.Plans {
			if p.Skipped || p.Command == "" {
				continue
			}
			if err := runInstallCommand(ctx, b.Dir, p.Command, dryRun, w, seen); err != nil {
				if isNpmPeerConflict(err) && batchHasNpmPlans(b) {
					fmt.Fprintln(w, "    npm peer dependency conflict detected; adding vetted overrides and retrying")
					if overrideErr := applyNpmOverrides(b); overrideErr != nil {
						return fmt.Errorf("%s failed in %s: %w; override retry failed: %v", p.Command, b.Dir, err, overrideErr)
					}
					retryCtx, retryCancel := context.WithTimeout(ctx, installCommandTimeout)
					retryErr := runShell(retryCtx, b.Dir, p.Command)
					retryCancel()
					if retryErr == nil {
						continue
					}
					return fmt.Errorf("%s failed in %s after override retry: %w", p.Command, b.Dir, retryErr)
				}
				return fmt.Errorf("%s failed in %s: %w", p.Command, b.Dir, err)
			}
		}
	}
	return nil
}

// runInstallCommand runs one command in dir, deduplicated by (dir, command). It
// returns nil when the command was already run (deduped) or succeeds, and the raw
// shell error otherwise (callers add context). Honors dryRun and the timeout.
func runInstallCommand(ctx context.Context, dir, command string, dryRun bool, w io.Writer, seen map[string]bool) error {
	if command == "" {
		return nil
	}
	key := dir + "::" + command
	if seen[key] {
		return nil
	}
	seen[key] = true
	fmt.Fprintf(w, "  $ (cd %s && %s)\n", dir, command)
	if dryRun {
		return nil
	}
	cmdCtx, cancel := context.WithTimeout(ctx, installCommandTimeout)
	defer cancel()
	return runShell(cmdCtx, dir, command)
}

func isNpmPeerConflict(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "ERESOLVE") || strings.Contains(strings.ToLower(msg), "peer dependency")
}

func batchHasNpmPlans(b FixBatch) bool {
	for _, p := range b.Plans {
		if !p.Skipped && strings.EqualFold(p.Ecosystem, "npm") && p.TargetVer != "" {
			return true
		}
	}
	return false
}

func applyNpmOverrides(b FixBatch) error {
	path := filepath.Join(b.Dir, "package.json")
	if _, err := os.Stat(path); err != nil {
		return err
	}
	pm := ""
	pins := map[string]string{}
	for _, p := range b.Plans {
		if p.Skipped || !strings.EqualFold(p.Ecosystem, "npm") || p.PackageName == "" || p.TargetVer == "" {
			continue
		}
		pins[p.PackageName] = p.TargetVer
		if pm == "" && p.PackageManager != "" {
			pm = p.PackageManager
		}
	}
	return applyPackageJSONOverrides(path, pm, pins)
}

func runShell(ctx context.Context, dir, command string) error {
	shell := "sh"
	args := []string{"-c", command}
	if runtime.GOOS == "windows" {
		shell = "cmd"
		args = []string{"/C", command}
	}
	cmd := exec.CommandContext(ctx, shell, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if ctxErr := ctx.Err(); ctxErr != nil {
			if msg != "" {
				return fmt.Errorf("%w after %s: %s", ctxErr, installCommandTimeout, msg)
			}
			return fmt.Errorf("%w after %s", ctxErr, installCommandTimeout)
		}
		if msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}
