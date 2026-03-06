package update

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// InstallMethod describes how the binary was installed.
type InstallMethod int

const (
	MethodSourceBuild InstallMethod = iota
	MethodGoInstall
	MethodPrebuilt
)

// DetectInstallMethod determines how the binary was installed.
func DetectInstallMethod(version, commit string) InstallMethod {
	// Dev builds or unknown commits indicate source build
	if strings.Contains(version, "-dev") || commit == "unknown" {
		return MethodSourceBuild
	}

	// Check if binary is inside GOBIN or GOPATH/bin
	exe, err := os.Executable()
	if err == nil {
		exe, _ = filepath.EvalSymlinks(exe)
		dir := filepath.Dir(exe)

		if gobin := os.Getenv("GOBIN"); gobin != "" && dir == gobin {
			return MethodGoInstall
		}
		if gopath := os.Getenv("GOPATH"); gopath != "" {
			if dir == filepath.Join(gopath, "bin") {
				return MethodGoInstall
			}
		}
		// Default GOPATH
		if home, err := os.UserHomeDir(); err == nil {
			if dir == filepath.Join(home, "go", "bin") {
				return MethodGoInstall
			}
		}
	}

	return MethodPrebuilt
}

// Update performs a self-update of the binary.
func Update(currentVersion, commit string) error {
	method := DetectInstallMethod(currentVersion, commit)

	switch method {
	case MethodSourceBuild:
		return fmt.Errorf("this binary was built from source; use 'go build' or 'make dev' to update")

	case MethodGoInstall:
		return updateViaGoInstall()

	case MethodPrebuilt:
		return updatePrebuilt()

	default:
		return fmt.Errorf("unknown install method")
	}
}

func updateViaGoInstall() error {
	fmt.Println("Updating via go install...")
	cmd := exec.Command("go", "install", "github.com/vulnetix/cli@latest")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go install failed: %w", err)
	}
	fmt.Println("Update complete.")
	return nil
}

func updatePrebuilt() error {
	release, err := CheckLatest()
	if err != nil {
		return err
	}

	downloadURL := FindAsset(release)
	if downloadURL == "" {
		return fmt.Errorf("no release asset found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	fmt.Printf("Downloading %s...\n", release.TagName)

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("cannot resolve executable path: %w", err)
	}

	// Download to temp file in same directory (for atomic rename)
	dir := filepath.Dir(exe)
	tmpFile, err := os.CreateTemp(dir, "vulnetix-update-*")
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(downloadURL)
	if err != nil {
		tmpFile.Close()
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		tmpFile.Close()
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		return fmt.Errorf("download failed: %w", err)
	}
	tmpFile.Close()

	// Make executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("chmod failed: %w", err)
	}

	// On Windows, rename current binary first (can't overwrite running exe)
	if runtime.GOOS == "windows" {
		oldPath := exe + ".old"
		os.Remove(oldPath) // ignore error
		if err := os.Rename(exe, oldPath); err != nil {
			return fmt.Errorf("cannot move current binary: %w", err)
		}
	}

	// Atomic replace
	if err := os.Rename(tmpPath, exe); err != nil {
		return fmt.Errorf("cannot replace binary: %w", err)
	}

	fmt.Printf("Updated to %s\n", release.TagName)
	return nil
}
