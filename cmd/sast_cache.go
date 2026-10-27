package cmd

import (
	"fmt"
	"os"
	"path/filepath"
)

// sastCacheDir is where the SAST result cache lives (internal/sast
// result_cache.go), or "" when it is off: --no-cache, or no user cache
// directory. VULNETIX_SAST_CACHE_DIR moves it, for a CI cache step.
func sastCacheDir(off bool) string {
	if off {
		return ""
	}
	if d := os.Getenv("VULNETIX_SAST_CACHE_DIR"); d != "" {
		return d
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "vulnetix", "sast")
}

// sastCacheSalt identifies this build in the cache key, so a new binary never
// reads findings an older engine produced. A release differs by version and
// commit; a development build, which keeps both, differs by the executable's
// size and modification time.
func sastCacheSalt() string {
	salt := fmt.Sprintf("%s|%s|%s", version, commit, buildDate)
	if exe, err := os.Executable(); err == nil {
		if info, err := os.Stat(exe); err == nil {
			salt += fmt.Sprintf("|%d|%d", info.Size(), info.ModTime().UnixNano())
		}
	}
	return salt
}
