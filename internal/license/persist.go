package license

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// The registry, deps.dev and GitHub lookups answered every scan afresh, so a
// project's licences cost one third-party round trip per package on every run
// (37 Hackage requests for a 37-package Haskell project, every time). What they
// answer is a property of a published release, so the answers persist on disk
// beside the VDB response cache, and a licence found is reused for a week.
// A miss is stored only when the source said so definitively (storeMiss; today
// only GitHub, whose gh calls distinguish a 404 from a timeout) and is reused
// for a day; elsewhere the fetchers return "" for a timeout as well as for a
// release with no licence, and remembering a timeout would hide the licence.
// VULNETIX_NO_LICENSE_CACHE disables the store.

const (
	licenseTTL     = 7 * 24 * time.Hour
	licenseMissTTL = 24 * time.Hour
)

// licenseStoreDir is where answers persist; empty disables the store. A var
// so tests can point it at a temporary directory.
var licenseStoreDir = defaultLicenseStoreDir()

func defaultLicenseStoreDir() string {
	if os.Getenv("VULNETIX_NO_LICENSE_CACHE") != "" {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".vulnetix", "cache", "licenses")
}

type storedLicense struct {
	License string `json:"license"`
	Miss    bool   `json:"miss,omitempty"`
	At      int64  `json:"at"` // unix seconds
}

func licenseStorePath(source, key string) string {
	sum := sha256.Sum256([]byte(source + "\x00" + key))
	return filepath.Join(licenseStoreDir, source, hex.EncodeToString(sum[:16])+".json")
}

// loadStoredLicense returns the stored licence for key from source, if it is
// still fresh.
func loadStoredLicense(source, key string) (lic string, ok bool) {
	if licenseStoreDir == "" {
		return "", false
	}
	raw, err := os.ReadFile(licenseStorePath(source, key))
	if err != nil {
		return "", false
	}
	var s storedLicense
	if json.Unmarshal(raw, &s) != nil || s.License == "" {
		return "", false
	}
	if time.Since(time.Unix(s.At, 0)) > licenseTTL {
		return "", false
	}
	return s.License, true
}

// storeLicense records a licence for key from source. Best-effort: a store that
// cannot be written costs the next run a lookup.
func storeLicense(source, key, lic string) {
	if licenseStoreDir == "" || lic == "" {
		return
	}
	writeStoredLicense(licenseStorePath(source, key), storedLicense{License: lic, At: time.Now().Unix()})
}

func writeStoredLicense(path string, s storedLicense) {
	raw, err := json.Marshal(s)
	if err != nil || os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(raw)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), path) != nil {
		_ = os.Remove(tmp.Name())
	}
}

// storedOrFetch returns the stored licence for key, or fetches it and stores a
// licence found.
func storedOrFetch(source, key string, fetch func() string) string {
	if lic, ok := loadStoredLicense(source, key); ok {
		return lic
	}
	lic := fetch()
	storeLicense(source, key, lic)
	return lic
}

// storeMiss records that source definitively has no licence for key.
func storeMiss(source, key string) {
	if licenseStoreDir == "" {
		return
	}
	writeStoredLicense(licenseStorePath(source, key+"\x00miss"), storedLicense{Miss: true, At: time.Now().Unix()})
}

// loadStoredMiss reports a definitive miss for key from source within a day.
func loadStoredMiss(source, key string) bool {
	if licenseStoreDir == "" {
		return false
	}
	raw, err := os.ReadFile(licenseStorePath(source, key+"\x00miss"))
	if err != nil {
		return false
	}
	var s storedLicense
	return json.Unmarshal(raw, &s) == nil && s.Miss && time.Since(time.Unix(s.At, 0)) <= licenseMissTTL
}
