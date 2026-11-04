// Package provision is the sensor side of sensor provisioning (vdb-site
// docs/sensor-provisioning-api.md): enrolling a device, as a person or with an
// MDM key, keeping the credential and the profile's configuration on disk,
// pulling configuration changes, and rendering the systemd units for the
// profile's protection level.
package provision

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultDir is where an enrolled sensor keeps its credential and config.
const DefaultDir = "/etc/vulnetix-sensor"

const (
	credentialFile = "credential"
	configFile     = "config.json"
	// uninstallingFile marks an uninstall in progress, so the daemon stopping
	// under it does not report the stop as a signal, and the guard leaves it
	// stopped.
	uninstallingFile = "uninstalling"
)

// Protection levels.
const (
	Standard = "standard"
	Hardened = "hardened"
	Locked   = "locked"
)

// Config is a profile's sensor configuration, as the site sends it.
type Config struct {
	Mode                  string   `json:"mode"`
	Hold                  string   `json:"hold,omitempty"`
	Feeds                 []string `json:"feeds"`
	FeedKey               string   `json:"feedKey"`
	EgressListen          string   `json:"egressListen"`
	DNSListen             string   `json:"dnsListen"`
	Forward               []string `json:"forward"`
	InventoryEvery        string   `json:"inventoryEvery,omitempty"`
	Protection            string   `json:"protection"`
	AllowUserStop         bool     `json:"allowUserStop"`
	HeartbeatAlertMinutes int      `json:"heartbeatAlertMinutes,omitempty"`
	// AutoUpdate lets the guard replace the sensor with the latest release.
	// Absent means on; false pins the fleet to the installed version.
	AutoUpdate *bool `json:"autoUpdate,omitempty"`
	// AllowMajorUpdate lets the guard take a release with a higher major version.
	// Absent or false holds the sensor on its major version: a major release can
	// change the profile format, the units and the protocol.
	AllowMajorUpdate *bool `json:"allowMajorUpdate,omitempty"`
	// UpdateBaseURL is an https mirror of the release layout
	// (<base>/latest, <base>/download/<tag>/checksums.txt and the binaries) for
	// hosts that cannot reach GitHub. Empty means GitHub.
	UpdateBaseURL string `json:"updateBaseUrl,omitempty"`
}

// Level is the protection level, standard when unset or unknown.
func (c Config) Level() string {
	switch c.Protection {
	case Hardened, Locked:
		return c.Protection
	}

	return Standard
}

// UserMayStop is whether a manual stop is allowed. A locked sensor never
// allows one, whatever allowUserStop says.
func (c Config) UserMayStop() bool {
	switch c.Level() {
	case Standard:
		return true
	case Locked:
		return false
	}

	return c.AllowUserStop
}

// ProfileRef names the profile a device enrolled under.
type ProfileRef struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// Snapshot is the last configuration the device pulled.
type Snapshot struct {
	Profile    ProfileRef `json:"profile"`
	Config     Config     `json:"config"`
	ConfigEtag string     `json:"configEtag"`
}

// Credential is what the device authenticates with.
type Credential struct {
	Scheme     string `json:"scheme"` // Sensor | ApiKey
	Value      string `json:"value"`
	DeviceUUID string `json:"deviceUuid"`
	Endpoint   string `json:"endpoint"`
}

// AuthHeader is the Authorization header value for c. A Sensor value is
// "<deviceUuid>:<secret>" as the site returns it; a bare secret is prefixed
// with the device uuid.
func (c Credential) AuthHeader() string {
	v := strings.TrimSpace(c.Value)
	if v == "" {
		return ""
	}
	switch strings.ToLower(c.Scheme) {
	case "sensor":
		if !strings.Contains(v, ":") && c.DeviceUUID != "" {
			v = c.DeviceUUID + ":" + v
		}

		return "Sensor " + v
	case "apikey":
		return "ApiKey " + v
	}

	return ""
}

// SensorKeyParam is the sensor key to name in config pulls and uninstalls:
// an ApiKey credential (user-key and org-key profiles) does not identify the
// device, so the site needs the key; a Sensor credential does, so "".
func (c Credential) SensorKeyParam(sensorKey string) string {
	if strings.EqualFold(c.Scheme, "apikey") {
		return sensorKey
	}

	return ""
}

// Store is the on-disk state of an enrolled device.
type Store struct {
	Dir string
}

func (s Store) dir() string {
	if s.Dir == "" {
		return DefaultDir
	}

	return s.Dir
}

// CredentialPath is the credential file.
func (s Store) CredentialPath() string { return filepath.Join(s.dir(), credentialFile) }

// ConfigPath is the config snapshot enroll writes.
func (s Store) ConfigPath() string { return filepath.Join(s.dir(), configFile) }

// UninstallingPath is the uninstall-in-progress marker.
func (s Store) UninstallingPath() string { return filepath.Join(s.dir(), uninstallingFile) }

// Uninstalling is whether an uninstall is in progress.
func (s Store) Uninstalling() bool {
	_, err := os.Stat(s.UninstallingPath())

	return err == nil
}

// SaveCredential writes the credential, readable by root only.
func (s Store) SaveCredential(c Credential) error {
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return writeFile(s.CredentialPath(), raw, 0o600)
}

// HasCredential is whether a credential is stored, from systemd's
// credentials directory or the store. It does not need to read the file.
func (s Store) HasCredential() bool {
	for _, p := range s.credentialPaths() {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}

	return false
}

// credentialPaths is where a credential is looked for: systemd's
// LoadCredential= copy first (the unit runs as a dynamic user that cannot
// read the root-only original), then the store.
func (s Store) credentialPaths() []string {
	var out []string
	if d := os.Getenv("CREDENTIALS_DIRECTORY"); d != "" {
		out = append(out, filepath.Join(d, credentialFile))
	}

	return append(out, s.CredentialPath())
}

// ErrNoCredential is returned when the device is not enrolled.
var ErrNoCredential = errors.New("not enrolled: no sensor credential")

// LoadCredential reads the credential.
func (s Store) LoadCredential() (Credential, error) {
	for _, p := range s.credentialPaths() {
		raw, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return Credential{}, fmt.Errorf("sensor credential %s: %w", p, err)
		}
		var c Credential
		if err := json.Unmarshal(raw, &c); err != nil {
			return Credential{}, fmt.Errorf("sensor credential %s: %w", p, err)
		}
		if c.AuthHeader() == "" {
			return Credential{}, fmt.Errorf("sensor credential %s: unknown scheme %q or empty value", p, c.Scheme)
		}

		return c, nil
	}

	return Credential{}, ErrNoCredential
}

// SaveSnapshot writes the store's config snapshot. It holds no secret.
func (s Store) SaveSnapshot(sn Snapshot) error { return SaveSnapshotAt(s.ConfigPath(), sn) }

// SaveSnapshotAt writes a config snapshot to path.
func SaveSnapshotAt(path string, sn Snapshot) error {
	raw, err := json.MarshalIndent(sn, "", "  ")
	if err != nil {
		return err
	}

	return writeFile(path, append(raw, '\n'), 0o644)
}

// LoadSnapshot reads the newest of the snapshots at paths: enroll writes one
// under the store, and the running sensor (which cannot write /etc) writes
// what it pulls to its state directory. A missing file is skipped.
func LoadSnapshot(paths ...string) (Snapshot, string, error) {
	var (
		best     Snapshot
		bestPath string
		bestTime time.Time
	)
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return Snapshot{}, "", err
		}
		var sn Snapshot
		if err := json.Unmarshal(raw, &sn); err != nil {
			return Snapshot{}, "", fmt.Errorf("config snapshot %s: %w", p, err)
		}
		if bestPath == "" || st.ModTime().After(bestTime) {
			best, bestPath, bestTime = sn, p, st.ModTime()
		}
	}
	if bestPath == "" {
		return Snapshot{}, "", fs.ErrNotExist
	}

	return best, bestPath, nil
}

// writeFile replaces path atomically with data at mode.
func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()

		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()

		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), path)
}

// AutoUpdateOn reports whether the sensor keeps itself current: on unless
// the profile says false.
func (c Config) AutoUpdateOn() bool { return c.AutoUpdate == nil || *c.AutoUpdate }

// AllowMajorUpdateOn reports whether the guard may cross a major version: off
// unless the profile says true.
func (c Config) AllowMajorUpdateOn() bool { return c.AllowMajorUpdate != nil && *c.AllowMajorUpdate }
