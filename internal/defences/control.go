package defences

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ControlsFile is where recorded compensating controls live, relative to the
// project root.
const ControlsFile = ".vulnetix/controls.json"

// DefaultControlLife is how long a recorded control lasts when --until is not
// given. A compensating control is a loan against a patch that has not arrived,
// so it expires; the licence exception file works the same way.
const DefaultControlLife = 90 * 24 * time.Hour

// Control is a statement by a person that a defence is in place for a finding
// that has no fix. The CLI cannot verify it is deployed: this is a record of a
// claim, with an expiry, and every renderer says so.
type Control struct {
	VulnID  string `json:"vulnId"`
	Package string `json:"package"`
	Version string `json:"version,omitempty"`
	// Ecosystem is optional context for the VEX statement.
	Ecosystem string `json:"ecosystem,omitempty"`
	Lane      Lane   `json:"lane"`
	Kind      Kind   `json:"kind,omitempty"`
	// Where is the person's own description: "ModSecurity, prod-eu ingress".
	Where      string    `json:"where"`
	RecordedAt time.Time `json:"recordedAt"`
	RecordedBy string    `json:"recordedBy,omitempty"`
	Until      time.Time `json:"until"`
	// Mode is the mode the rule states it is safe to start in, copied from the
	// rule so the PROTECTED line can repeat it ("log only" protects nothing).
	Mode       string `json:"mode,omitempty"`
	RuleSHA256 string `json:"ruleSha256,omitempty"`
}

// Active reports whether the control is still in date.
func (c Control) Active(now time.Time) bool {
	return !c.Until.IsZero() && now.Before(c.Until)
}

// Expired reports whether the control has lapsed.
func (c Control) Expired(now time.Time) bool { return !c.Active(now) }

// Blocks reports whether the control stops the request. A detection alone does
// not, and a rule still in log-only mode does not either.
func (c Control) Blocks() bool {
	if c.Lane != LaneBlock {
		return false
	}
	m := strings.ToLower(strings.TrimSpace(c.Mode))
	return m != "log" && m != "log-only" && m != "monitor"
}

// ControlSet is the loaded set of controls.
type ControlSet struct {
	Version  int       `json:"version"`
	Controls []Control `json:"controls"`
}

// LoadControls reads the controls file under root. A missing file is an empty
// set, not an error.
func LoadControls(root string) (ControlSet, error) {
	set := ControlSet{Version: 1}
	data, err := os.ReadFile(filepath.Join(root, ControlsFile))
	if errors.Is(err, os.ErrNotExist) {
		return set, nil
	}
	if err != nil {
		return set, err
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return ControlSet{Version: 1}, fmt.Errorf("%s: %w", ControlsFile, err)
	}
	return set, nil
}

// Save writes the set back, sorted so the file diffs cleanly.
func (s ControlSet) Save(root string) error {
	s.Version = 1
	sort.SliceStable(s.Controls, func(i, j int) bool {
		a, b := s.Controls[i], s.Controls[j]
		if a.VulnID != b.VulnID {
			return a.VulnID < b.VulnID
		}
		return a.Package < b.Package
	})
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(root, ControlsFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// Upsert adds a control, replacing any earlier record for the same
// vulnerability, package and lane.
func (s *ControlSet) Upsert(c Control) {
	for i, e := range s.Controls {
		if strings.EqualFold(e.VulnID, c.VulnID) && strings.EqualFold(e.Package, c.Package) && e.Lane == c.Lane {
			s.Controls[i] = c
			return
		}
	}
	s.Controls = append(s.Controls, c)
}

// For returns every control recorded for a vulnerability on a package,
// regardless of expiry, so a renderer can tell "none" from "lapsed".
func (s ControlSet) For(vulnID, pkg string) []Control {
	var out []Control
	for _, c := range s.Controls {
		if strings.EqualFold(c.VulnID, vulnID) && strings.EqualFold(c.Package, pkg) {
			out = append(out, c)
		}
	}
	return out
}
