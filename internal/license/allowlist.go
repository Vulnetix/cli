package license

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// AllowList is a set of approved SPDX license IDs.
type AllowList struct {
	Licenses []string `yaml:"licenses"`
}

// LoadAllowListFromFile reads a YAML allow list file.
// Expected format:
//
//	licenses:
//	  - MIT
//	  - Apache-2.0
func LoadAllowListFromFile(path string) (*AllowList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var al AllowList
	if err := yaml.Unmarshal(data, &al); err != nil {
		return nil, err
	}
	// Normalize all IDs.
	for i, id := range al.Licenses {
		al.Licenses[i] = NormalizeSPDX(id)
	}
	return &al, nil
}

// ParseAllowListCSV parses a comma-separated list of SPDX IDs.
func ParseAllowListCSV(csv string) *AllowList {
	parts := strings.Split(csv, ",")
	al := &AllowList{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			al.Licenses = append(al.Licenses, NormalizeSPDX(p))
		}
	}
	return al
}

// Contains returns true if the given SPDX ID is in the allow list.
func (al *AllowList) Contains(spdxID string) bool {
	if al == nil || len(al.Licenses) == 0 {
		return true // no allow list = everything allowed
	}
	normalized := NormalizeSPDX(spdxID)
	for _, id := range al.Licenses {
		if strings.EqualFold(id, normalized) {
			return true
		}
	}
	return false
}

// IsActive returns true if the allow list has entries.
func (al *AllowList) IsActive() bool {
	return al != nil && len(al.Licenses) > 0
}
