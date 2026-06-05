package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const PackageFirewallHost = "packages.vulnetix.com"

// NetrcInfo describes the Vulnetix Package Firewall entry in netrc.
type NetrcInfo struct {
	Path         string
	Found        bool
	MachineFound bool
	Secure       bool
	OrgID        string
	APIKey       string
	Err          error
}

// NetrcPath returns the platform-specific netrc path used by Go and curl-like tools.
func NetrcPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to determine home directory: %w", err)
	}
	return netrcPathFor(runtime.GOOS, homeDir), nil
}

func netrcPathFor(goos, homeDir string) string {
	if goos == "windows" {
		return filepath.Join(homeDir, "_netrc")
	}
	return filepath.Join(homeDir, ".netrc")
}

// NetrcStatus reports whether netrc contains usable Vulnetix credentials.
func NetrcStatus() NetrcInfo {
	path, err := NetrcPath()
	if err != nil {
		return NetrcInfo{Err: err}
	}

	info := NetrcInfo{Path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return info
		}
		info.Found = true
		info.Err = err
		return info
	}
	info.Found = true

	if err := checkNetrcPermissions(path); err != nil {
		info.Err = err
		return info
	}
	info.Secure = true

	orgID, apiKey, ok := parseNetrcMachine(string(data), PackageFirewallHost)
	if !ok {
		return info
	}
	info.MachineFound = true
	info.OrgID = orgID
	info.APIKey = apiKey
	if orgID == "" || apiKey == "" {
		info.Err = fmt.Errorf("netrc entry for %s is missing login or password", PackageFirewallHost)
	}
	return info
}

// LoadNetrcCredentials loads Package Firewall credentials from netrc as Direct API Key auth.
func LoadNetrcCredentials() (*Credentials, error) {
	info := NetrcStatus()
	if info.Err != nil {
		return nil, info.Err
	}
	if !info.Found {
		return nil, fmt.Errorf("netrc file not found")
	}
	if !info.MachineFound {
		return nil, fmt.Errorf("netrc file %s has no machine %s entry", info.Path, PackageFirewallHost)
	}
	if info.OrgID == "" || info.APIKey == "" {
		return nil, fmt.Errorf("netrc entry for %s is missing login or password", PackageFirewallHost)
	}
	return &Credentials{
		OrgID:  info.OrgID,
		APIKey: info.APIKey,
		Method: DirectAPIKey,
	}, nil
}

func checkNetrcPermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%s permissions are too open; run chmod 600 %s", path, path)
	}
	return nil
}

func parseNetrcMachine(data, machine string) (login, password string, ok bool) {
	tokens := netrcTokens(data)
	for i := 0; i < len(tokens); i++ {
		if tokens[i] != "machine" || i+1 >= len(tokens) || tokens[i+1] != machine {
			continue
		}
		ok = true
		for j := i + 2; j < len(tokens); j++ {
			switch tokens[j] {
			case "machine", "default":
				return login, password, true
			case "login":
				if j+1 < len(tokens) {
					login = tokens[j+1]
					j++
				}
			case "password":
				if j+1 < len(tokens) {
					password = tokens[j+1]
					j++
				}
			}
		}
		return login, password, true
	}
	return "", "", false
}

func netrcTokens(data string) []string {
	var tokens []string
	for _, line := range strings.Split(data, "\n") {
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		tokens = append(tokens, strings.Fields(line)...)
	}
	return tokens
}
