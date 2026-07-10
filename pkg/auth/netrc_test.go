package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseNetrcMachine(t *testing.T) {
	data := `
machine example.com
  login someone
  password nope

machine packages.vulnetix.com
  login 123e4567-e89b-12d3-a456-426614174000
  password abcdef
`
	login, password, ok := parseNetrcMachine(data, PackageFirewallHost)
	if !ok {
		t.Fatal("expected packages.vulnetix.com entry")
	}
	if login != "123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("login = %q", login)
	}
	if password != "abcdef" {
		t.Fatalf("password = %q", password)
	}
}

func TestLoadCredentials_FromNetrc(t *testing.T) {
	t.Setenv("VULNETIX_API_KEY", "")
	t.Setenv("VULNETIX_ORG_ID", "")
	t.Setenv("VVD_ORG", "")
	t.Setenv("VVD_SECRET", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(home); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	path := filepath.Join(home, ".netrc")
	if runtime.GOOS == "windows" {
		path = filepath.Join(home, "_netrc")
	}
	if err := os.WriteFile(path, []byte("machine packages.vulnetix.com login org password key\n"), 0600); err != nil {
		t.Fatalf("write netrc: %v", err)
	}

	creds, err := LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if creds.Method != DirectAPIKey || creds.OrgID != "org" || creds.APIKey != "key" {
		t.Fatalf("unexpected creds: %+v", creds)
	}
}

func TestLoadNetrcCredentialsRejectsOpenPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows _netrc permissions are not chmod based")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	path := filepath.Join(home, ".netrc")
	if err := os.WriteFile(path, []byte("machine packages.vulnetix.com login org password key\n"), 0644); err != nil {
		t.Fatalf("write netrc: %v", err)
	}

	if _, err := LoadNetrcCredentials(); err == nil {
		t.Fatal("expected open permissions to be rejected")
	}
}
