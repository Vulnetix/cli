package cmd

import (
	"strings"
	"testing"
)

func TestUpsertNetrcMachine(t *testing.T) {
	existing := "machine example.com\nlogin old\npassword old\n\nmachine packages.vulnetix.com\nlogin stale\npassword stale\n"
	got := upsertNetrcMachine(existing, "packages.vulnetix.com", "org", "key")

	if strings.Contains(got, "stale") {
		t.Fatalf("stale entry was not replaced:\n%s", got)
	}
	if !strings.Contains(got, "machine example.com") {
		t.Fatalf("unrelated entry was not preserved:\n%s", got)
	}
	if !strings.Contains(got, "machine packages.vulnetix.com\nlogin org\npassword key\n") {
		t.Fatalf("new entry missing:\n%s", got)
	}
}

func TestUpsertManagedBlock(t *testing.T) {
	existing := "before\n\n# Vulnetix Package Firewall\nold\n# End Vulnetix Package Firewall\n\nafter\n"
	block := shellEnvBlock("sh", "https://packages.vulnetix.com")
	got := upsertManagedBlock(existing, block)

	if strings.Contains(got, "\nold\n") {
		t.Fatalf("old managed block remained:\n%s", got)
	}
	if !strings.Contains(got, "export GOPROXY=\"https://packages.vulnetix.com\"") {
		t.Fatalf("new GOPROXY missing:\n%s", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Fatalf("surrounding content not preserved:\n%s", got)
	}
}

func TestUpsertGoEnvValues(t *testing.T) {
	existing := "FOO=bar\nGOPROXY=https://old.example\nexport GOAUTH=off\n"
	body := "GOPROXY=https://packages.vulnetix.com\nGOAUTH=netrc\n"
	got := upsertGoEnvValues(existing, body)

	if strings.Contains(got, "old.example") || strings.Contains(got, "GOAUTH=off") {
		t.Fatalf("old Go env values remained:\n%s", got)
	}
	if !strings.Contains(got, "FOO=bar") {
		t.Fatalf("unrelated env was not preserved:\n%s", got)
	}
	if !strings.Contains(got, body) {
		t.Fatalf("new Go env body missing:\n%s", got)
	}
}
