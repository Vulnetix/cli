package cmd

import (
	"strings"
	"testing"

	"github.com/vulnetix/cli/v4/pkg/vdb"
)

// The server reports what it changed about an exemption request (an expiry
// shortened to the maximum window); the CLI must show it, not drop it.
func TestRenderJailExemptionShowsServerWarnings(t *testing.T) {
	out := renderJailExemption(&vdb.CliJailExemptResponse{
		Action:    "created",
		Exemption: &vdb.CliJailExemptionApplied{Uuid: "e-1"},
		Warnings:  []string{"expiry shortened to the 90 day maximum"},
	})
	if !strings.Contains(out, "  warning expiry shortened to the 90 day maximum") {
		t.Fatalf("warning not rendered:\n%s", out)
	}
	if out = renderJailExemption(&vdb.CliJailExemptResponse{Action: "created"}); strings.Contains(out, "warning") {
		t.Fatalf("no warnings expected:\n%s", out)
	}
}
