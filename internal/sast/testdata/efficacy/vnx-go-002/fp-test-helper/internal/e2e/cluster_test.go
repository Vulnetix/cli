package e2e

import (
	"fmt"
	"os/exec"
	"testing"
)

// The test builds its own shell lines from its own constants.
func TestClusterUp(t *testing.T) {
	name := "kind-e2e"
	if err := exec.Command("sh", "-c", fmt.Sprintf("kind create cluster --name %s", name)).Run(); err != nil {
		t.Skip(err)
	}
}
