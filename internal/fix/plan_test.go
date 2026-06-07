package fix

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulnetix/cli/v3/internal/scan"
)

func TestEditableManifestForMapsLockToSiblingManifest(t *testing.T) {
	groups := []scan.ManifestGroup{{Files: []string{"package.json", "package-lock.json"}}}
	require.Equal(t, "package.json", editableManifestFor("package-lock.json", groups))
	require.Equal(t, "package.json", editableManifestFor("package.json", groups))
}

func TestEditableManifestForLeavesLockWhenNoManifest(t *testing.T) {
	groups := []scan.ManifestGroup{{Files: []string{"package-lock.json"}}}
	// No sibling manifest to retarget to: keep the original.
	require.Equal(t, "package-lock.json", editableManifestFor("package-lock.json", groups))
}

func TestIsLockfile(t *testing.T) {
	require.True(t, isLockfile("package-lock.json"))
	require.True(t, isLockfile("a/b/yarn.lock"))
	require.False(t, isLockfile("package.json"))
	require.False(t, isLockfile("pom.xml"))
}
