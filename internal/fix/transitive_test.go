package fix

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBestParentVersionFromNpmMetaFindsSmallestAdmittingSafeChild(t *testing.T) {
	meta := npmRegistryPackage{Versions: map[string]npmRegistryVersion{
		"1.0.0": {Dependencies: map[string]string{"child": "^1.0.0"}},
		"1.1.0": {Dependencies: map[string]string{"child": "^1.5.0"}},
		"2.0.0": {Dependencies: map[string]string{"child": "^2.0.0"}},
		"2.1.0": {Dependencies: map[string]string{"child": "^2.2.0"}},
	}}

	got := bestParentVersionFromNpmMeta(meta, "1.0.0", "child", "2.2.3")
	require.Equal(t, "2.0.0", got)
}

func TestBestParentVersionFromNpmMetaHonoursCurrentParentFloor(t *testing.T) {
	meta := npmRegistryPackage{Versions: map[string]npmRegistryVersion{
		"1.0.0": {Dependencies: map[string]string{"child": "^2.0.0"}},
		"1.1.0": {PeerDependencies: map[string]string{"child": "^2.0.0"}},
	}}

	got := bestParentVersionFromNpmMeta(meta, "1.1.0", "child", "2.2.3")
	require.Equal(t, "1.1.0", got)
}
