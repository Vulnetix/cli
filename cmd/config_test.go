package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnetix/cli/v3/internal/display"
)

func TestBuildPackageFirewallRequestDispatch(t *testing.T) {
	tests := []struct {
		name string
		args []string
		kind packageFirewallRequestKind
		err  string
	}{
		{
			name: "policy form",
			args: nil,
			kind: packageFirewallPolicyRequest,
		},
		{
			name: "mirror form",
			args: []string{"npm", "https://registry.npmjs.org"},
			kind: packageFirewallMirrorRequest,
		},
		{
			name: "one positional rejected",
			args: []string{"npm"},
			err:  "requires both <ecosystem> and <url>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newConfigSetPackageFirewallCommand()
			got, err := buildPackageFirewallRequest(cmd, tt.args)
			if tt.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.kind, got.Kind)
		})
	}
}

func TestBuildPackageFirewallRequestRejectsConflictingMirrorState(t *testing.T) {
	cmd := newConfigSetPackageFirewallCommand()
	require.NoError(t, cmd.Flags().Set("enable", "true"))
	require.NoError(t, cmd.Flags().Set("disable", "true"))

	_, err := buildPackageFirewallRequest(cmd, []string{"npm", "https://registry.npmjs.org"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestBuildPackageFirewallRequestRejectsMixedFlags(t *testing.T) {
	t.Run("policy flag with mirror args", func(t *testing.T) {
		cmd := newConfigSetPackageFirewallCommand()
		require.NoError(t, cmd.Flags().Set("cvss-threshold", "7"))

		_, err := buildPackageFirewallRequest(cmd, []string{"npm", "https://registry.npmjs.org"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only valid when setting org-wide")
	})

	t.Run("mirror flag with policy args", func(t *testing.T) {
		cmd := newConfigSetPackageFirewallCommand()
		require.NoError(t, cmd.Flags().Set("priority", "1"))

		_, err := buildPackageFirewallRequest(cmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only valid when setting a package-firewall mirror")
	})
}

func TestBuildPackageFirewallRequestValidatesRanges(t *testing.T) {
	tests := []struct {
		name  string
		flag  string
		value string
		err   string
	}{
		{name: "cvss low", flag: "cvss-threshold", value: "-0.1", err: "between 0 and 10"},
		{name: "cvss high", flag: "cvss-threshold", value: "10.1", err: "between 0 and 10"},
		{name: "epss high", flag: "epss-threshold", value: "1.1", err: "between 0 and 1"},
		{name: "cess high", flag: "cess-threshold", value: "10.1", err: "between 0 and 10"},
		{name: "cooldown negative", flag: "cooldown-days", value: "-1", err: "greater than or equal to 0"},
		{name: "lag negative", flag: "version-lag", value: "-1", err: "greater than or equal to 0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newConfigSetPackageFirewallCommand()
			require.NoError(t, cmd.Flags().Set(tt.flag, tt.value))

			_, err := buildPackageFirewallRequest(cmd, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.err)
		})
	}
}

func TestBuildPackageFirewallPolicyRequestOnlyChangedFlagsPopulatePointers(t *testing.T) {
	cmd := newConfigSetPackageFirewallCommand()
	require.NoError(t, cmd.Flags().Set("cvss-threshold", "7.5"))
	require.NoError(t, cmd.Flags().Set("block-malware", "false"))
	require.NoError(t, cmd.Flags().Set("block-kev", "true"))
	require.NoError(t, cmd.Flags().Set("cooldown-days", "3"))

	got, err := buildPackageFirewallRequest(cmd, nil)
	require.NoError(t, err)
	require.Equal(t, packageFirewallPolicyRequest, got.Kind)

	require.NotNil(t, got.Config.CvssThreshold)
	assert.Equal(t, 7.5, *got.Config.CvssThreshold)
	require.NotNil(t, got.Config.BlockMalware)
	assert.False(t, *got.Config.BlockMalware)
	require.NotNil(t, got.Config.BlockKev)
	assert.True(t, *got.Config.BlockKev)
	require.NotNil(t, got.Config.CooldownDays)
	assert.Equal(t, 3, *got.Config.CooldownDays)

	assert.Nil(t, got.Config.EpssThreshold)
	assert.Nil(t, got.Config.CessThreshold)
	assert.Nil(t, got.Config.BlockEol)
	assert.Nil(t, got.Config.BlockWeaponized)
	assert.Nil(t, got.Config.BlockActive)
	assert.Nil(t, got.Config.BlockPoc)
	assert.Nil(t, got.Config.BlockBadActors)
	assert.Nil(t, got.Config.VersionLag)
}

func TestBuildPackageFirewallPolicyRequestAcceptsSpaceSeparatedBoolValue(t *testing.T) {
	cmd := newConfigSetPackageFirewallCommand()
	require.NoError(t, cmd.Flags().Parse([]string{
		"--cvss-threshold", "7",
		"--block-malware", "false",
		"--cooldown-days", "3",
	}))

	got, err := buildPackageFirewallRequest(cmd, cmd.Flags().Args())
	require.NoError(t, err)
	require.Equal(t, packageFirewallPolicyRequest, got.Kind)
	require.NotNil(t, got.Config.BlockMalware)
	assert.False(t, *got.Config.BlockMalware)
	assert.Nil(t, got.Mirror.IsActive)
}

func TestBuildPackageFirewallMirrorRequestOnlyChangedFlagsPopulatePointers(t *testing.T) {
	t.Run("priority and disable", func(t *testing.T) {
		cmd := newConfigSetPackageFirewallCommand()
		require.NoError(t, cmd.Flags().Set("priority", "4"))
		require.NoError(t, cmd.Flags().Set("disable", "true"))

		got, err := buildPackageFirewallRequest(cmd, []string{"npm", "https://registry.npmjs.org"})
		require.NoError(t, err)
		require.Equal(t, packageFirewallMirrorRequest, got.Kind)

		assert.Equal(t, "npm", got.Mirror.Ecosystem)
		assert.Equal(t, "https://registry.npmjs.org", got.Mirror.URL)
		require.NotNil(t, got.Mirror.Priority)
		assert.Equal(t, 4, *got.Mirror.Priority)
		require.NotNil(t, got.Mirror.IsActive)
		assert.False(t, *got.Mirror.IsActive)
	})

	t.Run("omitted mirror flags stay nil", func(t *testing.T) {
		cmd := newConfigSetPackageFirewallCommand()

		got, err := buildPackageFirewallRequest(cmd, []string{"pypi", "https://pypi.org/simple"})
		require.NoError(t, err)
		assert.Nil(t, got.Mirror.Priority)
		assert.Nil(t, got.Mirror.IsActive)
	})
}

func TestRenderPackageFirewallGetPopulated(t *testing.T) {
	ctx := display.New(display.ModeText, false)
	data := map[string]any{
		"config": map[string]any{
			"cvssThreshold":   7.5,
			"epssThreshold":   0.4,
			"cessThreshold":   0.0,
			"blockMalware":    true,
			"blockEol":        false,
			"blockKev":        true,
			"blockWeaponized": false,
			"blockActive":     false,
			"blockPoc":        false,
			"blockBadActors":  true,
			"cooldownDays":    float64(7),
			"versionLag":      float64(2),
		},
		"mirrors": []any{
			map[string]any{"ecosystem": "npm", "url": "https://b.example", "priority": float64(1), "isActive": false},
			map[string]any{"ecosystem": "go", "url": "https://proxy.golang.org", "priority": float64(0), "isActive": true},
			map[string]any{"ecosystem": "npm", "url": "https://a.example", "priority": float64(0), "isActive": true},
		},
	}

	out := renderPackageFirewallGet(ctx, data)

	assert.Contains(t, out, "Package Firewall policy")
	assert.Contains(t, out, "CVSS threshold")
	assert.Contains(t, out, "7.5")
	assert.Contains(t, out, "Block malware")
	assert.Contains(t, out, "Cooldown days")
	// Mirrors table present with all three rows.
	assert.Contains(t, out, "Mirrors")
	assert.Contains(t, out, "https://proxy.golang.org")
	assert.Contains(t, out, "https://a.example")
	assert.Contains(t, out, "https://b.example")
	// go sorts before npm; within npm, priority 0 (a.example) precedes priority 1 (b.example).
	goIdx := indexOf(out, "https://proxy.golang.org")
	aIdx := indexOf(out, "https://a.example")
	bIdx := indexOf(out, "https://b.example")
	assert.True(t, goIdx < aIdx && aIdx < bIdx, "mirrors should be ordered by ecosystem then priority")
}

func TestRenderPackageFirewallGetEmpty(t *testing.T) {
	ctx := display.New(display.ModeText, false)
	out := renderPackageFirewallGet(ctx, map[string]any{"config": nil, "mirrors": []any{}})
	assert.Contains(t, out, "No policy configured")
	assert.Contains(t, out, "No mirrors configured")
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
