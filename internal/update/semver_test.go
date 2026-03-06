package update

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input   string
		want    Version
		wantErr bool
	}{
		{"1.0.0", Version{1, 0, 0, ""}, false},
		{"v1.2.3", Version{1, 2, 3, ""}, false},
		{"0.0.1-dev", Version{0, 0, 1, "dev"}, false},
		{"v2.10.0-rc1", Version{2, 10, 0, "rc1"}, false},
		{"bad", Version{}, true},
		{"1.2", Version{}, true},
		{"1.2.3.4", Version{}, true},
		{"v.1.2", Version{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseVersion(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVersionString(t *testing.T) {
	assert.Equal(t, "1.2.3", Version{1, 2, 3, ""}.String())
	assert.Equal(t, "0.0.1-dev", Version{0, 0, 1, "dev"}.String())
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"2.0.0", "1.9.9", 1},
		{"0.1.0", "0.0.9", 1},
		{"1.0.0-dev", "1.0.0", -1},   // pre-release < release
		{"1.0.0", "1.0.0-dev", 1},    // release > pre-release
		{"1.0.0-alpha", "1.0.0-beta", -1}, // lexicographic
		{"1.0.0-dev", "1.0.0-dev", 0},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			a, err := ParseVersion(tt.a)
			require.NoError(t, err)
			b, err := ParseVersion(tt.b)
			require.NoError(t, err)
			assert.Equal(t, tt.want, a.Compare(b))
		})
	}
}

func TestIsNewerThan(t *testing.T) {
	a, _ := ParseVersion("1.1.0")
	b, _ := ParseVersion("1.0.0")
	assert.True(t, a.IsNewerThan(b))
	assert.False(t, b.IsNewerThan(a))
	assert.False(t, a.IsNewerThan(a))
}
