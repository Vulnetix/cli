package filecache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPrune(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	for i, name := range []string{"a.json", "b.json", "c.json", "d.json", "e.json"} {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("{}"), 0o600))
		require.NoError(t, os.Chtimes(p, now, now.Add(-time.Duration(i)*time.Hour)))
	}
	Prune(dir, 3)
	left, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range left {
		names = append(names, e.Name())
	}
	require.ElementsMatch(t, []string{"a.json", "b.json", "c.json"}, names, "the newest three are kept")
}

func TestWriteIsAtomicAndPerRoot(t *testing.T) {
	dir := t.TempDir()
	a, b := Path(dir, "/repo", "k"), Path(dir, "/other", "k")
	require.NotEqual(t, a, b, "each scanned directory has its own documents")
	Write(a, []byte(`{"v":1}`))
	Write(a, []byte(`{"v":2}`))
	got, err := os.ReadFile(a)
	require.NoError(t, err)
	require.Equal(t, `{"v":2}`, string(got))
	left, err := os.ReadDir(filepath.Dir(a))
	require.NoError(t, err)
	require.Len(t, left, 1, "no temporary file is left behind")
}

func TestContentSHA(t *testing.T) {
	require.Equal(t, ContentSHA([]byte("x")), ContentSHA([]byte("x")))
	require.NotEqual(t, ContentSHA([]byte("x")), ContentSHA([]byte("y")))
}
