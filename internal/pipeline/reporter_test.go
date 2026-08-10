package pipeline

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriterReporterOutput(t *testing.T) {
	var buf bytes.Buffer
	r := NewWriterReporter(&buf)

	r.Stage("Parsing 3 detected file(s)")
	r.Update(1, "Parsed 42 package(s)")
	r.Logf(LevelInfo, "Loaded %d rules", 1899)
	r.Logf(LevelWarn, "could not load SAST rules: %v", io.EOF)
	r.Complete("scan complete")

	out := buf.String()
	require.Contains(t, out, "Parsing 3 detected file(s)")
	require.Contains(t, out, "Parsed 42 package(s)")
	require.Contains(t, out, "Loaded 1899 rules")
	require.Contains(t, out, "warning: could not load SAST rules: EOF")
	require.Contains(t, out, "scan complete")
}

func TestReporterSkipsEmptyStages(t *testing.T) {
	// Update(done, "") is how the scan advances numeric progress without
	// changing the label. It must not emit a blank line.
	var buf bytes.Buffer
	r := NewWriterReporter(&buf)
	r.Stage("")
	r.Stage("   ")
	r.Update(2, "")
	require.Empty(t, buf.String())
}

func TestDegradationsAreRecordedAndSurfaced(t *testing.T) {
	// "No findings" and "did not look" must never be indistinguishable. Every
	// implementation keeps the ledger, including the one that discards output.
	for name, r := range map[string]Reporter{
		"writer":  NewWriterReporter(io.Discard),
		"discard": Discard(),
	} {
		t.Run(name, func(t *testing.T) {
			r.Degraded("412 file(s) were not content-scanned")
			r.Degraded("   ") // ignored
			r.Degraded("git history was not scanned: not a repository")

			require.Equal(t, []string{
				"412 file(s) were not content-scanned",
				"git history was not scanned: not a repository",
			}, r.Degradations())
		})
	}
}

func TestDegradationsSnapshotIsACopy(t *testing.T) {
	r := NewWriterReporter(io.Discard)
	r.Degraded("first")
	got := r.Degradations()
	r.Degraded("second")
	require.Equal(t, []string{"first"}, got, "an earlier snapshot must not grow underneath the caller")
	require.Len(t, r.Degradations(), 2)
}

func TestDegradationsEmptyIsNilNotEmptySlice(t *testing.T) {
	// The Result carries this straight into JSON output, where a nil elides the
	// key and an empty slice renders as [].
	require.Nil(t, Discard().Degradations())
}

func TestFinishHappensOnce(t *testing.T) {
	// runLocalScan defers Complete and also calls Complete/Fail on specific
	// paths (autofix dry run, autofix applied). The deferred call must not
	// overwrite an earlier outcome.
	var buf bytes.Buffer
	r := NewWriterReporter(&buf)
	r.Fail("failed")
	r.Complete("scan complete")
	out := buf.String()
	require.Contains(t, out, "failed")
	require.NotContains(t, out, "scan complete")
}

func TestReporterIsConcurrencySafe(t *testing.T) {
	// Scan stages fan out across goroutines, and the language server evaluates
	// shards in parallel. Run with -race.
	r := NewWriterReporter(io.Discard)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.Stage("stage")
			r.Update(i, "working")
			r.Logf(LevelWarn, "warn %d", i)
			r.Degraded("degraded")
			_ = r.Degradations()
		}(i)
	}
	wg.Wait()
	require.Len(t, r.Degradations(), 16)
	r.Complete("done")
}

func TestNilWriterDiscards(t *testing.T) {
	r := NewWriterReporter(nil)
	require.NotPanics(t, func() {
		r.Stage("x")
		r.Logf(LevelError, "y")
		r.Complete("z")
	})
	require.Equal(t, io.Discard, r.Writer())
}

func TestLevelString(t *testing.T) {
	require.Equal(t, "info", LevelInfo.String())
	require.Equal(t, "warning", LevelWarn.String())
	require.Equal(t, "error", LevelError.String())
	require.Equal(t, "info", Level(99).String())
}

func TestTerminalReporterIsSilentWhenSilenced(t *testing.T) {
	// --silent must not write a progress line, but degradations are still
	// recorded so the Result can report them.
	r := NewTerminalReporter("Scan", 7, true, false)
	r.Stage("Parsing")
	r.Update(1, "Parsed")
	r.Degraded("412 file(s) were not content-scanned")
	r.Complete("scan complete")

	require.Equal(t, []string{"412 file(s) were not content-scanned"}, r.Degradations())
}

func TestTerminalReporterSatisfiesReporter(t *testing.T) {
	var _ Reporter = NewTerminalReporter("Scan", 7, true, true)
	var _ Reporter = NewWriterReporter(io.Discard)
	var _ Reporter = Discard()
}

func TestWriterReporterLogfDoesNotDoubleNewline(t *testing.T) {
	// Callers must not append their own newline; assert the contract holds so a
	// stray one shows up here rather than as blank lines in scan output.
	var buf bytes.Buffer
	r := NewWriterReporter(&buf)
	r.Logf(LevelInfo, "one")
	r.Logf(LevelInfo, "two")
	require.Equal(t, "one\ntwo\n", buf.String())
	require.Equal(t, 2, strings.Count(buf.String(), "\n"))
}
