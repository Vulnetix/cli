package scan

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// writeELFFixture writes a file whose first bytes are the ELF magic. It is not a
// loadable object — analyzeBinary records the parse error and still reports size,
// hashes and path, which is exactly the shape this test needs.
func writeELFFixture(t *testing.T, path string, filler byte, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, size)
	copy(body, []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00})
	for i := 8; i < len(body); i++ {
		body[i] = filler
	}
	if err := os.WriteFile(path, body, 0o755); err != nil {
		t.Fatal(err)
	}
}

func binaryFixtureTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	// Names deliberately unsorted relative to walk order, and one nested dir, so
	// an ordering regression shows up.
	writeELFFixture(t, filepath.Join(root, "zeta"), 'z', 4096)
	writeELFFixture(t, filepath.Join(root, "alpha"), 'a', 8192)
	writeELFFixture(t, filepath.Join(root, "nested", "beta"), 'b', 2048)
	writeELFFixture(t, filepath.Join(root, "nested", "deep", "gamma"), 'g', 1024)
	// Non-ELF files must be ignored entirely.
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestScanContainerFilesystemParallelMatchesSerial pins the contract that made
// the fan-out safe to add: concurrency changes timing only. Results must be
// identical to the single-worker path, including order.
func TestScanContainerFilesystemParallelMatchesSerial(t *testing.T) {
	root := binaryFixtureTree(t)

	serial := ScanContainerFilesystemWithOptions(root, BinaryScanOptions{Concurrency: 1})
	parallel := ScanContainerFilesystemWithOptions(root, BinaryScanOptions{Concurrency: 4})

	if serial.ELFCount != 4 {
		t.Fatalf("ELFCount = %d, want 4 (non-ELF files must be skipped)", serial.ELFCount)
	}
	if serial.ELFCount != parallel.ELFCount || serial.Total != parallel.Total {
		t.Fatalf("counts differ: serial=%d/%d parallel=%d/%d",
			serial.Total, serial.ELFCount, parallel.Total, parallel.ELFCount)
	}
	if len(serial.Binaries) != len(parallel.Binaries) {
		t.Fatalf("binary counts differ: %d vs %d", len(serial.Binaries), len(parallel.Binaries))
	}
	for i := range serial.Binaries {
		if !reflect.DeepEqual(serial.Binaries[i], parallel.Binaries[i]) {
			t.Fatalf("binary %d differs:\n serial   = %+v\n parallel = %+v",
				i, serial.Binaries[i], parallel.Binaries[i])
		}
	}
	if !reflect.DeepEqual(serial.Errors, parallel.Errors) {
		t.Fatalf("errors differ:\n serial   = %v\n parallel = %v", serial.Errors, parallel.Errors)
	}
}

// TestScanContainerFilesystemOrderIsDeterministic runs the fan-out repeatedly:
// the worker that finishes first must not influence the output order, because
// downstream SARIF/SBOM artefacts are diffed between runs.
func TestScanContainerFilesystemOrderIsDeterministic(t *testing.T) {
	root := binaryFixtureTree(t)

	want := pathsOf(ScanContainerFilesystemWithOptions(root, BinaryScanOptions{Concurrency: 4}))
	if len(want) != 4 {
		t.Fatalf("got %d binaries, want 4", len(want))
	}
	for range 8 {
		got := pathsOf(ScanContainerFilesystemWithOptions(root, BinaryScanOptions{Concurrency: 4}))
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("order changed between runs:\n first = %v\n later = %v", want, got)
		}
	}
	// Walk order is lexical per directory, so the nested entries follow their
	// parent — assert the exact sequence rather than just stability.
	expect := []string{
		filepath.Join(root, "alpha"),
		filepath.Join(root, "nested", "beta"),
		filepath.Join(root, "nested", "deep", "gamma"),
		filepath.Join(root, "zeta"),
	}
	if !reflect.DeepEqual(want, expect) {
		t.Fatalf("walk order = %v, want %v", want, expect)
	}
}

// TestScanContainerFilesystemTinyByteBudget covers the semaphore's escape hatch:
// a file bigger than the whole budget must still be analysed (alone) instead of
// deadlocking the pool.
func TestScanContainerFilesystemTinyByteBudget(t *testing.T) {
	root := binaryFixtureTree(t)

	done := make(chan *ScanResult, 1)
	go func() {
		done <- ScanContainerFilesystemWithOptions(root, BinaryScanOptions{
			Concurrency: 4,
			ByteBudget:  16, // smaller than every fixture
		})
	}()
	select {
	case res := <-done:
		if len(res.Binaries) != 4 {
			t.Fatalf("got %d binaries, want 4", len(res.Binaries))
		}
	case <-t.Context().Done():
		t.Fatal("scan did not finish: byte budget deadlocked the pool")
	}
}

func TestScanContainerFilesystemDefaultsMatchExplicitOptions(t *testing.T) {
	root := binaryFixtureTree(t)
	if !reflect.DeepEqual(
		pathsOf(ScanContainerFilesystem(root)),
		pathsOf(ScanContainerFilesystemWithOptions(root, BinaryScanOptions{})),
	) {
		t.Fatal("ScanContainerFilesystem must equal the zero-value options path")
	}
}

func TestByteBudgetAdmitsOversizedRequest(t *testing.T) {
	b := newByteBudget(100)
	b.acquire(40)
	// 400 > limit: allowed only once the budget is idle, and then on its own.
	released := make(chan struct{})
	go func() {
		b.acquire(400)
		close(released)
	}()
	b.release(40)
	select {
	case <-released:
	case <-t.Context().Done():
		t.Fatal("oversized acquire never admitted")
	}
	b.release(400)
	if b.inUse != 0 {
		t.Fatalf("inUse = %d, want 0", b.inUse)
	}
}

func pathsOf(res *ScanResult) []string {
	out := make([]string, 0, len(res.Binaries))
	for _, b := range res.Binaries {
		out = append(out, b.Path)
	}
	return out
}
