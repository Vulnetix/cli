package testutils

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// CaptureStdout captures the output of stdout during a test.
// It returns the captured string and a function to restore stdout.
func CaptureStdout(t *testing.T) (string, func()) {
	t.Helper()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outC <- buf.String()
	}()

	return "", func() {
		t.Helper()
		w.Close()
		os.Stdout = oldStdout
		captured := <-outC
		// Trim trailing newline if present, as Println adds one
		if strings.HasSuffix(captured, "\n") {
			captured = captured[:len(captured)-1]
		}
		t.Logf("Captured stdout: %s", captured)
	}
}

// AssertError asserts that an error is not nil and contains the expected message.
func AssertError(t *testing.T, err error, expectedMsg string) {
	t.Helper()
	if err == nil {
		t.Fatalf("Expected an error, but got nil")
	}
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Fatalf("Expected error message to contain '%s', but got '%s'", expectedMsg, err.Error())
	}
}

// AssertNoError asserts that an error is nil.
func AssertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}
}
