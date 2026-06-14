package secretscan

import (
	"strings"
	"testing"
)

func TestExtractStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		min      int
		contains []string
		excludes []string
	}{
		{
			name:     "basic printable run",
			input:    "AKIAIOSFODNN7EXAMPLE\x00\x00\x01\x02some noise here",
			min:      4,
			contains: []string{"AKIAIOSFODNN7EXAMPLE", "some noise here"},
		},
		{
			name:     "minimum length filter",
			input:    "ab\x00abcdef",
			min:      4,
			contains: []string{"abcdef"},
			excludes: []string{"ab\n"},
		},
		{
			name:     "tab/CR/LF as terminators",
			input:    "line1\nline2\ttabbed\rwindows",
			min:      4,
			contains: []string{"line1", "line2", "tabbed", "windows"},
		},
		{
			name:     "high bytes preserved (latin1 style)",
			input:    "hello\xe9world",
			min:      4,
			contains: []string{"hello", "world"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractStrings([]byte(tc.input), tc.min)
			for _, want := range tc.contains {
				if !strings.Contains(got, want) {
					t.Errorf("ExtractStrings missing %q in output:\n%s", want, got)
				}
			}
			for _, noWant := range tc.excludes {
				if strings.Contains(got, noWant) {
					t.Errorf("ExtractStrings unexpectedly contains %q:\n%s", noWant, got)
				}
			}
		})
	}
}

func TestIsBinary(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "empty", data: nil, want: false},
		{name: "text", data: []byte("hello world\nthis is plain text\n"), want: false},
		{name: "binary nul byte", data: []byte{0x7f, 'E', 'L', 'F', 0, 1, 2, 3}, want: true},
		{name: "compressed-looking", data: []byte{0x78, 0x9c, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, want: true},
		{name: "low printable ratio", data: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsBinary(tc.data); got != tc.want {
				t.Errorf("IsBinary(%x) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}

func TestInspectBinary_JPEGSmoke(t *testing.T) {
	// Tiny JPEG: SOI + minimal APP1 EXIF + EOI.
	// We don't expect the parser to extract anything meaningful, but the
	// call must not panic and must return a sane insight.
	data := []byte{
		0xff, 0xd8, 0xff, 0xe1,
		0x00, 0x10, // segment length
		'E', 'x', 'i', 'f', 0x00, 0x00, // Exif header
		'M', 'M', 0x00, '*', 0x00, 0x00, 0x00, 0x08, // TIFF header
		0x00, 0x00, // 0 IFDs
	}
	insight := InspectBinary("photo.jpg", data, InspectOptions{IncludeStrings: true, MinStringLength: 4})
	if !strings.HasPrefix(insight.StringsKey, PathBinaryPrefix) {
		t.Errorf("expected StringsKey to begin with %q, got %q", PathBinaryPrefix, insight.StringsKey)
	}
	if !strings.HasSuffix(insight.StringsKey, "photo.jpg") {
		t.Errorf("expected StringsKey to end with photo.jpg, got %q", insight.StringsKey)
	}
}
