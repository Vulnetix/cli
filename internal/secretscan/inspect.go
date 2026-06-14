package secretscan

import (
	"path/filepath"
	"strings"
)

// SyntheticPathPrefixes are the prefixes we use when injecting non-text file
// content into the secrets scan input. Anything matching a rule that begins
// with one of these came from a binary, EXIF, or git history source — not
// from the live working tree.
//
// Rules can use these prefixes to filter ("only fire on real source code") or
// to enrich reporting ("this came from .git history of a deleted file").
const (
	// PathBinaryPrefix marks a file path whose value is the printable-strings
	// extraction from a binary file.
	PathBinaryPrefix = "__binary_strings__/"
	// PathEXIFPrefix marks a file path whose value is the EXIF/IPTC/XMP
	// metadata of an image file.
	PathEXIFPrefix = "__exif__/"
	// PathGitHistoryPrefix marks a file path whose value is the contents of
	// a file as it appeared in a past git commit.
	PathGitHistoryPrefix = "__git_history__/"
)

// InspectOptions configures InspectBinary.
type InspectOptions struct {
	// IncludeStrings controls whether printable strings are extracted from
	// the binary. When false, only EXIF (for image files) is extracted.
	IncludeStrings bool
	// MinStringLength is the minimum length of a printable run to surface
	// from strings extraction. Defaults to 4 (unix `strings` default).
	MinStringLength int
}

// BinaryInsight holds the synthetic file-content values that InspectBinary
// produced for a given file. Both fields are optional and may be empty.
//
// The keys are the synthetic paths that should be used in the secrets scan
// input.file_contents map. They are constructed from the original file path
// so that rules can correlate the artifact back to the source file.
type BinaryInsight struct {
	// StringsKey → printable-strings extraction (newlines joined).
	StringsKey string
	StringsVal string
	// EXIFKey → EXIF/IPTC/XMP key=value extraction.
	EXIFKey string
	EXIFVal string
	// HadEXIF reports whether the file actually carried EXIF metadata.
	HadEXIF bool
}

// InspectBinary analyses a binary file and returns the synthetic file-content
// entries that should be added to the secrets scan input. The file extension
// is used to decide whether EXIF extraction applies — only images and TIFF
// containers are processed.
func InspectBinary(path string, data []byte, opts InspectOptions) BinaryInsight {
	var insight BinaryInsight
	if opts.MinStringLength < 1 {
		opts.MinStringLength = StringMin
	}
	if opts.IncludeStrings {
		insight.StringsKey = PathBinaryPrefix + filepath.ToSlash(path)
		insight.StringsVal = ExtractStrings(data, opts.MinStringLength)
	}
	if isImagePath(path) {
		if exif, ok := ExtractEXIF(data); ok && exif.Raw != "" {
			insight.EXIFKey = PathEXIFPrefix + filepath.ToSlash(path)
			insight.EXIFVal = exif.Raw
			insight.HadEXIF = true
		}
	}
	return insight
}

// isImagePath returns true for JPEG, TIFF, PNG, HEIC, WebP, GIF and PSD
// file extensions. EXIF is only formally carried by JPEG and TIFF, but
// surfacing the string extraction of any image format is worthwhile.
func isImagePath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".jpg", ".jpeg", ".jpe", ".jfif",
		".tif", ".tiff",
		".heic", ".heif",
		".webp",
		".png",
		".gif",
		".psd",
		".dng", ".cr2", ".nef", ".arw", ".orf", ".rw2":
		return true
	}
	return false
}
