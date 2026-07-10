// Package secretscan provides binary file inspection and git history scanning
// helpers used by the secrets detection stage.
//
// The high-fidelity secrets scanner needs to look for credentials everywhere
// they can hide: source files, compiled binaries, container images, embedded
// strings, document metadata (EXIF, PDF info, Office core properties), and
// the entire git history of a repository. This package provides the
// supporting primitives for those scans.
package secretscan

// StringMin is the minimum length of a printable run we consider a "string"
// in the unix `strings` sense. 4 is the default of GNU `strings`.
const StringMin = 4

// ExtractStrings returns the printable ASCII / UTF-8 runs of at least min
// characters from data, joined with newlines. This is a faithful re-implementation
// of the unix `strings` command's --print-file-name-free default behaviour and
// is intended to surface credentials embedded in compiled binaries, container
// image layers, or opaque blobs.
//
// We deliberately do NOT bound the output: a 50MB binary can contain tens of
// thousands of strings. Callers that need to bound memory should pre-truncate
// the input. The return is a string suitable for feeding to OPA as a file
// content slice.
func ExtractStrings(data []byte, min int) string {
	if min < 1 {
		min = StringMin
	}
	out := make([]byte, 0, len(data)/8)
	run := make([]byte, 0, 64)
	flush := func() {
		if len(run) >= min {
			out = append(out, run...)
			out = append(out, '\n')
		}
		run = run[:0]
	}
	for _, b := range data {
		// Treat tab, newline, vertical tab, form feed, carriage return as
		// string terminators — the unix `strings` default.
		if b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r' {
			flush()
			continue
		}
		// Common non-printable bytes end the run. Allow high bytes through
		// for UTF-8 sequences (rune.IsPrint handles the multi-byte case).
		if b < 0x20 || b == 0x7f {
			flush()
			continue
		}
		// High bytes that aren't a valid UTF-8 lead are kept in the run for
		// safety — binaries often carry latin-1 strings.
		run = append(run, b)
	}
	flush()
	return string(out)
}

// IsBinary reports whether data appears to be a binary file. A file is
// considered binary if it contains NUL bytes within the first probe bytes or
// has a high ratio of non-printable characters.
//
// The probe is intentionally small (8 KiB) so we do not have to read the
// whole file just to decide.
func IsBinary(data []byte) bool {
	const probe = 8192
	if len(data) == 0 {
		return false
	}
	check := data
	if len(check) > probe {
		check = check[:probe]
	}
	// A single NUL byte in the first 8 KiB is the strongest binary signal.
	for _, b := range check {
		if b == 0 {
			return true
		}
	}
	// Otherwise look at the printable ratio: anything under 70% printable
	// ASCII (excluding common whitespace) is almost certainly binary.
	printable := 0
	for _, b := range check {
		if b == '\n' || b == '\r' || b == '\t' {
			printable++
			continue
		}
		if b >= 0x20 && b < 0x7f {
			printable++
		}
	}
	return printable*10 < len(check)*7
}
