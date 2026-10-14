package extract

import "archive/zip"

// The old extractor did path := filepath.Join(dest, f.Name) and then
// os.Create(path) with no check: that was CVE-worthy.
func Count(r *zip.Reader) int {
	// target := filepath.Join(dst, hdr.Name)
	return len(r.File)
}
