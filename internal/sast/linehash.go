package sast

// primaryLocationLineHash, ported from github/codeql-action src/fingerprints.ts.
//
// GitHub code scanning tracks an alert across commits by the result's
// partialFingerprints.primaryLocationLineHash. codeql-action's upload step
// computes it when a SARIF file lacks it, but a SARIF posted straight to the
// REST API (`vulnetix gha publish code-scanning`) gets none, and without it a
// line moving by one opens a new alert and closes the old one. So the value is
// computed here, byte for byte as codeql-action computes it: the golden vectors
// in linehash_test.go are codeql-action's own.
//
// The algorithm: a rolling polynomial hash (base 37, signed 64-bit arithmetic
// that wraps) over a window of the next 100 characters from the start of each
// line, skipping spaces and tabs and normalising \r, \n and \r\n to \n. A
// sentinel (65535) marks the end of the file, followed by enough zeros to fill
// the window. Characters are UTF-16 code units, as JavaScript's charCodeAt
// reads them. Identical hashes in one file are numbered (hash:1, hash:2).

import (
	"os"
	"strconv"
	"unicode/utf16"
)

const (
	lineHashBlockSize = 100
	lineHashMod       = int64(37)
	lineHashEOF       = 65535
)

// lineHashFirstMod is 37^100 with wrapping signed 64-bit multiplication.
var lineHashFirstMod = func() int64 {
	m := int64(1)
	for i := 0; i < lineHashBlockSize; i++ {
		m *= lineHashMod
	}
	return m
}()

// LineHashes returns the primaryLocationLineHash of every line of content,
// indexed by line number minus one. An empty input has one line.
func LineHashes(content []byte) []string {
	var (
		window      [lineHashBlockSize]int64
		lineNumbers [lineHashBlockSize]int
		hashRaw     int64
		index       int
		lineNumber  int
		lineStart   = true
		prevCR      bool
		counts      = map[string]int{}
		out         []string
	)
	for i := range lineNumbers {
		lineNumbers[i] = -1
	}

	outputHash := func() {
		v := strconv.FormatUint(uint64(hashRaw), 16)
		counts[v]++
		ln := lineNumbers[index]
		for len(out) < ln {
			out = append(out, "")
		}
		out[ln-1] = v + ":" + strconv.Itoa(counts[v])
		lineNumbers[index] = -1
	}
	updateHash := func(current int64) {
		begin := window[index]
		window[index] = current
		hashRaw = lineHashMod*hashRaw + current - lineHashFirstMod*begin
		index = (index + 1) % lineHashBlockSize
	}
	process := func(current int64) {
		if current == ' ' || current == '\t' || (prevCR && current == '\n') {
			prevCR = false
			return
		}
		if current == '\r' {
			current = '\n'
			prevCR = true
		} else {
			prevCR = false
		}
		if lineNumbers[index] != -1 {
			outputHash()
		}
		if lineStart {
			lineStart = false
			lineNumber++
			lineNumbers[index] = lineNumber
		}
		if current == '\n' {
			lineStart = true
		}
		updateHash(current)
	}

	for _, u := range utf16.Encode([]rune(string(content))) {
		process(int64(u))
	}
	process(lineHashEOF)
	for i := 0; i < lineHashBlockSize; i++ {
		if lineNumbers[index] != -1 {
			outputHash()
		}
		updateHash(0)
	}
	return out
}

// LineHashCache hashes each file once, however many results point into it.
type LineHashCache struct {
	files map[string][]string
}

// NewLineHashCache returns an empty cache.
func NewLineHashCache() *LineHashCache {
	return &LineHashCache{files: map[string][]string{}}
}

// Hash returns the primaryLocationLineHash for line (1-based; 0 means the
// whole file, hashed at line 1 as codeql-action does) of the file at path, or
// "" when the file cannot be read or has no such line.
func (c *LineHashCache) Hash(path string, line int) string {
	if c == nil || path == "" {
		return ""
	}
	hashes, ok := c.files[path]
	if !ok {
		data, err := os.ReadFile(path)
		if err == nil {
			hashes = LineHashes(data)
		}
		c.files[path] = hashes
	}
	if line <= 0 {
		line = 1
	}
	if line > len(hashes) {
		return ""
	}
	return hashes[line-1]
}
