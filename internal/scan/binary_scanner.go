package scan

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/glaslos/ssdeep"
	"github.com/glaslos/tlsh"
)

// ── Binary scan types ───────────────────────────────────────────────────

// BinaryHashes carries every hash computed for one ELF binary.
type BinaryHashes struct {
	SHA256    string `json:"sha256"`
	MD5       string `json:"md5"`
	SHA1      string `json:"sha1"`
	SSDEEP    string `json:"ssdeep,omitempty"`
	TLSH      string `json:"tlsh,omitempty"`
	SHA256Raw string `json:"sha256Raw,omitempty"`
	MD5Raw    string `json:"md5Raw,omitempty"`
	SHA1Raw   string `json:"sha1Raw,omitempty"`
}

// BinaryAnalysis is the complete local analysis of one ELF binary.
type BinaryAnalysis struct {
	Path         string         `json:"path"`
	Size         int64          `json:"size"`
	ModTime      int64          `json:"modTime,omitempty"`
	ELFType      string         `json:"elfType,omitempty"`
	ELFArch      string         `json:"elfArch,omitempty"`
	ELFOSABI     string         `json:"elfOSABI,omitempty"`
	Hashes       BinaryHashes   `json:"hashes"`
	Weaknesses   []string       `json:"weaknesses,omitempty"`
	Capabilities []string       `json:"capabilities,omitempty"`
	Strings      []string       `json:"strings,omitempty"`
	Exif         map[string]any `json:"exif,omitempty"`
	Error        string         `json:"error,omitempty"`
}

// BinaryResult is the wire shape sent to /v2/cli.analyze — BinaryAnalysis
// plus external lookup results.
type BinaryResult struct {
	Path          string               `json:"path"`
	Size          int64                `json:"size"`
	ELFType       string               `json:"elfType,omitempty"`
	ELFArch       string               `json:"elfArch,omitempty"`
	ELFOSABI      string               `json:"elfOSABI,omitempty"`
	Hashes        BinaryHashes         `json:"hashes"`
	Weaknesses    []string             `json:"weaknesses,omitempty"`
	Capabilities  []string             `json:"capabilities,omitempty"`
	Strings       []string             `json:"strings,omitempty"`
	Exif          map[string]any       `json:"exif,omitempty"`
	Hashlookup    *HashlookupResult    `json:"hashlookup,omitempty"`
	MalwareBazaar *MalwareBazaarResult `json:"malwareBazaar,omitempty"`
}

// ScanResult is the top-level result of a container filesystem scan.
type ScanResult struct {
	ScannerRunUUID string         `json:"scannerRunUuid,omitempty"`
	Path           string         `json:"path"`
	Total          int            `json:"total"`
	ELFCount       int            `json:"elfCount"`
	Binaries       []BinaryResult `json:"binaries"`
	Errors         []string       `json:"errors,omitempty"`
}

// ── ELF detection ───────────────────────────────────────────────────────

var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// isELF reads the first 4 bytes of a regular file and checks for the ELF
// magic number.
func isELF(path string, d fs.DirEntry) bool {
	if d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
		return false
	}
	if !d.Type().IsRegular() {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return bytes.Equal(magic[:], elfMagic)
}

// ── Filesystem walker ───────────────────────────────────────────────────

// ScanContainerFilesystem recursively walks root looking for ELF binaries,
// analyzes each one, and returns the full scan result.
func ScanContainerFilesystem(root string) *ScanResult {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}

	result := &ScanResult{
		Path:     abs,
		Binaries: make([]BinaryResult, 0),
		Errors:   make([]string, 0),
	}

	var elfPaths []string
	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("walk %s: %v", path, err))
			return nil
		}
		if isELF(path, d) {
			elfPaths = append(elfPaths, path)
		}
		return nil
	})
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("walk root: %v", err))
	}

	result.Total = len(elfPaths)
	result.ELFCount = len(elfPaths)

	for _, p := range elfPaths {
		bin := analyzeBinary(p)
		if bin.Error != "" {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", p, bin.Error))
		}
		result.Binaries = append(result.Binaries, BinaryResult{
			Path:         bin.Path,
			Size:         bin.Size,
			ELFType:      bin.ELFType,
			ELFArch:      bin.ELFArch,
			ELFOSABI:     bin.ELFOSABI,
			Hashes:       bin.Hashes,
			Weaknesses:   bin.Weaknesses,
			Capabilities: bin.Capabilities,
			Strings:      bin.Strings,
			Exif:         bin.Exif,
		})
	}

	return result
}

// ── Single-binary analysis ──────────────────────────────────────────────

func analyzeBinary(path string) BinaryAnalysis {
	a := BinaryAnalysis{Path: path}

	fi, err := os.Stat(path)
	if err != nil {
		a.Error = fmt.Sprintf("stat: %v", err)
		return a
	}
	a.Size = fi.Size()
	a.ModTime = fi.ModTime().UnixMilli()

	data, err := os.ReadFile(path)
	if err != nil {
		a.Error = fmt.Sprintf("read: %v", err)
		return a
	}

	ef, elfErr := elf.NewFile(bytes.NewReader(data))
	if elfErr == nil {
		a.ELFType = elfTypeString(ef.Type)
		a.ELFArch = elfMachineString(ef.Machine)
		a.ELFOSABI = elfOSABIString(ef.OSABI)
	}

	a.Capabilities = detectCapabilities(path)
	a.Exif = extractMetadata(data, ef, elfErr, a.ModTime)
	a.Weaknesses = detectWeaknesses(path, fi, ef, elfErr, a.Capabilities, a.Exif)

	a.Hashes = computeHashes(data)

	if elfErr == nil && ef != nil {
		a.Hashes.SHA256Raw, a.Hashes.MD5Raw, a.Hashes.SHA1Raw = computeRawHashes(data, ef)
	}

	a.Strings = extractRelevantStrings(data)

	return a
}

// ── Metadata / EXIF / trailing-data extraction ──────────────────────────

// extractMetadata collects, losslessly, everything we can learn about a
// binary short of the blob itself: ELF identity, dynamic-linking metadata,
// build provenance, and any trailing/overlay data appended past the logical
// end of the ELF (a strong supply-chain / malware indicator). The result is
// serialised into the ContainerBinary.exif column.
func extractMetadata(data []byte, ef *elf.File, elfErr error, modTime int64) map[string]any {
	meta := map[string]any{
		"modTime": modTime,
	}
	if elfErr != nil || ef == nil {
		meta["elfParseError"] = errString(elfErr)
		return meta
	}

	meta["sectionCount"] = len(ef.Sections)
	meta["segmentCount"] = len(ef.Progs)

	if id := buildID(ef); id != "" {
		meta["buildID"] = id
	}
	if interp := sectionString(ef, ".interp"); interp != "" {
		meta["interpreter"] = interp
	}
	if comment := sectionStrings(ef, ".comment"); len(comment) > 0 {
		meta["compiler"] = comment
	}
	if needed, err := ef.DynString(elf.DT_NEEDED); err == nil && len(needed) > 0 {
		meta["neededLibs"] = needed
	}
	if soname, err := ef.DynString(elf.DT_SONAME); err == nil && len(soname) > 0 {
		meta["soname"] = soname[0]
	}
	if rpath, err := ef.DynString(elf.DT_RPATH); err == nil && len(rpath) > 0 {
		meta["rpath"] = rpath
	}
	if runpath, err := ef.DynString(elf.DT_RUNPATH); err == nil && len(runpath) > 0 {
		meta["runpath"] = runpath
	}
	meta["stripped"] = ef.Section(".symtab") == nil
	if notes := noteNames(ef); len(notes) > 0 {
		meta["notes"] = notes
	}

	if ov := detectOverlay(data, ef); ov != nil {
		meta["overlay"] = ov
	}

	return meta
}

// detectOverlay returns metadata about any bytes appended past the logical
// end of the ELF (the maximum file extent referenced by a section, a PT_LOAD
// segment, or the program/section header tables). Returns nil when there is
// no overlay.
func detectOverlay(data []byte, ef *elf.File) map[string]any {
	var end uint64
	for _, s := range ef.Sections {
		if s.Type == elf.SHT_NOBITS {
			continue // occupies no file space
		}
		if e := s.Offset + s.Size; e > end {
			end = e
		}
	}
	for _, p := range ef.Progs {
		if e := p.Off + p.Filesz; e > end {
			end = e
		}
	}
	// The program-header and section-header tables also occupy file space and
	// commonly sit at/after the last section — exclude them from the overlay.
	if e := headerTablesEnd(data, ef); e > end {
		end = e
	}
	if end >= uint64(len(data)) {
		return nil
	}
	overlay := data[end:]
	if len(overlay) == 0 {
		return nil
	}
	sum := sha256.Sum256(overlay)
	ov := map[string]any{
		"present": true,
		"offset":  end,
		"size":    len(overlay),
		"sha256":  hex.EncodeToString(sum[:]),
	}
	if preview := printablePreview(overlay, 120); preview != "" {
		ov["preview"] = preview
	}
	return ov
}

// buildID extracts the GNU build-id (hex) from the .note.gnu.build-id note.
func buildID(ef *elf.File) string {
	sec := ef.Section(".note.gnu.build-id")
	if sec == nil {
		return ""
	}
	d, err := sec.Data()
	if err != nil || len(d) < 16 {
		return ""
	}
	order := ef.ByteOrder
	nameSz := order.Uint32(d[0:4])
	descSz := order.Uint32(d[4:8])
	// 12-byte note header, then name (4-byte aligned), then desc.
	nameEnd := 12 + align4(nameSz)
	descEnd := nameEnd + descSz
	if uint32(len(d)) < descEnd || descSz == 0 {
		return ""
	}
	return hex.EncodeToString(d[nameEnd:descEnd])
}

func align4(n uint32) uint32 { return (n + 3) &^ 3 }

// headerTablesEnd computes the file offset of the end of the program-header
// and section-header tables by reading the raw ELF header fields. These tables
// (especially the section-header table at e_shoff) typically sit at the very
// end of the file and must not be mistaken for appended overlay data.
func headerTablesEnd(data []byte, ef *elf.File) uint64 {
	order := ef.ByteOrder
	var end uint64
	if ef.Class == elf.ELFCLASS64 {
		if len(data) < 64 {
			return 0
		}
		phoff := order.Uint64(data[32:40])
		shoff := order.Uint64(data[40:48])
		phentsize := uint64(order.Uint16(data[54:56]))
		phnum := uint64(order.Uint16(data[56:58]))
		shentsize := uint64(order.Uint16(data[58:60]))
		shnum := uint64(order.Uint16(data[60:62]))
		if phoff > 0 {
			end = maxU64(end, phoff+phentsize*phnum)
		}
		if shoff > 0 {
			end = maxU64(end, shoff+shentsize*shnum)
		}
	} else {
		if len(data) < 52 {
			return 0
		}
		phoff := uint64(order.Uint32(data[28:32]))
		shoff := uint64(order.Uint32(data[32:36]))
		phentsize := uint64(order.Uint16(data[42:44]))
		phnum := uint64(order.Uint16(data[44:46]))
		shentsize := uint64(order.Uint16(data[46:48]))
		shnum := uint64(order.Uint16(data[48:50]))
		if phoff > 0 {
			end = maxU64(end, phoff+phentsize*phnum)
		}
		if shoff > 0 {
			end = maxU64(end, shoff+shentsize*shnum)
		}
	}
	return end
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// sectionString returns the NUL-trimmed contents of a section as a single
// string (used for .interp).
func sectionString(ef *elf.File, name string) string {
	sec := ef.Section(name)
	if sec == nil {
		return ""
	}
	d, err := sec.Data()
	if err != nil {
		return ""
	}
	return strings.Trim(string(d), "\x00")
}

// sectionStrings splits a NUL-delimited section (e.g. .comment) into entries.
func sectionStrings(ef *elf.File, name string) []string {
	sec := ef.Section(name)
	if sec == nil {
		return nil
	}
	d, err := sec.Data()
	if err != nil {
		return nil
	}
	var out []string
	for _, part := range strings.Split(string(d), "\x00") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// noteNames returns the names of all SHT_NOTE sections.
func noteNames(ef *elf.File) []string {
	var out []string
	for _, s := range ef.Sections {
		if s.Type == elf.SHT_NOTE && s.Name != "" {
			out = append(out, s.Name)
		}
	}
	return out
}

// printablePreview returns up to max printable ASCII bytes from b, for a quick
// human-readable hint at appended-data contents.
func printablePreview(b []byte, max int) string {
	var sb strings.Builder
	for _, c := range b {
		if sb.Len() >= max {
			break
		}
		if c >= 0x20 && c <= 0x7e {
			sb.WriteByte(c)
		}
	}
	return strings.TrimSpace(sb.String())
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ── Weakness detection ──────────────────────────────────────────────────

func detectWeaknesses(path string, fi fs.FileInfo, ef *elf.File, elfErr error, caps []string, meta map[string]any) []string {
	var w []string
	if fi != nil {
		mode := fi.Mode()

		if mode&os.ModeSetuid != 0 {
			w = append(w, "setuid")
		}
		if mode&os.ModeSetgid != 0 {
			w = append(w, "setgid")
		}
		if mode.Perm()&0002 != 0 {
			w = append(w, "world-writable")
		}

		// SUID on a script
		if mode&os.ModeSetuid != 0 {
			f, err := os.Open(path)
			if err == nil {
				var shebang [2]byte
				if n, _ := io.ReadFull(f, shebang[:]); n == 2 {
					if shebang[0] == '#' && shebang[1] == '!' {
						w = append(w, "suid-script")
					}
				}
				f.Close()
			}
		}
	}

	// Dangerous Linux file capabilities (privilege-escalation primitives).
	w = append(w, dangerousCapWeaknesses(caps)...)

	// Trailing/appended data past the logical ELF end (set in metadata).
	if ov, ok := meta["overlay"].(map[string]any); ok {
		if present, _ := ov["present"].(bool); present {
			w = append(w, "overlay-data")
		}
	}

	if ef == nil || elfErr != nil {
		return w
	}

	// PIE check
	if ef.Type == elf.ET_EXEC {
		w = append(w, "no-pie")
	}

	// Statically linked (no program interpreter).
	if !hasInterp(ef) {
		w = append(w, "static-binary")
	}

	// RELRO, NX, and W^X segment checks over the program headers.
	hasRelro := false
	for _, p := range ef.Progs {
		if p.Type == elf.PT_GNU_RELRO {
			hasRelro = true
		}
		if p.Type == elf.PT_GNU_STACK && p.Flags&elf.PF_X != 0 {
			w = append(w, "nx-disabled")
		}
		// Writable AND executable mapped segment — violates W^X.
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_W != 0 && p.Flags&elf.PF_X != 0 {
			w = append(w, "wx-segment")
		}
	}
	if !hasRelro {
		w = append(w, "no-relro")
	}

	if hasRelro {
		if dynamicHasBindNow(ef) {
			// Full RELRO — drop any partial/no-relro markers.
			filtered := make([]string, 0, len(w))
			for _, item := range w {
				if item != "no-relro" && item != "partial-relro" {
					filtered = append(filtered, item)
				}
			}
			w = filtered
		} else {
			w = append(w, "partial-relro")
		}
	}

	if !hasStackCanary(ef) {
		w = append(w, "no-stack-canary")
	}

	// Text relocations (DT_TEXTREL / DF_TEXTREL) — writable code pages.
	if hasTextRel(ef) {
		w = append(w, "textrel")
	}

	// Insecure RPATH/RUNPATH search paths.
	w = append(w, rpathWeaknesses(meta)...)

	// FORTIFY_SOURCE: dynamically linked but no _chk-fortified calls.
	if hasInterp(ef) && !hasFortify(ef) {
		w = append(w, "missing-fortify")
	}

	// UPX (or other) packer markers.
	if isPacked(ef) {
		w = append(w, "upx-packed")
	}

	return w
}

// hasInterp reports whether the binary has a program interpreter (PT_INTERP).
func hasInterp(ef *elf.File) bool {
	for _, p := range ef.Progs {
		if p.Type == elf.PT_INTERP {
			return true
		}
	}
	return ef.Section(".interp") != nil
}

// hasTextRel reports whether the dynamic section requests text relocations.
func hasTextRel(ef *elf.File) bool {
	if vals, err := ef.DynValue(elf.DT_TEXTREL); err == nil && len(vals) > 0 {
		return true
	}
	if flags, err := ef.DynValue(elf.DT_FLAGS); err == nil {
		for _, f := range flags {
			if f&uint64(elf.DF_TEXTREL) != 0 {
				return true
			}
		}
	}
	return false
}

// hasFortify reports whether the binary imports any _chk fortified function.
func hasFortify(ef *elf.File) bool {
	if syms, err := ef.ImportedSymbols(); err == nil {
		for _, s := range syms {
			if strings.HasSuffix(s.Name, "_chk") {
				return true
			}
		}
	}
	return false
}

// isPacked reports whether the binary carries UPX packer section markers.
func isPacked(ef *elf.File) bool {
	for _, s := range ef.Sections {
		if s.Name == "UPX0" || s.Name == "UPX1" || s.Name == "UPX2" {
			return true
		}
	}
	return false
}

// dangerousCaps maps risky Linux file capabilities to a normalised name.
var dangerousCaps = map[string]bool{
	"cap_setuid": true, "cap_setgid": true, "cap_sys_admin": true,
	"cap_dac_override": true, "cap_dac_read_search": true, "cap_net_admin": true,
	"cap_sys_ptrace": true, "cap_sys_module": true, "cap_sys_chroot": true,
	"cap_fowner": true, "cap_setfcap": true, "cap_sys_rawio": true,
}

// dangerousCapWeaknesses returns a "dangerous-capability:<cap>" entry for each
// risky capability present in caps (e.g. "cap_setuid+ep").
func dangerousCapWeaknesses(caps []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range caps {
		// Capability tokens look like "cap_setuid+ep" — split off the name.
		name := c
		if idx := strings.IndexAny(c, "+="); idx > 0 {
			name = c[:idx]
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if dangerousCaps[name] && !seen[name] {
			seen[name] = true
			out = append(out, "dangerous-capability:"+name)
		}
	}
	return out
}

// rpathWeaknesses inspects RPATH/RUNPATH search paths recorded in metadata and
// flags their presence plus any insecure entries.
func rpathWeaknesses(meta map[string]any) []string {
	var out []string
	rpath := stringSliceFromMeta(meta["rpath"])
	runpath := stringSliceFromMeta(meta["runpath"])
	if len(rpath) > 0 {
		out = append(out, "rpath-set")
	}
	if len(runpath) > 0 {
		out = append(out, "runpath-set")
	}
	insecure := false
	for _, p := range append(append([]string{}, rpath...), runpath...) {
		for _, entry := range strings.Split(p, ":") {
			e := strings.TrimSpace(entry)
			if e == "" || e == "." || strings.HasPrefix(e, "$ORIGIN") ||
				!strings.HasPrefix(e, "/") || strings.HasPrefix(e, "/tmp") ||
				strings.HasPrefix(e, "/dev/shm") || strings.HasPrefix(e, "/var/tmp") {
				insecure = true
			}
		}
	}
	if insecure {
		out = append(out, "insecure-rpath")
	}
	return out
}

// stringSliceFromMeta coerces a metadata value back into a []string.
func stringSliceFromMeta(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, e := range s {
			if str, ok := e.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

func dynamicHasBindNow(ef *elf.File) bool {
	for _, s := range ef.Sections {
		if s.Type == elf.SHT_DYNAMIC {
			dyn, err := s.Data()
			if err != nil {
				continue
			}
			return checkDynamicBindNow(ef.ByteOrder, dyn, ef.Class)
		}
	}
	return false
}

const (
	dtNull    = 0
	dtFlags   = 30
	dtFlags1  = 0x6ffffffb
	dtBindNow = 24
)

const dfBindNow = 8
const df1Now = 1

func checkDynamicBindNow(order binary.ByteOrder, data []byte, class elf.Class) bool {
	if class == elf.ELFCLASS64 {
		return scanDynamic64(order, data)
	}
	return scanDynamic32(order, data)
}

func scanDynamic64(order binary.ByteOrder, data []byte) bool {
	for len(data) >= 16 {
		tag := order.Uint64(data[0:8])
		val := order.Uint64(data[8:16])
		if tag == dtNull {
			break
		}
		if tag == dtBindNow && val != 0 {
			return true
		}
		if tag == dtFlags && val&dfBindNow != 0 {
			return true
		}
		if tag == dtFlags1 && val&df1Now != 0 {
			return true
		}
		data = data[16:]
	}
	return false
}

func scanDynamic32(order binary.ByteOrder, data []byte) bool {
	for len(data) >= 8 {
		tag := order.Uint32(data[0:4])
		val := order.Uint32(data[4:8])
		if tag == dtNull {
			break
		}
		if tag == dtBindNow && val != 0 {
			return true
		}
		if tag == dtFlags && val&dfBindNow != 0 {
			return true
		}
		if tag == dtFlags1 && val&df1Now != 0 {
			return true
		}
		data = data[8:]
	}
	return false
}

func hasStackCanary(ef *elf.File) bool {
	syms, err := ef.ImportedSymbols()
	if err == nil {
		for _, s := range syms {
			if s.Name == "__stack_chk_fail" || strings.HasPrefix(s.Name, "__stack_chk") {
				return true
			}
		}
	}
	dynSyms, err := ef.DynamicSymbols()
	if err == nil {
		for _, s := range dynSyms {
			if s.Name == "__stack_chk_fail" || strings.HasPrefix(s.Name, "__stack_chk") {
				return true
			}
		}
	}
	return false
}

func detectCapabilities(path string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getcap", path).CombinedOutput()
	if err != nil {
		return nil
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil
	}
	lines := strings.Split(trimmed, "\n")
	var caps []string
	for _, line := range lines {
		if idx := strings.LastIndexByte(line, ' '); idx > 0 {
			capStr := strings.TrimSpace(line[idx:])
			for _, c := range strings.Fields(capStr) {
				caps = append(caps, c)
			}
		}
	}
	return caps
}

// ── Hash computation ────────────────────────────────────────────────────

func computeHashes(data []byte) BinaryHashes {
	h := BinaryHashes{}

	s256 := sha256.Sum256(data)
	h.SHA256 = hex.EncodeToString(s256[:])

	mSum := md5.Sum(data)
	h.MD5 = hex.EncodeToString(mSum[:])

	s1 := sha1.Sum(data)
	h.SHA1 = hex.EncodeToString(s1[:])

	h.SSDEEP = computeSSDeep(data)
	h.TLSH = computeTLSH(data)

	return h
}

func computeRawHashes(data []byte, ef *elf.File) (sha256raw, md5raw, sha1raw string) {
	stripped := stripMetadata(data, ef)

	s256 := sha256.Sum256(stripped)
	sha256raw = hex.EncodeToString(s256[:])

	s512 := md5.Sum(stripped)
	md5raw = hex.EncodeToString(s512[:])

	s1 := sha1.Sum(stripped)
	sha1raw = hex.EncodeToString(s1[:])

	return
}

func stripMetadata(data []byte, ef *elf.File) []byte {
	if len(data) == 0 {
		return data
	}

	out := make([]byte, len(data))
	copy(out, data)

	for _, s := range ef.Sections {
		if s.Name == "" {
			continue
		}
		if strings.HasPrefix(s.Name, ".debug_") ||
			strings.HasPrefix(s.Name, ".zdebug_") ||
			s.Name == ".comment" ||
			strings.HasPrefix(s.Name, ".note.") ||
			s.Name == ".note" {
			off := s.Offset
			end := off + s.Size
			if off < uint64(len(out)) && end <= uint64(len(out)) {
				for i := off; i < end; i++ {
					out[i] = 0
				}
			}
		}
	}

	for len(out) > 0 && out[len(out)-1] == 0 {
		out = out[:len(out)-1]
	}

	return out
}

// ── ssdeep / TLSH ───────────────────────────────────────────────────────

// computeSSDeep returns the ssdeep context-triggered piecewise fuzzy hash of
// data. ssdeep needs a few KiB of input to produce a meaningful digest; for
// inputs that are too small (or any other error) it returns "" — non-fatal,
// the binary is still recorded with its other hashes.
func computeSSDeep(data []byte) string {
	h, err := ssdeep.FuzzyBytes(data)
	if err != nil {
		return ""
	}
	return h
}

// computeTLSH returns the TLSH locality-sensitive hash of data. TLSH requires
// at least 256 bytes and ~50 features; on any error (too small / too little
// variance) it returns "" — non-fatal.
func computeTLSH(data []byte) string {
	if len(data) < 256 {
		return ""
	}
	t, err := tlsh.HashBytes(data)
	if err != nil || t == nil {
		return ""
	}
	s := t.String()
	// glaslos/tlsh emits an all-zero digest when it cannot compute a real
	// hash; treat that as "no hash" rather than recording a meaningless one.
	if strings.Trim(s, "0") == "" {
		return ""
	}
	return s
}

// ── String extraction ───────────────────────────────────────────────────

var relevantPatterns = []string{
	"OpenSSL", "GNU C Library", "libcrypto", "libssl", "libc",
	"GLIBC", "GLIBCXX", "GCC:", "clang version",
	"libpython", "libperl", "libruby", "liblua",
	"Copyright", "All rights reserved",
}

func extractRelevantStrings(data []byte) []string {
	if len(data) < 6 {
		return nil
	}

	seen := make(map[string]bool)
	var out []string
	start := -1

	for i, b := range data {
		isPrintable := b >= 0x20 && b <= 0x7e
		if isPrintable {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 && i-start >= 6 {
				s := string(data[start:i])
				if !seen[s] && isRelevantString(s) {
					seen[s] = true
					out = append(out, s)
				}
			}
			start = -1
		}
	}
	if start >= 0 && len(data)-start >= 6 {
		s := string(data[start:])
		if !seen[s] && isRelevantString(s) {
			out = append(out, s)
		}
	}

	return out
}

func isRelevantString(s string) bool {
	if looksLikeVersion(s) {
		return true
	}
	for _, pat := range relevantPatterns {
		if strings.Contains(s, pat) {
			return true
		}
	}
	return false
}

func looksLikeVersion(s string) bool {
	for i := 0; i < len(s)-2; i++ {
		if s[i] >= '0' && s[i] <= '9' {
			if j := strings.IndexByte(s[i:], '.'); j > 0 {
				if k := strings.IndexAny(s[i+j+1:], "0123456789"); k >= 0 {
					return true
				}
			}
		}
	}
	return false
}

// ── ELF type/machine/OSABI stringers ────────────────────────────────────

func elfTypeString(t elf.Type) string {
	switch t {
	case elf.ET_NONE:
		return "ET_NONE"
	case elf.ET_REL:
		return "ET_REL"
	case elf.ET_EXEC:
		return "ET_EXEC"
	case elf.ET_DYN:
		return "ET_DYN"
	case elf.ET_CORE:
		return "ET_CORE"
	default:
		return fmt.Sprintf("0x%04x", uint16(t))
	}
}

func elfMachineString(m elf.Machine) string {
	switch m {
	case elf.EM_X86_64:
		return "EM_X86_64"
	case elf.EM_AARCH64:
		return "EM_AARCH64"
	case elf.EM_386:
		return "EM_386"
	case elf.EM_ARM:
		return "EM_ARM"
	case elf.EM_MIPS:
		return "EM_MIPS"
	case elf.EM_PPC64:
		return "EM_PPC64"
	case elf.EM_S390:
		return "EM_S390"
	case elf.EM_RISCV:
		return "EM_RISCV"
	default:
		return fmt.Sprintf("0x%04x", uint16(m))
	}
}

func elfOSABIString(a elf.OSABI) string {
	switch a {
	case elf.ELFOSABI_NONE:
		return "NONE"
	case elf.ELFOSABI_LINUX:
		return "LINUX"
	case elf.ELFOSABI_FREEBSD:
		return "FREEBSD"
	case elf.ELFOSABI_NETBSD:
		return "NETBSD"
	case elf.ELFOSABI_HPUX:
		return "HPUX"
	case elf.ELFOSABI_SOLARIS:
		return "SOLARIS"
	default:
		return fmt.Sprintf("0x%02x", byte(a))
	}
}

// ── Utilities ───────────────────────────────────────────────────────────

// SetScannerRunUUID stamps the scan result with the scanner run identifier.
func (sr *ScanResult) SetScannerRunUUID(uuid string) {
	sr.ScannerRunUUID = uuid
}

// ToJSON returns the indented JSON representation of the scan result.
//
// Deliberately NOT named MarshalJSON: that magic name would make *ScanResult
// implement json.Marshaler, and the json.MarshalIndent(sr, ...) call below
// would then recurse into itself indefinitely.
func (sr *ScanResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(sr, "", "  ")
}
