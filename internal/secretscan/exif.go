package secretscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// EXIF is the subset of EXIF/IPTC/XMP metadata relevant to secrets detection.
// It is intentionally permissive: anything that can carry a credential is
// surfaced as a key, even if the underlying tag is not formally recognised.
type EXIF struct {
	Make        string
	Model       string
	Software    string
	DateTime    string
	Artist      string
	Copyright   string
	ImageDescr  string
	UserComment string
	GPS         map[string]string
	Other       map[string]string
	// Raw returns the full serialised key=value list, useful for regex rules
	// that want to match against any metadata field.
	Raw string
}

// ExtractEXIF returns a best-effort EXIF extraction from data. It supports
// JPEG (APP1 EXIF, IPTC, XMP) and TIFF containers. Other formats return a
// zero-value EXIF and ok=false.
//
// This is intentionally a minimal parser — we do not need the full spec, we
// need to surface the strings that secrets detection can match against.
func ExtractEXIF(data []byte) (exif EXIF, ok bool) {
	exif.Other = make(map[string]string)
	exif.GPS = make(map[string]string)

	if len(data) < 4 {
		return exif, false
	}

	// JPEG: starts with FF D8 FF
	if data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff {
		return parseJPEG(data, &exif)
	}

	// TIFF: starts with "II*\0" (little endian) or "MM\0*" (big endian)
	if (data[0] == 'I' && data[1] == 'I' && data[2] == '*' && data[3] == 0) ||
		(data[0] == 'M' && data[1] == 'M' && data[2] == 0 && data[3] == '*') {
		return parseTIFF(data, &exif)
	}

	return exif, false
}

func parseJPEG(data []byte, exif *EXIF) (EXIF, bool) {
	// Walk APPn markers until we hit SOS or EOI.
	i := 2
	for i+4 < len(data) {
		if data[i] != 0xff {
			break
		}
		marker := data[i+1]
		// Skip standalone markers
		if marker == 0xd8 || (marker >= 0xd0 && marker <= 0xd7) {
			i += 2
			continue
		}
		// SOS — start of scan, metadata is over
		if marker == 0xda {
			break
		}
		if i+4 > len(data) {
			break
		}
		segLen := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if segLen < 2 || i+2+segLen > len(data) {
			break
		}
		seg := data[i+4 : i+2+segLen]
		switch marker {
		case 0xe1:
			// APP1: EXIF or XMP
			if bytes.HasPrefix(seg, []byte("Exif\x00\x00")) {
				exifTiff := seg[6:]
				if len(exifTiff) > 8 {
					_ = parseTIFFDir(exifTiff, exif)
				}
			} else if bytes.HasPrefix(seg, []byte("http://ns.adobe.com/xap/1.0/")) {
				parseXMP(seg[29:], exif)
			}
		case 0xed:
			// APP13: IPTC
			parseIPTC(seg, exif)
		}
		i += 2 + segLen
	}
	serialiseEXIF(exif)
	return *exif, true
}

func parseTIFF(data []byte, exif *EXIF) (EXIF, bool) {
	// Determine endianness
	var bo binary.ByteOrder
	if data[0] == 'I' {
		bo = binary.LittleEndian
	} else {
		bo = binary.BigEndian
	}
	if len(data) < 8 {
		return *exif, false
	}
	// data[4..8] is the IFD0 offset
	ifd0Off := bo.Uint32(data[4:8])
	if int(ifd0Off)+2 > len(data) {
		return *exif, false
	}
	_ = parseTIFFDirAt(data, bo, ifd0Off, exif)
	serialiseEXIF(exif)
	return *exif, true
}

func parseTIFFDir(tiff []byte, exif *EXIF) bool {
	var bo binary.ByteOrder
	if tiff[0] == 'I' {
		bo = binary.LittleEndian
	} else {
		bo = binary.BigEndian
	}
	return parseTIFFDirAt(tiff, bo, 8, exif)
}

func parseTIFFDirAt(tiff []byte, bo binary.ByteOrder, offset uint32, exif *EXIF) bool {
	if int(offset)+2 > len(tiff) {
		return false
	}
	numEntries := int(bo.Uint16(tiff[offset : offset+2]))
	for i := 0; i < numEntries; i++ {
		entryOff := offset + 2 + uint32(i)*12
		if int(entryOff)+12 > len(tiff) {
			return true
		}
		tag := bo.Uint16(tiff[entryOff : entryOff+2])
		typ := uint32(bo.Uint16(tiff[entryOff+2 : entryOff+4]))
		count := bo.Uint32(tiff[entryOff+4 : entryOff+8])
		valOff := entryOff + 8
		val := readTIFFValue(tiff, bo, typ, count, valOff)
		assignTag(exif, tag, val)
		// Recurse into EXIF sub-IFD and GPS sub-IFD
		if tag == 0x8769 {
			// EXIF sub-IFD
			subOff := bo.Uint32(tiff[valOff : valOff+4])
			parseTIFFDirAt(tiff, bo, subOff, exif)
		}
		if tag == 0x8825 {
			// GPS sub-IFD
			subOff := bo.Uint32(tiff[valOff : valOff+4])
			parseGPSDir(tiff, bo, subOff, exif)
		}
	}
	return true
}

func parseGPSDir(tiff []byte, bo binary.ByteOrder, offset uint32, exif *EXIF) {
	if int(offset)+2 > len(tiff) {
		return
	}
	numEntries := int(bo.Uint16(tiff[offset : offset+2]))
	for i := 0; i < numEntries; i++ {
		entryOff := offset + 2 + uint32(i)*12
		if int(entryOff)+12 > len(tiff) {
			return
		}
		tag := bo.Uint16(tiff[entryOff : entryOff+2])
		typ := uint32(bo.Uint16(tiff[entryOff+2 : entryOff+4]))
		count := bo.Uint32(tiff[entryOff+4 : entryOff+8])
		valOff := entryOff + 8
		val := readTIFFValue(tiff, bo, typ, count, valOff)
		exif.GPS[fmt.Sprintf("0x%04x", tag)] = val
	}
}

func readTIFFValue(tiff []byte, bo binary.ByteOrder, typ, count uint32, valOff uint32) string {
	var size uint32
	switch typ {
	case 1, 2, 7:
		size = 1
	case 3:
		size = 2
	case 4:
		size = 4
	case 5, 10:
		size = 8
	case 9:
		size = 4
	case 11:
		size = 4
	case 12:
		size = 8
	default:
		return ""
	}
	total := size * count
	dataOff := valOff
	if total > 4 {
		dataOff = bo.Uint32(tiff[valOff : valOff+4])
	}
	if int(dataOff)+int(total) > len(tiff) {
		return ""
	}
	data := tiff[dataOff : dataOff+total]
	switch typ {
	case 2:
		// ASCII
		s := string(data)
		if idx := strings.IndexByte(s, 0); idx >= 0 {
			s = s[:idx]
		}
		return s
	case 7:
		// UNDEFINED — surface as hex
		return fmt.Sprintf("%x", data)
	default:
		return fmt.Sprintf("%v", data)
	}
}

func assignTag(exif *EXIF, tag uint16, val string) {
	switch tag {
	case 0x010f:
		exif.Make = val
	case 0x0110:
		exif.Model = val
	case 0x0131:
		exif.Software = val
	case 0x0132:
		exif.DateTime = val
	case 0x013b:
		exif.Artist = val
	case 0x8298:
		exif.Copyright = val
	case 0x010e:
		exif.ImageDescr = val
	case 0x9286:
		exif.UserComment = val
	default:
		exif.Other[fmt.Sprintf("0x%04x", tag)] = val
	}
}

func parseIPTC(seg []byte, exif *EXIF) {
	// Very rough IPTC: pull all printable ASCII runs ≥ 4 chars from the segment.
	exif.Other["iptc"] = ExtractStrings(seg, 8)
}

func parseXMP(xmp []byte, exif *EXIF) {
	// XMP is XML; surface the entire packet as a "xmp" field — regex rules can
	// match against any field name.
	exif.Other["xmp"] = string(xmp)
}

// serialiseEXIF writes the flat key=value representation of the EXIF into
// exif.Raw so that the secrets scanner can feed the same content to Rego as
// it would for any other file.
func serialiseEXIF(exif *EXIF) {
	keys := make([]string, 0, 8+len(exif.Other)+len(exif.GPS))
	pairs := make(map[string]string, 8+len(exif.Other)+len(exif.GPS))
	add := func(k, v string) {
		if v == "" {
			return
		}
		keys = append(keys, k)
		pairs[k] = v
	}
	add("Make", exif.Make)
	add("Model", exif.Model)
	add("Software", exif.Software)
	add("DateTime", exif.DateTime)
	add("Artist", exif.Artist)
	add("Copyright", exif.Copyright)
	add("ImageDescription", exif.ImageDescr)
	add("UserComment", exif.UserComment)
	for k, v := range exif.GPS {
		add("GPS."+k, v)
	}
	for k, v := range exif.Other {
		add(k, v)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(pairs[k])
		b.WriteString("\n")
	}
	exif.Raw = b.String()
}
