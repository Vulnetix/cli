package secretscan

import (
	"encoding/binary"
	"strings"
	"testing"
)

// TestExtractEXIF_TIFF builds a tiny in-memory TIFF with a Make/Model tag
// and confirms the parser recovers the strings.
func TestExtractEXIF_TIFF(t *testing.T) {
	tiff := buildTinyTIFF(t, map[uint16]string{
		0x010f: "TestCam",     // Make
		0x0110: "TC-1",        // Model
		0x0131: "my-software", // Software
	})
	exif, ok := ExtractEXIF(tiff)
	if !ok {
		t.Fatal("ExtractEXIF did not recognise the TIFF")
	}
	if exif.Make != "TestCam" {
		t.Errorf("Make = %q, want TestCam", exif.Make)
	}
	if exif.Model != "TC-1" {
		t.Errorf("Model = %q, want TC-1", exif.Model)
	}
	if exif.Software != "my-software" {
		t.Errorf("Software = %q, want my-software", exif.Software)
	}
	if !strings.Contains(exif.Raw, "Make=TestCam") {
		t.Errorf("Raw EXIF missing Make=TestCam: %q", exif.Raw)
	}
}

// TestExtractEXIF_JPEG wraps the same TIFF payload inside a JPEG APP1
// segment and confirms the JPEG parser still surfaces the strings.
func TestExtractEXIF_JPEG(t *testing.T) {
	tiff := buildTinyTIFF(t, map[uint16]string{0x010f: "CamJPEG"})
	// APP1 segment: length (2 bytes big-endian) + "Exif\0\0" + TIFF payload.
	app1 := make([]byte, 0, 6+len(tiff))
	app1 = append(app1, []byte("Exif\x00\x00")...)
	app1 = append(app1, tiff...)
	segLen := uint16(len(app1) + 2) // segment length includes its own length bytes
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe1}
	jpeg = append(jpeg, byte(segLen>>8), byte(segLen))
	jpeg = append(jpeg, app1...)
	jpeg = append(jpeg, 0xff, 0xd9) // EOI

	exif, ok := ExtractEXIF(jpeg)
	if !ok {
		t.Fatal("ExtractEXIF did not recognise the JPEG")
	}
	if exif.Make != "CamJPEG" {
		t.Errorf("Make = %q, want CamJPEG", exif.Make)
	}
}

func TestExtractEXIF_NotAnImage(t *testing.T) {
	if _, ok := ExtractEXIF([]byte("hello world")); ok {
		t.Error("ExtractEXIF should return ok=false for plain text")
	}
}

// buildTinyTIFF constructs a valid (single IFD) TIFF big-endian byte stream
// with the given ASCII tags. Only type 2 (ASCII) is supported.
func buildTinyTIFF(t *testing.T, tags map[uint16]string) []byte {
	t.Helper()
	// Layout:
	//   [0..2)   "MM"  big endian
	//   [2..4)   0x00 0x2A  magic
	//   [4..8)   IFD0 offset (8)
	//   [8..)    IFD entries
	//   [n..]    string data
	var b []byte
	b = append(b, 'M', 'M', 0, 0x2a)
	b = binary.BigEndian.AppendUint16(b, 0) // placeholder for IFD0 ptr
	b = binary.BigEndian.AppendUint16(b, 8) // IFD0 at offset 8

	// Number of entries.
	if len(tags) > 0xffff {
		t.Fatalf("too many tags")
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(tags)))

	// Compute where the string pool begins.
	entrySize := 12
	poolOffset := 8 + 2 + entrySize*len(tags) + 4 // +4 for next-IFD ptr

	stringPool := []byte{}

	for tag, val := range tags {
		// Entry layout: tag(2) type(2) count(4) value/offset(4)
		b = binary.BigEndian.AppendUint16(b, tag)
		b = binary.BigEndian.AppendUint16(b, 2) // ASCII
		b = binary.BigEndian.AppendUint32(b, uint32(len(val)+1))
		if len(val)+1 <= 4 {
			// Inline value, right-padded with NUL.
			off := len(b)
			b = b[:off+4]
			copy(b[off:], val)
			b[off+len(val)] = 0
		} else {
			off := poolOffset + len(stringPool)
			b = binary.BigEndian.AppendUint32(b, uint32(off))
			stringPool = append(stringPool, val...)
			stringPool = append(stringPool, 0)
		}
	}
	// Next-IFD offset (0 = no more).
	b = binary.BigEndian.AppendUint32(b, 0)
	b = append(b, stringPool...)
	return b
}
