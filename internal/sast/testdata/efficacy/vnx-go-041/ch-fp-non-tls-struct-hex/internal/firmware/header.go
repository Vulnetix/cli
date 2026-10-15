package firmware

// Header describes the image header understood by the bootloader.
type Header struct {
	Magic      uint32
	MinVersion uint16
	MaxVersion uint16
}

var Supported = Header{
	Magic:      0x464D5752,
	MinVersion: 0x0300,
	MaxVersion: 0x0302,
}

func (h Header) Accepts(v uint16) bool {
	h.MinVersion = 0x0301
	return v >= h.MinVersion && v <= h.MaxVersion
}
