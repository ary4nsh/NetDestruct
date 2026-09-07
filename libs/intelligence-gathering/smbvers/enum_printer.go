package smbvers

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

const printerEnumLocal = 0x00000002

func decodePrinterEnumBuffer(buf []byte, count uint32) ([]EnumPrinter, error) {
	if len(buf) == 0 || count == 0 {
		return nil, nil
	}
	const recordSize = 16
	var out []EnumPrinter
	for i := uint32(0); i < count; i++ {
		hdr := int(i) * recordSize
		if hdr+recordSize > len(buf) {
			break
		}
		flags := binary.LittleEndian.Uint32(buf[hdr:])
		// Offsets in the INFO buffer are relative to the start of this record.
		base := uint32(hdr)
		descOff := base + binary.LittleEndian.Uint32(buf[hdr+4:])
		nameOff := base + binary.LittleEndian.Uint32(buf[hdr+8:])
		commentOff := base + binary.LittleEndian.Uint32(buf[hdr+12:])
		desc := readInfoBufferString(buf, descOff)
		name := readInfoBufferString(buf, nameOff)
		comment := readInfoBufferString(buf, commentOff)
		if name == "" && desc != "" {
			name = firstDescSegment(desc)
		}
		if name == "" && desc == "" {
			continue
		}
		out = append(out, EnumPrinter{
			Name:        name,
			Description: desc,
			Comment:     comment,
			Flags:       flags,
		})
	}
	return out, nil
}

func readInfoBufferString(buf []byte, offset uint32) string {
	if offset == 0 || int(offset) >= len(buf) {
		return ""
	}
	data := buf[offset:]
	if len(data) < 2 {
		return ""
	}
	u16 := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		ch := binary.LittleEndian.Uint16(data[i:])
		if ch == 0 {
			break
		}
		u16 = append(u16, ch)
	}
	return string(utf16.Decode(u16))
}

func firstDescSegment(desc string) string {
	if desc == "" {
		return ""
	}
	if idx := strings.Index(desc, ","); idx >= 0 {
		return desc[:idx]
	}
	return desc
}

func formatPrinterName(host, name string) string {
	if strings.HasPrefix(name, `\\`) {
		return name
	}
	short := strings.TrimPrefix(name, `\`)
	if host == "" || short == "" {
		return name
	}
	return fmt.Sprintf(`\\%s\%s`, host, short)
}
