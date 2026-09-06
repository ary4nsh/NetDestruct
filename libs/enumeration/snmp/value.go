package snmp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func formatSNMPValue(tag byte, raw []byte) string {
	switch tag {
	case 0x02:
		return "INTEGER: " + formatInteger(raw)
	case 0x04:
		return "STRING: " + quoteSNMPString(string(raw))
	case 0x05:
		return "NULL"
	case 0x06:
		if oid, err := decodeOID(raw); err == nil {
			return "OID: " + formatSymbolicOID(oid)
		}
		return "OID: " + fmt.Sprintf("%x", raw)
	case 0x40:
		if len(raw) == 4 {
			return "IpAddress: " + net.IP(raw).String()
		}
		return "IpAddress: " + fmt.Sprintf("%x", raw)
	case 0x41:
		return "Counter32: " + formatUnsigned(raw)
	case 0x42:
		return "Gauge32: " + formatUnsigned(raw)
	case 0x43:
		return "Timeticks: (" + formatUnsigned(raw) + ") " + formatTimeticks(raw)
	case 0x44:
		return "Opaque: " + fmt.Sprintf("%x", raw)
	case 0x46:
		return "Counter64: " + formatUnsigned64(raw)
	case 0x80:
		return "NoSuchObject"
	case 0x81:
		return "NoSuchInstance"
	case 0x82:
		return "EndOfMibView"
	default:
		if len(raw) == 0 {
			return fmt.Sprintf("Unknown(%#x)", tag)
		}
		return fmt.Sprintf("Unknown(%#x): %x", tag, raw)
	}
}

func formatInteger(raw []byte) string {
	if len(raw) == 0 {
		return "0"
	}
	neg := raw[0]&0x80 != 0
	var v int64
	for _, b := range raw {
		v = (v << 8) | int64(b)
	}
	if neg {
		width := int64(len(raw) * 8)
		v -= 1 << width
	}
	return strconv.FormatInt(v, 10)
}

func formatUnsigned(raw []byte) string {
	var v uint64
	for _, b := range raw {
		v = (v << 8) | uint64(b)
	}
	return strconv.FormatUint(v, 10)
}

func formatUnsigned64(raw []byte) string {
	if len(raw) >= 8 {
		return strconv.FormatUint(binary.BigEndian.Uint64(raw[len(raw)-8:]), 10)
	}
	return formatUnsigned(raw)
}

func formatTimeticks(raw []byte) string {
	var v uint64
	for _, b := range raw {
		v = (v << 8) | uint64(b)
	}
	sec := v / 100
	return fmt.Sprintf("%d:%02d:%02d", sec/3600, (sec%3600)/60, sec%60)
}

func quoteSNMPString(s string) string {
	if s == "" {
		return `""`
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return r < 0x20 || r > 0x7e
	}) >= 0 {
		return fmt.Sprintf("%q", s)
	}
	return `"` + s + `"`
}

func isSNMPException(tag byte) bool {
	return tag == 0x80 || tag == 0x81 || tag == 0x82
}
