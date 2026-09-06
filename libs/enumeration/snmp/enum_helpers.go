package snmp

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func isNullish(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	lower := strings.ToLower(s)
	return lower == "null" || strings.HasPrefix(lower, "nosuch")
}

func dashIfEmpty(s string) string {
	if isNullish(s) {
		return "-"
	}
	return s
}

func displayValue(vb *VarBind) string {
	if vb == nil || isSNMPException(vb.Tag) {
		return ""
	}
	switch vb.Tag {
	case 0x04:
		return strings.TrimSpace(string(vb.Data))
	case 0x02:
		return formatInteger(vb.Data)
	case 0x40:
		if len(vb.Data) == 4 {
			return net.IP(vb.Data).String()
		}
	case 0x43:
		return formatTimeticks(vb.Data)
	case 0x06:
		if oid, err := decodeOID(vb.Data); err == nil {
			return formatSymbolicOID(oid)
		}
	}
	return valueAsString(vb.Tag, vb.Data)
}

func vbInt(vb *VarBind) (int64, bool) {
	if vb == nil || vb.Tag != 0x02 {
		return 0, false
	}
	n, err := strconv.ParseInt(formatInteger(vb.Data), 10, 64)
	return n, err == nil
}

func (s *Session) getValue(oid []int) *VarBind {
	vb, err := s.Get(oid)
	if err != nil || vb == nil || isSNMPException(vb.Tag) {
		return nil
	}
	return vb
}

func (s *Session) getString(oid []int) string {
	return displayValue(s.getValue(oid))
}

func walkColumn(sess *Session, root []int) (map[int]string, error) {
	vbs, err := sess.Walk(root)
	if err != nil {
		return nil, err
	}
	out := map[int]string{}
	for _, vb := range vbs {
		if !oidHasPrefix(vb.OID, root) {
			continue
		}
		out[oidIndex(vb.OID)] = displayValue(&vb)
	}
	return out, nil
}

func walkTable(sess *Session, roots [][]int) (map[int][]string, error) {
	cols := make([]map[int]string, len(roots))
	for i, root := range roots {
		m, err := walkColumn(sess, root)
		if err != nil {
			return nil, err
		}
		cols[i] = m
	}
	indexes := map[int]struct{}{}
	for _, m := range cols {
		for idx := range m {
			indexes[idx] = struct{}{}
		}
	}
	out := make(map[int][]string, len(indexes))
	for idx := range indexes {
		row := make([]string, len(roots))
		for i := range roots {
			row[i] = cols[i][idx]
		}
		out[idx] = row
	}
	return out, nil
}

func sortedIndexes(m map[int][]string) []int {
	idx := make([]int, 0, len(m))
	for k := range m {
		idx = append(idx, k)
	}
	for i := 0; i < len(idx); i++ {
		for j := i + 1; j < len(idx); j++ {
			if idx[j] < idx[i] {
				idx[i], idx[j] = idx[j], idx[i]
			}
		}
	}
	return idx
}

func formatMAC(raw []byte) string {
	if len(raw) == 0 {
		return "unknown"
	}
	if len(raw) != 6 {
		return fmt.Sprintf("%x", raw)
	}
	parts := make([]string, 6)
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

func formatDateAndTime(raw []byte) string {
	if len(raw) < 8 {
		return "-"
	}
	year := int(raw[0])*256 + int(raw[1])
	return fmt.Sprintf("%d-%d-%d %02d:%02d:%02d.%d",
		year, int(raw[2]), int(raw[3]), int(raw[4]), int(raw[5]), int(raw[6]), int(raw[7]))
}

func numberToHumanSize(sizeVal, unitVal string) string {
	size, err1 := strconv.ParseInt(strings.Fields(sizeVal)[0], 10, 64)
	unit, err2 := strconv.ParseInt(strings.Fields(unitVal)[0], 10, 64)
	if err1 != nil || err2 != nil || size < 0 || unit < 0 {
		return sizeVal
	}
	bytes := size * unit
	const kb = 1024
	switch {
	case bytes < kb:
		return fmt.Sprintf("%d bytes", bytes)
	case bytes < kb*kb:
		return fmt.Sprintf("%.2f KB", float64(bytes)/kb)
	case bytes < kb*kb*kb:
		return fmt.Sprintf("%.2f MB", float64(bytes)/(kb*kb))
	default:
		return fmt.Sprintf("%.2f GB", float64(bytes)/(kb*kb*kb))
	}
}

func mapIfType(t string) string {
	n, _ := strconv.Atoi(strings.TrimSpace(t))
	types := map[int]string{
		1: "other", 2: "regular1822", 3: "hdh1822", 4: "ddn-x25", 5: "rfc877-x25",
		6: "ethernet-csmacd", 7: "iso88023-csmacd", 8: "iso88024-tokenBus", 9: "iso88025-tokenRing",
		10: "iso88026-man", 11: "starLan", 12: "proteon-10Mbit", 13: "proteon-80Mbit", 14: "hyperchannel",
		15: "fddi", 16: "lapb", 17: "sdlc", 18: "ds1", 19: "e1", 20: "basicISDN", 21: "primaryISDN",
		22: "propPointToPointSerial", 23: "ppp", 24: "softwareLoopback", 25: "eon", 26: "ethernet-3Mbit",
		27: "nsip", 28: "slip", 29: "ultra", 30: "ds3", 31: "sip", 32: "frame-relay",
	}
	if v, ok := types[n]; ok {
		return v
	}
	return "unknown"
}

func mapIfStatus(s string) string {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	switch n {
	case 1:
		return "up"
	case 2:
		return "down"
	case 3:
		return "testing"
	default:
		return "unknown"
	}
}

func mapTCPState(s string) string {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	states := map[int]string{
		1: "closed", 2: "listen", 3: "synSent", 4: "synReceived", 5: "established",
		6: "finWait1", 7: "finWait2", 8: "closeWait", 9: "lastAck", 10: "closing",
		11: "timeWait", 12: "deleteTCB",
	}
	if v, ok := states[n]; ok {
		return v
	}
	return "unknown"
}

func mapStorageType(oid string) string {
	m := map[string]string{
		"1.3.6.1.2.1.25.2.1.1": "Other", "1.3.6.1.2.1.25.2.1.2": "Ram", "1.3.6.1.2.1.25.2.1.3": "Virtual Memory",
		"1.3.6.1.2.1.25.2.1.4": "Fixed Disk", "1.3.6.1.2.1.25.2.1.5": "Removable Disk", "1.3.6.1.2.1.25.2.1.6": "Floppy Disk",
		"1.3.6.1.2.1.25.2.1.7": "Compact Disc", "1.3.6.1.2.1.25.2.1.8": "RamDisk", "1.3.6.1.2.1.25.2.1.9": "Flash Memory",
		"1.3.6.1.2.1.25.2.1.10": "Network Disk",
	}
	oid = strings.TrimPrefix(strings.TrimSpace(oid), ".")
	if v, ok := m[oid]; ok {
		return v
	}
	return "unknown"
}

func mapDeviceType(oid string) string {
	m := map[string]string{
		"1.3.6.1.2.1.25.3.1.1": "Other", "1.3.6.1.2.1.25.3.1.2": "Unknown", "1.3.6.1.2.1.25.3.1.3": "Processor",
		"1.3.6.1.2.1.25.3.1.4": "Network", "1.3.6.1.2.1.25.3.1.5": "Printer", "1.3.6.1.2.1.25.3.1.6": "Disk Storage",
		"1.3.6.1.2.1.25.3.1.10": "Video", "1.3.6.1.2.1.25.3.1.11": "Audio", "1.3.6.1.2.1.25.3.1.12": "Coprocessor",
		"1.3.6.1.2.1.25.3.1.13": "Keyboard", "1.3.6.1.2.1.25.3.1.14": "Modem", "1.3.6.1.2.1.25.3.1.15": "Parallel Port",
		"1.3.6.1.2.1.25.3.1.16": "Pointing", "1.3.6.1.2.1.25.3.1.17": "Serial Port", "1.3.6.1.2.1.25.3.1.18": "Tape",
		"1.3.6.1.2.1.25.3.1.19": "Clock", "1.3.6.1.2.1.25.3.1.20": "Volatile Memory", "1.3.6.1.2.1.25.3.1.21": "Non Volatile Memory",
	}
	oid = strings.TrimPrefix(strings.TrimSpace(oid), ".")
	if v, ok := m[oid]; ok {
		return v
	}
	return "unknown"
}

func mapDeviceStatus(s string) string {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	switch n {
	case 1:
		return "unknown"
	case 2:
		return "running"
	case 3:
		return "warning"
	case 4:
		return "testing"
	case 5:
		return "down"
	default:
		return "unknown"
	}
}

func mapProcessStatus(s string) string {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	switch n {
	case 1:
		return "running"
	case 2:
		return "runnable"
	default:
		return "unknown"
	}
}

func mapFSType(oid string) string {
	m := map[string]string{
		"1.3.6.1.2.1.25.3.9.1": "Other", "1.3.6.1.2.1.25.3.9.2": "Unknown", "1.3.6.1.2.1.25.3.9.3": "BerkeleyFFS",
		"1.3.6.1.2.1.25.3.9.4": "Sys5FS", "1.3.6.1.2.1.25.3.9.5": "Fat", "1.3.6.1.2.1.25.3.9.6": "HPFS",
		"1.3.6.1.2.1.25.3.9.7": "HFS", "1.3.6.1.2.1.25.3.9.8": "MFS", "1.3.6.1.2.1.25.3.9.9": "NTFS",
		"1.3.6.1.2.1.25.3.9.10": "VNode", "1.3.6.1.2.1.25.3.9.11": "Journaled", "1.3.6.1.2.1.25.3.9.12": "iso9660",
		"1.3.6.1.2.1.25.3.9.13": "RockRidge", "1.3.6.1.2.1.25.3.9.14": "NFS", "1.3.6.1.2.1.25.3.9.15": "Netware",
		"1.3.6.1.2.1.25.3.9.16": "AFS", "1.3.6.1.2.1.25.3.9.17": "DFS", "1.3.6.1.2.1.25.3.9.18": "Appleshare",
		"1.3.6.1.2.1.25.3.9.19": "RFS", "1.3.6.1.2.1.25.3.9.20": "DGCFS", "1.3.6.1.2.1.25.3.9.21": "BFS",
		"1.3.6.1.2.1.25.3.9.22": "FAT32", "1.3.6.1.2.1.25.3.9.23": "LinuxExt2",
	}
	oid = strings.TrimPrefix(strings.TrimSpace(oid), ".")
	if v, ok := m[oid]; ok {
		return v
	}
	return "Null"
}

func ipForwardingText(vb *VarBind) string {
	if vb == nil {
		return ""
	}
	n, ok := vbInt(vb)
	if !ok {
		return ""
	}
	if n == 1 {
		return "yes"
	}
	if n == 0 || n == 2 {
		return "no"
	}
	return displayValue(vb)
}

func ifaceSpeedMbps(speed string) string {
	n, err := strconv.ParseInt(strings.TrimSpace(speed), 10, 64)
	if err != nil || n <= 0 {
		return "unknown"
	}
	return fmt.Sprintf("%d Mbps", n/1_000_000)
}