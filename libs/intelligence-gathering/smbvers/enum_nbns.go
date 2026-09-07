package smbvers

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

type nbnsEntry struct {
	Name        string
	Suffix      byte
	Group       bool
	Permanent   bool
	Active      bool
	Conflict    bool
	Description string
}

type nbnsResult struct {
	Workgroup string
	Entries   []nbnsEntry
	MAC       string
}

var nbtSuffixDesc = map[byte]struct {
	group bool
	desc  string
}{
	0x01: {false, "Master Browser"},
	0x03: {false, "Messenger Service"},
	0x20: {false, "File Server Service"},
	0x1B: {false, "Domain Master Browser"},
	0x1C: {false, "Domain Controllers"},
	0x1D: {false, "Master Browser"},
	0x1E: {false, "Browser Service Elections"},
}

func queryNBSTAT(host string, timeout time.Duration) (*nbnsResult, error) {
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, "137"))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	query := buildNBSTATQuery()
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseNBSTATResponse(buf[:n])
}

func buildNBSTATQuery() []byte {
	rawName := make([]byte, 16)
	rawName[0] = '*'
	pkt := make([]byte, 0, 64)
	pkt = append(pkt, 0x12, 0x34) // transaction ID
	pkt = append(pkt, 0x00, 0x00) // query flags
	pkt = append(pkt, 0x00, 0x01) // QDCOUNT
	pkt = append(pkt, 0x00, 0x00) // ANCOUNT
	pkt = append(pkt, 0x00, 0x00) // NSCOUNT
	pkt = append(pkt, 0x00, 0x00) // ARCOUNT
	pkt = append(pkt, 0x20)       // name length
	pkt = append(pkt, encodeNetBIOSName(string(rawName))...)
	pkt = append(pkt, 0x00)
	pkt = append(pkt, 0x00, 0x21) // NBSTAT
	pkt = append(pkt, 0x00, 0x01) // IN class
	return pkt
}

func parseNBSTATResponse(data []byte) (*nbnsResult, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("short NBSTAT response")
	}
	ancount := int(binary.BigEndian.Uint16(data[6:8]))
	if ancount == 0 {
		return nil, fmt.Errorf("no NBSTAT answers")
	}
	off := 12
	for i := 0; i < ancount; i++ {
		if off >= len(data) {
			break
		}
		if data[off] == 0xC0 {
			off += 2
		} else {
			ln := int(data[off])
			off += 1 + ln + 1
		}
		if off+10 > len(data) {
			break
		}
		qtype := binary.BigEndian.Uint16(data[off : off+2])
		off += 2
		off += 2 // class
		off += 4 // TTL
		rdlen := int(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
		if off+rdlen > len(data) {
			break
		}
		rdata := data[off : off+rdlen]
		off += rdlen
		if qtype != 0x0021 {
			continue
		}
		return parseNBSTATRData(rdata)
	}
	return nil, fmt.Errorf("no NBSTAT record")
}

func parseNBSTATRData(rdata []byte) (*nbnsResult, error) {
	if len(rdata) < 1 {
		return nil, fmt.Errorf("empty NBSTAT rdata")
	}
	count := int(rdata[0])
	pos := 1
	res := &nbnsResult{}
	for i := 0; i < count; i++ {
		if pos+18 > len(rdata) {
			break
		}
		nameBytes := rdata[pos : pos+16]
		flags := binary.BigEndian.Uint16(rdata[pos+16 : pos+18])
		pos += 18
		name := strings.TrimRight(string(nameBytes[:15]), " ")
		suffix := nameBytes[15]
		entry := nbnsEntry{
			Name:      name,
			Suffix:    suffix,
			Group:     flags&0x8000 != 0,
			Conflict:  flags&0x4000 != 0,
			Active:    flags&0x2000 != 0,
			Permanent: flags&0x1000 != 0,
		}
		switch suffix {
		case 0x00:
			if entry.Group {
				entry.Description = "Domain/Workgroup Name"
				if res.Workgroup == "" {
					res.Workgroup = name
				}
			} else {
				entry.Description = "Workstation Service"
			}
		default:
			if meta, ok := nbtSuffixDesc[suffix]; ok {
				entry.Description = meta.desc
			}
		}
		res.Entries = append(res.Entries, entry)
	}
	if pos+6 <= len(rdata) {
		mac := rdata[pos : pos+6]
		res.MAC = fmt.Sprintf("%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	}
	return res, nil
}

func formatNBNSEntryLine(e nbnsEntry) string {
	suffix := fmt.Sprintf("%02X", e.Suffix)
	group := "        "
	if e.Group {
		group = "<GROUP> "
	}
	state := ""
	if e.Permanent {
		state += "M "
	}
	if e.Active {
		state += "<ACTIVE>"
	}
	state = strings.TrimSpace(state)
	if state == "" {
		state = " "
	} else {
		state = state + " "
	}
	return fmt.Sprintf("- %-15s <%s> - %s%s %s", e.Name, suffix, group, state, e.Description)
}
