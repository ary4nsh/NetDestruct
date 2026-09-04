// Package hsrp extracts HSRP MD5 authentication hashes from pcap/pcapng files
// and optionally cracks them with a dictionary attack.
package hsrp

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

const tag = "\x1b[33m[HSRP]\x1b[0m"

// Cracker analyses an HSRP pcap/pcapng capture and optionally cracks MD5 hashes.
//
//	--hsrp --capture file.pcap[ng]             → print details + write hsrp-hashes.txt
//	--hsrp --capture file.pcap[ng] --crack     → above + dictionary attack
type Cracker struct {
	PcapFile string
	Wordlist string
	Crack    bool
}

type hsrpHash struct {
	raw    string
	salt   []byte
	dig    [16]byte
	pktNum int
}

type captureCtx struct {
	hf            *os.File
	hashes        []hsrpHash
	totalPkts     int
	hsrpPkts      int
	hashesWritten int
}

var v1States = map[uint8]string{
	0:  "Initial",
	1:  "Learn",
	2:  "Listen",
	4:  "Speak",
	8:  "Standby",
	16: "Active",
}

var v2States = map[uint8]string{
	0: "Initial",
	1: "Learn",
	2: "Listen",
	4: "Speak",
	6: "Active",
	8: "Standby",
}

// ─── Entry point ─────────────────────────────────────────────────────────────

func (c *Cracker) Run() error {
	hashes, err := parsePcap(c.PcapFile)
	if err != nil {
		return err
	}
	if !c.Crack {
		return nil
	}
	if len(hashes) == 0 {
		fmt.Printf("\n%s No crackable MD5 hashes found in capture.\n", tag)
		return nil
	}
	if c.Wordlist == "" {
		fmt.Printf("\n%s --crack requires --wordlist <file>\n", tag)
		return nil
	}
	return crackHashes(hashes, c.Wordlist)
}

// ─── Format detection and top-level reader ────────────────────────────────────

func parsePcap(path string) ([]hsrpHash, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var magicBuf [4]byte
	if _, err := io.ReadFull(f, magicBuf[:]); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	magic := uint32(magicBuf[0])<<24 | uint32(magicBuf[1])<<16 | uint32(magicBuf[2])<<8 | uint32(magicBuf[3])

	hf, err := os.Create("hsrp-hashes.txt")
	if err != nil {
		return nil, fmt.Errorf("create hsrp-hashes.txt: %w", err)
	}
	defer hf.Close()

	ctx := &captureCtx{hf: hf}

	switch magic {
	case 0x0A0D0D0A:
		fmt.Printf("%s Reading %s (pcapng)\n\n", tag, path)
		err = readPcapNG(f, ctx)
	case 0xa1b2c3d4, 0xa1b23c4d:
		err = readLegacyPcap(f, binary.BigEndian, path, ctx)
	case 0xd4c3b2a1, 0x4d3cb2a1:
		err = readLegacyPcap(f, binary.LittleEndian, path, ctx)
	default:
		return nil, fmt.Errorf("unrecognised file format (magic=0x%08x); expected pcap or pcapng", magic)
	}
	if err != nil {
		return nil, err
	}

	fmt.Printf("\n=== SUMMARY ===\n")
	fmt.Printf("Total packets processed: %d\n", ctx.totalPkts)
	fmt.Printf("HSRP packets found: %d\n", ctx.hsrpPkts)
	fmt.Printf("MD5 hashes written to hsrp-hashes.txt: %d\n", ctx.hashesWritten)

	return ctx.hashes, nil
}

// ─── Legacy pcap reader ───────────────────────────────────────────────────────

func readLegacyPcap(f *os.File, order binary.ByteOrder, path string, ctx *captureCtx) error {
	var ghdr struct {
		Major, Minor uint16
		Zone         int32
		Sigfigs      uint32
		Snaplen      uint32
		Network      uint32
	}
	if err := binary.Read(f, order, &ghdr); err != nil {
		return fmt.Errorf("read global header: %w", err)
	}
	fmt.Printf("%s Reading %s (pcap, link-type %d)\n\n", tag, path, ghdr.Network)

	var phdr struct {
		TsSec, TsUsec    uint32
		InclLen, OrigLen uint32
	}
	for {
		if err := binary.Read(f, order, &phdr); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("read packet header: %w", err)
		}
		pkt := make([]byte, phdr.InclLen)
		if _, err := io.ReadFull(f, pkt); err != nil {
			return fmt.Errorf("read packet data: %w", err)
		}
		ctx.totalPkts++
		if ctx.totalPkts%100 == 0 {
			fmt.Printf("Processed %d packets...\n", ctx.totalPkts)
		}
		dispatchFrame(pkt, ghdr.Network, ctx)
	}
	return nil
}

// ─── pcapng reader ────────────────────────────────────────────────────────────

func readPcapNG(f *os.File, ctx *captureCtx) error {
	order, err := parseSHBHeader(f)
	if err != nil {
		return fmt.Errorf("parse SHB: %w", err)
	}

	var ifaces []uint32

	for {
		var blockType uint32
		if err := binary.Read(f, order, &blockType); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("read block type: %w", err)
		}

		if blockType == 0x0A0D0D0A {
			order, err = parseSHBHeader(f)
			if err != nil {
				return fmt.Errorf("parse SHB: %w", err)
			}
			ifaces = ifaces[:0]
			continue
		}

		var blockLen uint32
		if err := binary.Read(f, order, &blockLen); err != nil {
			return fmt.Errorf("read block length: %w", err)
		}
		if blockLen < 12 {
			return fmt.Errorf("invalid block length %d for type 0x%08x", blockLen, blockType)
		}

		rem := make([]byte, blockLen-8)
		if _, err := io.ReadFull(f, rem); err != nil {
			return fmt.Errorf("read block body (type=0x%08x): %w", blockType, err)
		}
		body := rem[:blockLen-12]

		switch blockType {
		case 0x00000001: // Interface Description Block
			if len(body) < 4 {
				break
			}
			lt := uint32(order.Uint16(body[0:2]))
			ifaces = append(ifaces, lt)

		case 0x00000006: // Enhanced Packet Block
			if len(body) < 20 {
				break
			}
			ifaceID := order.Uint32(body[0:4])
			capturedLen := order.Uint32(body[12:16])
			if uint32(len(body)) < 20+capturedLen {
				break
			}
			pkt := body[20 : 20+capturedLen]
			lt := ifaceLinkType(ifaces, ifaceID)
			ctx.totalPkts++
			if ctx.totalPkts%100 == 0 {
				fmt.Printf("Processed %d packets...\n", ctx.totalPkts)
			}
			dispatchFrame(pkt, lt, ctx)

		case 0x00000003: // Simple Packet Block
			if len(body) < 4 {
				break
			}
			capturedLen := uint32(len(body) - 4)
			pkt := body[4 : 4+capturedLen]
			lt := ifaceLinkType(ifaces, 0)
			ctx.totalPkts++
			if ctx.totalPkts%100 == 0 {
				fmt.Printf("Processed %d packets...\n", ctx.totalPkts)
			}
			dispatchFrame(pkt, lt, ctx)

		case 0x00000002: // Obsolete Packet Block
			if len(body) < 20 {
				break
			}
			ifaceID := uint32(order.Uint16(body[0:2]))
			capturedLen := order.Uint32(body[12:16])
			if uint32(len(body)) < 20+capturedLen {
				break
			}
			pkt := body[20 : 20+capturedLen]
			lt := ifaceLinkType(ifaces, ifaceID)
			ctx.totalPkts++
			if ctx.totalPkts%100 == 0 {
				fmt.Printf("Processed %d packets...\n", ctx.totalPkts)
			}
			dispatchFrame(pkt, lt, ctx)
		}
	}
	return nil
}

func parseSHBHeader(f *os.File) (binary.ByteOrder, error) {
	var preamble [8]byte
	if _, err := io.ReadFull(f, preamble[:]); err != nil {
		return nil, fmt.Errorf("read SHB preamble: %w", err)
	}
	bigMagic := uint32(preamble[4])<<24 | uint32(preamble[5])<<16 | uint32(preamble[6])<<8 | uint32(preamble[7])

	var order binary.ByteOrder
	var blockLen uint32
	switch bigMagic {
	case 0x1A2B3C4D:
		order = binary.BigEndian
		blockLen = binary.BigEndian.Uint32(preamble[0:4])
	case 0x4D3C2B1A:
		order = binary.LittleEndian
		blockLen = binary.LittleEndian.Uint32(preamble[0:4])
	default:
		return nil, fmt.Errorf("invalid byte-order magic: 0x%08x", bigMagic)
	}

	remaining := int64(blockLen) - 12
	if remaining > 0 {
		if _, err := f.Seek(remaining, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("seek past SHB body: %w", err)
		}
	}
	return order, nil
}

func ifaceLinkType(ifaces []uint32, id uint32) uint32 {
	if int(id) < len(ifaces) {
		return ifaces[id]
	}
	return 1
}

// ─── Frame / network layer dispatch ──────────────────────────────────────────

func dispatchFrame(data []byte, linkType uint32, ctx *captureCtx) {
	switch linkType {
	case 1:
		dispatchEth(data, ctx)
	case 113: // Linux SLL
		if len(data) < 16 {
			return
		}
		fake := make([]byte, 14+len(data[16:]))
		fake[12] = data[14]
		fake[13] = data[15]
		copy(fake[14:], data[16:])
		dispatchEth(fake, ctx)
	case 101, 228: // Raw IPv4
		if len(data) < 20 {
			return
		}
		fake := make([]byte, 14+len(data))
		fake[12] = 0x08
		fake[13] = 0x00
		copy(fake[14:], data)
		dispatchEth(fake, ctx)
	}
}

func dispatchEth(frame []byte, ctx *captureCtx) {
	if len(frame) < 14 {
		return
	}
	srcMAC := frame[6:12]
	dstMAC := frame[0:6]
	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	ip := frame[14:]

	if etherType != 0x0800 { // IPv4 only; HSRP runs on IPv4
		return
	}
	if len(ip) < 20 {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return
	}
	proto := ip[9]
	if proto != 17 { // UDP
		return
	}

	ipTotalLen := int(uint16(ip[2])<<8 | uint16(ip[3]))
	if ipTotalLen > len(ip) {
		ipTotalLen = len(ip)
	}
	if ipTotalLen <= ihl+8 {
		return
	}

	udp := ip[ihl:]
	if len(udp) < 8 {
		return
	}
	srcPort := uint16(udp[0])<<8 | uint16(udp[1])
	dstPort := uint16(udp[2])<<8 | uint16(udp[3])
	if srcPort != 1985 && dstPort != 1985 {
		return
	}

	udpLen := int(uint16(udp[4])<<8 | uint16(udp[5]))
	payloadLen := udpLen - 8
	if payloadLen <= 0 || len(udp) < 8+payloadLen {
		return
	}
	payload := udp[8 : 8+payloadLen]

	srcIP := net.IP(ip[12:16]).String()
	dstIP := net.IP(ip[16:20]).String()

	handleHSRP(payload, srcIP, dstIP, fmtMAC(srcMAC), fmtMAC(dstMAC), ctx)
}

func fmtMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// ─── HSRP packet handler ──────────────────────────────────────────────────────

func handleHSRP(payload []byte, srcIP, dstIP, srcMAC, dstMAC string, ctx *captureCtx) {
	if len(payload) < 4 {
		return
	}

	// HSRPv2: starts with Group State TLV (type=1)
	if payload[0] == 0x01 {
		handleHSRPv2(payload, srcIP, dstIP, srcMAC, dstMAC, ctx)
		return
	}

	// HSRPv1/v0: starts with version byte 0x00 and opcode 0x00 (Hello)
	if payload[0] == 0x00 && len(payload) >= 20 {
		handleHSRPv1(payload, srcIP, dstIP, srcMAC, dstMAC, ctx)
		return
	}
}

// handleHSRPv1 processes HSRP version 0 (the common "HSRPv1") packets.
// MD5 auth: exactly 50-byte payload, TLV type 4 at offset 20.
func handleHSRPv1(payload []byte, srcIP, dstIP, srcMAC, dstMAC string, ctx *captureCtx) {
	ctx.hsrpPkts++
	num := ctx.hsrpPkts

	state := stateName(payload[2], v1States)
	helloTime := int(payload[3])
	holdTime := int(payload[4])
	priority := int(payload[5])
	group := int(payload[6])

	var virtualIP string
	if len(payload) >= 20 {
		virtualIP = net.IPv4(payload[16], payload[17], payload[18], payload[19]).String()
	}

	fmt.Printf("\n=== HSRP Packet #%d ===\n", num)
	fmt.Printf("%s\n", tag)
	fmt.Printf("- Source address: %s\n", srcIP)
	fmt.Printf("- Destination address: %s\n", dstIP)
	fmt.Printf("- Source MAC address: %s\n", srcMAC)
	fmt.Printf("- Destination MAC address: %s\n", dstMAC)
	fmt.Printf("- Protocol version: 0\n")
	fmt.Printf("- State: %s\n", state)
	fmt.Printf("- Hello time: %d seconds\n", helloTime)
	fmt.Printf("- Hold time: %d seconds\n", holdTime)
	fmt.Printf("- Router priority: %d\n", priority)
	fmt.Printf("- HSRP group: %d\n", group)
	fmt.Printf("- Virtual IP address: %s\n", virtualIP)

	// Check for plain-text auth in the 8-byte auth data field (bytes 8-15)
	if len(payload) >= 16 {
		authData := payload[8:16]
		plainText := extractPlainText(authData)
		if plainText != "" {
			fmt.Printf("- Authentication: Plain-text\n")
			fmt.Printf("- Plain-text password: %s\n", plainText)
		}
	}

	// Check for MD5 auth TLV: payload must be exactly 50 bytes, byte[20]=4
	if len(payload) == 50 && payload[20] == 0x04 {
		senderIP := net.IPv4(payload[26], payload[27], payload[28], payload[29]).String()
		keyID := binary.BigEndian.Uint32(payload[30:34])
		digest := payload[34:50]

		fmt.Printf("- Sender's IP address: %s\n", senderIP)
		fmt.Printf("- Authentication: MD5\n")
		fmt.Printf("- MD5 key ID: %d\n", keyID)
		fmt.Printf("- MD5 digest: %x\n", digest)

		// Build salt: first 34 bytes + 16 zero bytes
		salt := make([]byte, 50)
		copy(salt[:34], payload[:34])
		// bytes 34-49 remain zero (digest replaced with zeros)

		hashStr := fmt.Sprintf("$hsrp$%x$%x", salt, digest)
		fmt.Printf("%s\n", hashStr)

		var dig [16]byte
		copy(dig[:], digest)
		h := hsrpHash{raw: hashStr, salt: salt, dig: dig, pktNum: num}
		ctx.hashes = append(ctx.hashes, h)
		ctx.hf.WriteString(hashStr + "\n")
		ctx.hashesWritten++
	}

	fmt.Println()
}

// handleHSRPv2 processes TLV-based HSRP v2 packets.
func handleHSRPv2(payload []byte, srcIP, dstIP, srcMAC, dstMAC string, ctx *captureCtx) {
	ctx.hsrpPkts++
	num := ctx.hsrpPkts

	fmt.Printf("\n=== HSRP Packet #%d ===\n", num)
	fmt.Printf("%s\n", tag)
	fmt.Printf("- Source address: %s\n", srcIP)
	fmt.Printf("- Destination address: %s\n", dstIP)
	fmt.Printf("- Source MAC address: %s\n", srcMAC)
	fmt.Printf("- Destination MAC address: %s\n", dstMAC)
	fmt.Printf("- Protocol version: 2\n")

	// Parse TLVs
	offset := 0
	var salt []byte
	var digest []byte
	hasMD5 := false
	state := "Unknown"
	helloTime := 0
	holdTime := 0
	priority := uint32(0)
	group := uint16(0)
	virtualIP := ""
	senderIP := ""
	keyID := uint8(0)
	digestHex := ""
	hasGroupState := false
	hasTextAuth := false
	plainText := ""

	for offset+2 <= len(payload) {
		tlvType := payload[offset]
		tlvLength := int(payload[offset+1])
		totalTLV := tlvLength + 2
		if offset+totalTLV > len(payload) {
			break
		}
		tlvData := payload[offset+2 : offset+totalTLV]

		switch tlvType {
		case 1: // Group State TLV
			if len(tlvData) >= 28 {
				state = stateName(tlvData[2], v2States)
				group = binary.BigEndian.Uint16(tlvData[4:6])
				priority = binary.BigEndian.Uint32(tlvData[12:16])
				helloTime = int(binary.BigEndian.Uint32(tlvData[16:20]))
				holdTime = int(binary.BigEndian.Uint32(tlvData[20:24]))
				virtualIP = net.IPv4(tlvData[24], tlvData[25], tlvData[26], tlvData[27]).String()
				hasGroupState = true
			}
			salt = append(salt, payload[offset:offset+totalTLV]...)

		case 3: // Text Auth TLV
			if len(tlvData) > 0 {
				plainText = extractPlainText(tlvData)
				hasTextAuth = true
			}
			salt = append(salt, payload[offset:offset+totalTLV]...)

		case 4: // MD5 Auth TLV
			if len(tlvData) >= 16 {
				// Sender IP at data[4:8], key ID at data[8], digest = last 16 bytes
				if len(tlvData) >= 8 {
					senderIP = net.IPv4(tlvData[4], tlvData[5], tlvData[6], tlvData[7]).String()
				}
				if len(tlvData) >= 9 {
					keyID = tlvData[8]
				}
				digest = tlvData[len(tlvData)-16:]
				digestHex = fmt.Sprintf("%x", digest)

				// Build zeroed TLV for salt
				zeroedTLV := make([]byte, totalTLV)
				copy(zeroedTLV, payload[offset:offset+totalTLV])
				// Zero the last 16 bytes (digest area)
				for i := totalTLV - 16; i < totalTLV; i++ {
					zeroedTLV[i] = 0
				}
				salt = append(salt, zeroedTLV...)
				hasMD5 = true
			}
		}

		offset += totalTLV
	}

	if hasGroupState {
		fmt.Printf("- State: %s\n", state)
		fmt.Printf("- Hello time: %d seconds\n", helloTime/1000)
		fmt.Printf("- Hold time: %d seconds\n", holdTime/1000)
		fmt.Printf("- Router priority: %d\n", priority)
		fmt.Printf("- HSRP group: %d\n", group)
		fmt.Printf("- Virtual IP address: %s\n", virtualIP)
	}
	if senderIP != "" {
		fmt.Printf("- Sender's IP address: %s\n", senderIP)
	}
	if hasTextAuth && plainText != "" {
		fmt.Printf("- Authentication: Plain-text\n")
		fmt.Printf("- Plain-text password: %s\n", plainText)
	} else if hasMD5 {
		fmt.Printf("- Authentication: MD5\n")
		fmt.Printf("- MD5 key ID: %d\n", keyID)
		fmt.Printf("- MD5 digest: %s\n", digestHex)

		hashStr := fmt.Sprintf("$hsrp$%x$%x", salt, digest)
		fmt.Printf("%s\n", hashStr)

		var dig [16]byte
		copy(dig[:], digest)
		h := hsrpHash{raw: hashStr, salt: salt, dig: dig, pktNum: num}
		ctx.hashes = append(ctx.hashes, h)
		ctx.hf.WriteString(hashStr + "\n")
		ctx.hashesWritten++
	} else if !hasTextAuth {
		fmt.Printf("- Authentication: None\n")
	}

	fmt.Println()
}

func stateName(s uint8, m map[uint8]string) string {
	if name, ok := m[s]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (%d)", s)
}

func extractPlainText(data []byte) string {
	for i, b := range data {
		if b == 0 {
			if i == 0 {
				return ""
			}
			return string(data[:i])
		}
		if b < 32 || b > 126 {
			return ""
		}
	}
	return string(data)
}

// ─── Dictionary cracker ───────────────────────────────────────────────────────
//
// Algorithm:
//
//	MD5( key_padded_64_bytes || salt || key ) == digest
//
// The 64-byte first block contains the key with synthetic MD5 single-block
// padding: 0x80 at position len(key), LE uint32 bit-count at bytes 56-59.
func crackHashes(hashes []hsrpHash, wordlistPath string) error {
	wl, err := os.Open(wordlistPath)
	if err != nil {
		return fmt.Errorf("open wordlist %s: %w", wordlistPath, err)
	}
	defer wl.Close()

	fmt.Printf("\n%s Starting dictionary attack on %d hash(es) using %s...\n", tag, len(hashes), wordlistPath)

	cracked := 0
	tested := 0

	sc := bufio.NewScanner(wl)
	sc.Buffer(make([]byte, 0, 65536), 1024*1024)

	for sc.Scan() {
		password := []byte(sc.Text())
		tested++

		for i, h := range hashes {
			if computeHSRPMD5(password, h.salt) == h.dig {
				fmt.Printf("\n%s [+] CRACKED: \"%s\"\n", tag, string(password))
				fmt.Printf("    Hash #%d: %s\n", i+1, h.raw)
				cracked++
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read wordlist: %w", err)
	}

	fmt.Printf("\n%s Tested %d passwords. Cracked %d / %d hashes.\n", tag, tested, cracked, len(hashes))
	return nil
}

// computeHSRPMD5 algorithm.
// MD5( [key + 0x80 + zeros + LE_bit_count]_64bytes || salt || key ) = digest
func computeHSRPMD5(password, salt []byte) [16]byte {
	pwLen := len(password)
	if pwLen > 55 { // PLAINTEXT_LENGTH = 55
		pwLen = 55
	}
	pw := password[:pwLen]

	// Build the synthetic 64-byte first block (key + MD5 padding for one block).
	var block [64]byte
	copy(block[:], pw)
	block[pwLen] = 0x80
	binary.LittleEndian.PutUint32(block[56:60], uint32(pwLen)*8)

	h := md5.New()
	h.Write(block[:])
	h.Write(salt)
	h.Write(pw)

	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

