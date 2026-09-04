// Package ospf extracts OSPF MD5 authentication hashes from pcap/pcapng files
// and optionally cracks them with a dictionary attack.
package ospf

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

const tag = "\x1b[97m[OSPF]\x1b[0m"

// Cracker analyses an OSPF pcap/pcapng capture and optionally cracks MD5 hashes.
//
//	--ospf --capture file.pcap[ng]             → print details + write ospf-hashes.txt
//	--ospf --capture file.pcap[ng] --crack     → above + dictionary attack
type Cracker struct {
	PcapFile string
	Wordlist string // optional; required for --crack to run
	Crack    bool
}

// netmd5Hash holds a parsed $netmd5$ credential ready for cracking.
type netmd5Hash struct {
	raw  string   // full formatted string for display
	salt []byte   // raw OSPF packet bytes (MD5 salt)
	dig  [16]byte // 16-byte MD5 digest from the pcap
}

// captureCtx carries shared mutable state across the packet-reading loop.
type captureCtx struct {
	hf            *os.File
	hashes        []netmd5Hash
	totalPkts     int
	ospfPkts      int
	hashesWritten int
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

func parsePcap(path string) ([]netmd5Hash, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	// Read first 4 bytes to identify file format.
	var magicBuf [4]byte
	if _, err := io.ReadFull(f, magicBuf[:]); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	// Interpret as big-endian (byte-order-independent detection).
	magic := uint32(magicBuf[0])<<24 | uint32(magicBuf[1])<<16 | uint32(magicBuf[2])<<8 | uint32(magicBuf[3])

	hf, err := os.Create("ospf-hashes.txt")
	if err != nil {
		return nil, fmt.Errorf("create ospf-hashes.txt: %w", err)
	}
	defer hf.Close()

	ctx := &captureCtx{hf: hf}

	switch magic {
	case 0x0A0D0D0A: // pcapng — magic is the SHB block type (palindrome, endian-independent)
		fmt.Printf("%s Reading %s (pcapng)\n\n", tag, path)
		err = readPcapNG(f, ctx)
	case 0xa1b2c3d4, 0xa1b23c4d: // legacy pcap, big-endian
		err = readLegacyPcap(f, binary.BigEndian, path, ctx)
	case 0xd4c3b2a1, 0x4d3cb2a1: // legacy pcap, little-endian
		err = readLegacyPcap(f, binary.LittleEndian, path, ctx)
	default:
		return nil, fmt.Errorf("unrecognised file format (magic=0x%08x); expected pcap or pcapng", magic)
	}
	if err != nil {
		return nil, err
	}

	fmt.Printf("\n=== SUMMARY ===\n")
	fmt.Printf("Total packets processed: %d\n", ctx.totalPkts)
	fmt.Printf("OSPF packets found: %d\n", ctx.ospfPkts)
	fmt.Printf("MD5 hashes written to ospf-hashes.txt: %d\n", ctx.hashesWritten)

	return ctx.hashes, nil
}

// ─── Legacy pcap reader ───────────────────────────────────────────────────────

func readLegacyPcap(f *os.File, order binary.ByteOrder, path string, ctx *captureCtx) error {
	// 20-byte global header (the first 4-byte magic was already consumed).
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
//
// pcapng block layout:
//
//	[BlockType(4)][BlockTotalLen(4)][Body...][BlockTotalLen(4)]
//
// SHB body:  [ByteOrderMagic(4)][MajorVer(2)][MinorVer(2)][SectionLen(8)][Options...]
// IDB body:  [LinkType(2)][Reserved(2)][SnapLen(4)][Options...]
// EPB body:  [IfaceID(4)][TsHigh(4)][TsLow(4)][CapturedLen(4)][OrigLen(4)][PktData(padded)][Options...]
// SPB body:  [OrigLen(4)][PktData(padded)]
// OPB body:  [IfaceID(2)][Drops(2)][TsHigh(4)][TsLow(4)][CapturedLen(4)][OrigLen(4)][PktData(padded)][Options...]

func readPcapNG(f *os.File, ctx *captureCtx) error {
	// The first 4 bytes (SHB block type = 0x0A0D0D0A) were already consumed by
	// parsePcap. Read the SHB inline to determine byte order, then enter the
	// main block loop.
	order, err := parseSHBHeader(f)
	if err != nil {
		return fmt.Errorf("parse SHB: %w", err)
	}

	// Per-section interface list; reset whenever a new SHB is encountered.
	var ifaces []uint32

	for {
		var blockType uint32
		if err := binary.Read(f, order, &blockType); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("read block type: %w", err)
		}

		// New Section Header Block (multi-section files).
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

		// Read block body + trailing length in one shot.
		// Total block = type(4) + len(4) + body(N) + trailingLen(4) = blockLen bytes.
		// We already read 8 bytes, so remaining = blockLen - 8.
		rem := make([]byte, blockLen-8)
		if _, err := io.ReadFull(f, rem); err != nil {
			return fmt.Errorf("read block body (type=0x%08x): %w", blockType, err)
		}
		// body = rem[0 : blockLen-12],  trailing length = rem[blockLen-12 : blockLen-8]
		body := rem[:blockLen-12]

		switch blockType {
		case 0x00000001: // Interface Description Block
			if len(body) < 4 {
				break
			}
			// LinkType is a 16-bit field at body[0:2], followed by 2 reserved bytes.
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
			// body[0:4] = original packet length; rest (minus padding) is packet data.
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

// parseSHBHeader reads the byte-order magic and block total length from an
// SHB, skips the rest of the block, and returns the file's byte order.
// Called AFTER the 4-byte block type has already been consumed.
func parseSHBHeader(f *os.File) (binary.ByteOrder, error) {
	// Read 8 bytes: [block_total_length(4)][byte_order_magic(4)]
	var preamble [8]byte
	if _, err := io.ReadFull(f, preamble[:]); err != nil {
		return nil, fmt.Errorf("read SHB preamble: %w", err)
	}

	// Byte-order magic is always 0x1A2B3C4D in the file's native byte order.
	// Read it as big-endian to identify which endianness the file uses.
	bigMagic := uint32(preamble[4])<<24 | uint32(preamble[5])<<16 | uint32(preamble[6])<<8 | uint32(preamble[7])

	var order binary.ByteOrder
	var blockLen uint32
	switch bigMagic {
	case 0x1A2B3C4D: // magic in big-endian → file is big-endian
		order = binary.BigEndian
		blockLen = binary.BigEndian.Uint32(preamble[0:4])
	case 0x4D3C2B1A: // magic reversed → file is little-endian
		order = binary.LittleEndian
		blockLen = binary.LittleEndian.Uint32(preamble[0:4])
	default:
		return nil, fmt.Errorf("invalid byte-order magic: 0x%08x", bigMagic)
	}

	// Skip the rest of the SHB.
	// Consumed so far: 4 (block type, by caller) + 8 (preamble) = 12 bytes.
	// blockLen covers the entire block, so remaining = blockLen - 12.
	remaining := int64(blockLen) - 12
	if remaining > 0 {
		if _, err := f.Seek(remaining, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("seek past SHB body: %w", err)
		}
	}
	return order, nil
}

// ifaceLinkType returns the link type for the given interface ID,
// defaulting to 1 (Ethernet) if the interface list is empty or the ID is out of range.
func ifaceLinkType(ifaces []uint32, id uint32) uint32 {
	if int(id) < len(ifaces) {
		return ifaces[id]
	}
	return 1 // Ethernet default
}

// ─── Frame / network layer dispatch ──────────────────────────────────────────

func dispatchFrame(data []byte, linkType uint32, ctx *captureCtx) {
	switch linkType {
	case 1: // Ethernet II
		dispatchEth(data, ctx)

	case 113: // Linux SLL (16-byte header, EtherType at [14:16])
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
	dstMAC := frame[0:6]
	srcMAC := frame[6:12]
	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	ip := frame[14:]

	switch etherType {
	case 0x0800: // IPv4
		if len(ip) < 20 {
			return
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl {
			return
		}
		if ip[9] != 89 {
			return
		}
		srcIP := net.IP(ip[12:16]).String()
		dstIP := net.IP(ip[16:20]).String()
		ipTotalLen := int(uint16(ip[2])<<8 | uint16(ip[3]))
		if ipTotalLen > len(ip) {
			ipTotalLen = len(ip)
		}
		if ipTotalLen <= ihl {
			return
		}
		ospfData := ip[ihl:ipTotalLen]
		if len(ospfData) < 24 {
			return
		}
		ctx.ospfPkts++
		switch ospfData[0] {
		case 2:
			handleV2(ospfData, srcIP, dstIP, fmtMAC(srcMAC), ctx.ospfPkts, ctx)
		case 3:
			handleV3(ospfData, srcIP, dstIP, fmtMAC(srcMAC), fmtMAC(dstMAC), ctx.ospfPkts)
		default:
			fmt.Printf("\n=== OSPF Packet #%d ===\n", ctx.ospfPkts)
			fmt.Printf("- Source address: %s\n- Destination address: %s\n", srcIP, dstIP)
			fmt.Printf("- Unknown OSPF version: %d\n\n", ospfData[0])
		}

	case 0x86DD: // IPv6
		if len(ip) < 40 {
			return
		}
		nextHdr := ip[6]
		srcIP := net.IP(ip[8:24]).String()
		dstIP := net.IP(ip[24:40]).String()
		ipv6PayLen := int(uint16(ip[4])<<8 | uint16(ip[5]))
		ipv6End := 40 + ipv6PayLen
		if ipv6End > len(ip) {
			ipv6End = len(ip)
		}
		ospfData := ip[40:ipv6End]

		switch nextHdr {
		case 89: // OSPF directly
		case 51: // Authentication Header — skip AH to reach OSPF
			if len(ospfData) < 8 || ospfData[0] != 89 {
				return
			}
			ahLen := int(ospfData[1]+2) * 4
			if len(ospfData) < ahLen {
				return
			}
			ospfData = ospfData[ahLen:]
		default:
			return
		}

		if len(ospfData) < 16 {
			return
		}
		ctx.ospfPkts++
		switch ospfData[0] {
		case 2:
			handleV2(ospfData, srcIP, dstIP, fmtMAC(srcMAC), ctx.ospfPkts, ctx)
		case 3:
			handleV3(ospfData, srcIP, dstIP, fmtMAC(srcMAC), fmtMAC(dstMAC), ctx.ospfPkts)
		}
	}
}

func fmtMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// ─── OSPFv2 packet handler ────────────────────────────────────────────────────

func handleV2(payload []byte, srcIP, dstIP, srcMAC string, num int, ctx *captureCtx) {
	fmt.Printf("\n=== OSPFv2 Packet #%d ===\n", num)

	if len(payload) < 24 {
		fmt.Printf("OSPF payload too short: %d bytes\n\n", len(payload))
		return
	}

	version := payload[0]
	msgType := payload[1]
	pktLen := uint16(payload[2])<<8 | uint16(payload[3])
	areaID := net.IPv4(payload[8], payload[9], payload[10], payload[11])
	authType := uint16(payload[14])<<8 | uint16(payload[15])

	fmt.Printf("- Source address: %s\n", srcIP)
	fmt.Printf("- Destination address: %s\n", dstIP)
	if srcMAC != "" {
		fmt.Printf("- Source MAC address: %s\n", srcMAC)
	}
	fmt.Printf("- Protocol version: %d", version)
	if version == 2 {
		fmt.Printf(" (IPv4)\n")
	} else {
		fmt.Printf(" (Unknown)\n")
	}
	fmt.Printf("- Area ID: %s\n", areaID)
	fmt.Printf("- Authentication type: %d", authType)
	switch authType {
	case 0:
		fmt.Printf(" (null)\n")
	case 1:
		fmt.Printf(" (plain-text)\n")
	case 2:
		fmt.Printf(" (cryptographic)\n")
	default:
		fmt.Printf(" (unknown)\n")
	}

	var authData []byte
	var authDataLength uint8

	switch authType {
	case 2:
		keyID := payload[18]
		authDataLength = payload[19]
		seqNum := uint32(payload[20])<<24 | uint32(payload[21])<<16 | uint32(payload[22])<<8 | uint32(payload[23])

		fmt.Printf("- Authentication key ID: %d\n", keyID)
		fmt.Printf("- Authentication data length: %d\n", authDataLength)
		fmt.Printf("- Authentication sequence number: %d\n", seqNum)

		authStart := int(pktLen)
		if len(payload) >= authStart+int(authDataLength) {
			authData = payload[authStart : authStart+int(authDataLength)]
			fmt.Printf("- Authentication data (%d bytes): %x\n", authDataLength, authData)
		} else {
			fmt.Printf("- Authentication data: (hash not found or insufficient data)\n")
		}

	case 1:
		if len(payload) >= 24 {
			raw := payload[16:24]
			authDataLength = 8
			password := strings.TrimRight(string(raw), "\x00")
			fmt.Printf("- Authentication data length: %d\n", authDataLength)
			if password != "" {
				fmt.Printf("- Authentication data: %s\n", password)
			} else {
				fmt.Printf("- Authentication data: %x\n", raw)
			}
		}
	}

	if msgType == 1 && len(payload) >= 44 {
		netMask := net.IPv4(payload[24], payload[25], payload[26], payload[27])
		routerPri := payload[31]
		dr := net.IPv4(payload[36], payload[37], payload[38], payload[39])
		bdr := net.IPv4(payload[40], payload[41], payload[42], payload[43])
		fmt.Printf("- Network mask: %s\n", netMask)
		fmt.Printf("- Router priority: %d\n", routerPri)
		fmt.Printf("- Designated router: %s\n", dr)
		fmt.Printf("- Backup designated router: %s\n", bdr)
	}

	fmt.Println()

	// Emit $netmd5$ hash:
	// auth type 2, Hello packet, 16-byte MD5 digest appended after the packet.
	if authType == 2 && authDataLength == 16 && len(authData) == 16 && msgType == 1 {
		if int(pktLen) <= len(payload) {
			ospfBytes := make([]byte, pktLen)
			copy(ospfBytes, payload[:pktLen])

			hashStr := fmt.Sprintf("$netmd5$%x$%x", ospfBytes, authData)
			fmt.Printf("%s\n", hashStr)

			var dig [16]byte
			copy(dig[:], authData)
			ctx.hashes = append(ctx.hashes, netmd5Hash{raw: hashStr, salt: ospfBytes, dig: dig})
			ctx.hf.WriteString(hashStr + "\n")
			ctx.hashesWritten++
		}
	}
}

// ─── OSPFv3 packet handler ────────────────────────────────────────────────────

func handleV3(payload []byte, srcIP, dstIP, srcMAC, dstMAC string, num int) {
	fmt.Printf("\n=== OSPFv3 Packet #%d ===\n", num)

	if len(payload) < 16 {
		fmt.Printf("OSPFv3 payload too short: %d bytes\n\n", len(payload))
		return
	}

	version := payload[0]
	msgType := payload[1]
	areaID := net.IPv4(payload[8], payload[9], payload[10], payload[11])

	destHint := dstIP
	if dstIP == "ff02::5" {
		destHint = "ff02::5 (multicast)"
	}
	fmt.Printf("- Source address: %s\n", srcIP)
	fmt.Printf("- Destination address: %s\n", destHint)
	if srcMAC != "" {
		fmt.Printf("- Source MAC address: %s\n", srcMAC)
	}
	if dstMAC != "" {
		fmt.Printf("- Destination MAC address: %s\n", dstMAC)
	}
	fmt.Printf("- Protocol version: %d", version)
	if version == 3 {
		fmt.Printf(" (IPv6)\n")
	} else {
		fmt.Printf(" (Unknown)\n")
	}
	fmt.Printf("- Area ID: %s\n", areaID)

	if msgType == 1 && len(payload) >= 36 {
		routerPri := payload[20]
		dr := net.IPv4(payload[28], payload[29], payload[30], payload[31])
		bdr := net.IPv4(payload[32], payload[33], payload[34], payload[35])
		fmt.Printf("- Router priority: %d\n", routerPri)
		fmt.Printf("- Designated router: %s\n", dr)
		fmt.Printf("- Backup designated router: %s\n", bdr)
	}

	fmt.Println()
}

// ─── Dictionary cracker ───────────────────────────────────────────────────────
//
// Algorithm (RFC 2328):
//
//	MD5( ospf_packet_bytes || password_padded_to_16_bytes ) == digest
func crackHashes(hashes []netmd5Hash, wordlistPath string) error {
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

	var key [16]byte

	for sc.Scan() {
		password := sc.Text()
		tested++

		key = [16]byte{}
		copy(key[:], password)

		for i, h := range hashes {
			if md5sum(h.salt, key[:]) == h.dig {
				fmt.Printf("\n%s [+] CRACKED: \"%s\"\n", tag, password)
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

// md5sum computes MD5(a || b) and returns a fixed 16-byte array.
func md5sum(a, b []byte) (out [16]byte) {
	h := md5.New()
	h.Write(a)
	h.Write(b)
	copy(out[:], h.Sum(nil))
	return
}
