// Package glbp extracts GLBP MD5 authentication hashes from pcap/pcapng files
// and optionally cracks them.
//
// hash format:
//
//	<N>:$hsrp$<salt_hex>$<16-byte-digest-hex>
//
// Two MD5 algo types are supported:
//
//	algo_type==2 "MD5 string": Auth TLV total-len>=20, auth_data_len==16
//	    digest  = payload[16:32]
//	    salt    = payload[0:16] + srcIP(4) + zeros(12) + extra_TLVs
//
//	algo_type==3 "MD5 chain": Auth TLV total-len>=24, auth_data_len==20
//	    digest  = payload[20:36]
//	    salt    = payload[0:20] + srcIP(4) + zeros(12) + extra_TLVs
//
// extra_TLVs: TLV types 1, 2, 4 appended in order starting at
//
//	offset (12 + auth_tlv_total_len); stop on any other type.
//
// Cracking:
//
//	MD5( [key + 0x80 + zeros + LE_bit_count]_64bytes || salt || key ) == digest
package glbp

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

const tag = "\x1b[92m[GLBP]\x1b[0m"

// Cracker analyses a GLBP pcap/pcapng capture and optionally cracks MD5 hashes.
type Cracker struct {
	PcapFile string
	Wordlist string
	Crack    bool
}

type glbpHash struct {
	raw    string
	salt   []byte
	dig    [16]byte
	pktNum int
}

type captureCtx struct {
	hf            *os.File
	hashes        []glbpHash
	totalPkts     int
	glbpPkts      int
	hashesWritten int
}

var vgStates = map[uint8]string{
	0: "Initial", 1: "Listen", 2: "Standby", 32: "Active",
}
var vfStates = map[uint8]string{
	0: "Initial", 1: "Listen", 2: "Standby", 3: "Disabled", 32: "Active",
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

// ─── Format detection ─────────────────────────────────────────────────────────

func parsePcap(path string) ([]glbpHash, error) {
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

	hf, err := os.Create("glbp-hashes.txt")
	if err != nil {
		return nil, fmt.Errorf("create glbp-hashes.txt: %w", err)
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
	fmt.Printf("GLBP packets found: %d\n", ctx.glbpPkts)
	fmt.Printf("MD5 hashes written to glbp-hashes.txt: %d\n", ctx.hashesWritten)

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
			dispatchFrame(pkt, lt, ctx)

		case 0x00000003: // Simple Packet Block
			if len(body) < 4 {
				break
			}
			capturedLen := uint32(len(body) - 4)
			pkt := body[4 : 4+capturedLen]
			lt := ifaceLinkType(ifaces, 0)
			ctx.totalPkts++
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

// ─── Frame dispatch ───────────────────────────────────────────────────────────

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
	rest := frame[14:]

	// GLBP is IPv4 only
	if etherType != 0x0800 {
		return
	}
	if len(rest) < 20 {
		return
	}
	ihl := int(rest[0]&0x0f) * 4
	if ihl < 20 || len(rest) < ihl {
		return
	}
	if rest[9] != 17 { // UDP
		return
	}

	ipTotalLen := int(uint16(rest[2])<<8 | uint16(rest[3]))
	if ipTotalLen > len(rest) {
		ipTotalLen = len(rest)
	}
	if ipTotalLen <= ihl+8 {
		return
	}

	srcIP := net.IP(rest[12:16]).String()
	dstIP := net.IP(rest[16:20]).String()

	// Copy source IP raw bytes — needed for GLBP salt
	srcIPRaw := make([]byte, 4)
	copy(srcIPRaw, rest[12:16])

	udp := rest[ihl:]
	if len(udp) < 8 {
		return
	}
	dstPort := uint16(udp[2])<<8 | uint16(udp[3])
	srcPort := uint16(udp[0])<<8 | uint16(udp[1])
	if dstPort != 3222 && srcPort != 3222 {
		return
	}

	udpLen := int(uint16(udp[4])<<8 | uint16(udp[5]))
	payloadLen := udpLen - 8
	if payloadLen <= 0 || len(udp) < 8+payloadLen {
		return
	}
	payload := udp[8 : 8+payloadLen]

	handleGLBP(payload, srcIP, dstIP, fmtMAC(srcMAC), fmtMAC(dstMAC), srcIPRaw, ctx)
}

func fmtMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// ─── GLBP payload handler ─────────────────────────────────────────────────────
//
// GLBP UDP payload:
//
//	[0]    version (must be 1)
//	[1]    reserved
//	[2-3]  group (big-endian)
//	[4-11] owner VMAC / reserved
//	[12+]  TLVs: type(1) | total_length(1) | data(total_length-2)
//
// Auth TLV (type 3) at offset 12: tlv_type must be 3
//
//	[+0] type=3
//	[+1] total_length (authTLVLen)
//	[+2] algo_type    — 2: MD5 string, 3: MD5 chain
//	[+3] auth_data_len — 16 for type 2, 20 for type 3
//	[+4…] auth_data   — for type 3: 4-byte key + 16-byte digest
//
// Hello TLV (type 1): [+3]=VG state, [+5]=hello priority, [last-4:]=virtual IPv4
// RR TLV    (type 2): [+3]=VF state, [+5]=VF priority, [+6]=weight
func handleGLBP(payload []byte, srcIP, dstIP, srcMAC, dstMAC string, srcIPRaw []byte, ctx *captureCtx) {
	// version check and minimum length
	if len(payload) < 13 || payload[0] != 1 {
		return
	}

	// Auth TLV must be first (at offset 12)
	if payload[12] != 3 {
		return
	}

	ctx.glbpPkts++
	num := ctx.glbpPkts

	version := payload[0]
	group := uint16(payload[2])<<8 | uint16(payload[3])

	// ── Scan TLVs for display values ─────────────────────────────────────────
	authTypeName := "No authentication"
	var plainTextPass string
	var md5DigestHex string
	vgState := ""
	helloPriority := uint8(0)
	vfState := ""
	vfPriority := uint8(0)
	weight := uint8(0)
	virtualAddress := ""

	off := 12
	for off+1 < len(payload) {
		tlvType := payload[off]
		tlvLen := int(payload[off+1])
		if tlvLen < 2 || off+tlvLen > len(payload) {
			break
		}

		switch tlvType {
		case 3: // Auth TLV
			if tlvLen >= 4 {
				algoType := payload[off+2]
				authDataLen := int(payload[off+3])
				switch algoType {
				case 0:
					authTypeName = "No authentication"
				case 1:
					authTypeName = "Plain-text"
					if authDataLen > 0 && off+4+authDataLen <= len(payload) {
						plainTextPass = extractPlainText(payload[off+4 : off+4+authDataLen])
					}
				case 2:
					// MD5 string: digest is the full auth_data (16 bytes)
					authTypeName = "MD5"
					if authDataLen == 16 && off+4+16 <= len(payload) {
						md5DigestHex = fmt.Sprintf("%x", payload[off+4:off+20])
					}
				case 3:
					// MD5 chain: 4-byte key then 16-byte digest
					authTypeName = "MD5"
					if authDataLen == 20 && off+8+16 <= len(payload) {
						md5DigestHex = fmt.Sprintf("%x", payload[off+8:off+24])
					}
				}
			}

		case 1: // Hello TLV
			if tlvLen >= 26 {
				if off+3 < len(payload) {
					if name, ok := vgStates[payload[off+3]]; ok {
						vgState = name
					} else {
						vgState = fmt.Sprintf("Unknown (%d)", payload[off+3])
					}
				}
				if off+5 < len(payload) {
					helloPriority = payload[off+5]
				}
				vipOff := off + tlvLen - 4
				if vipOff >= off+2 && vipOff+3 < len(payload) {
					vip := net.IPv4(payload[vipOff], payload[vipOff+1], payload[vipOff+2], payload[vipOff+3])
					virtualAddress = vip.String()
				}
			}

		case 2: // Request/Response TLV — first occurrence only
			if vfState == "" && tlvLen >= 18 {
				if off+3 < len(payload) {
					if name, ok := vfStates[payload[off+3]]; ok {
						vfState = name
					} else {
						vfState = fmt.Sprintf("Unknown (%d)", payload[off+3])
					}
				}
				if off+5 < len(payload) {
					vfPriority = payload[off+5]
				}
				if off+6 < len(payload) {
					weight = payload[off+6]
				}
			}
		}

		off += tlvLen
	}

	// ── Display ───────────────────────────────────────────────────────────────
	fmt.Printf("\n=== GLBP Packet #%d ===\n", num)
	fmt.Printf("%s\n", tag)
	fmt.Printf("- Source address: %s\n", srcIP)
	fmt.Printf("- Destination address: %s\n", dstIP)
	fmt.Printf("- Source MAC address: %s\n", srcMAC)
	fmt.Printf("- Destination MAC address: %s\n", dstMAC)
	fmt.Printf("- Protocol version: %d\n", version)
	fmt.Printf("- GLBP group: %d\n", group)
	fmt.Printf("- VG state: %s\n", vgState)
	fmt.Printf("- GLBP hello priority: %d\n", helloPriority)
	fmt.Printf("- VF state: %s\n", vfState)
	fmt.Printf("- VF priority: %d\n", vfPriority)
	fmt.Printf("- Weight: %d\n", weight)
	fmt.Printf("- Virtual address: %s\n", virtualAddress)
	fmt.Printf("- Authentication type: %s\n", authTypeName)
	if plainTextPass != "" {
		fmt.Printf("- Plain-text password: %s\n", plainTextPass)
	} else if md5DigestHex != "" {
		fmt.Printf("- MD5 authentication data: %s\n", md5DigestHex)
	}

	// ── Hash generation ───────────────────────────────────────────────────────
	//
	// Requirements (both algo types):
	//   payload[12]==3  (Auth TLV first — already checked above)
	//   payload[14]==algo_type (2 or 3)
	//   payload[15]==auth_data_len (16 for type 2, 20 for type 3)
	//   payload[13]==authTLVLen (>=20 for type 2, >=24 for type 3)
	//
	// Extra TLVs (glbp_append_tlvs): types 1, 2, 4 in order; break on anything else.
	algoType := payload[14]
	authDataLen := int(payload[15])
	authTLVLen := int(payload[13])        // total Auth TLV length
	extraStart := 12 + authTLVLen         // where extra TLVs begin

	var digest []byte
	var saltHead []byte

	switch algoType {
	case 2:
		// if auth_length != 16 or len(data) < 32: continue
		// if auth_tlv_length < 20: continue
		if authDataLen != 16 || authTLVLen < 20 || len(payload) < 32 {
			fmt.Println()
			return
		}
		digest = payload[16:32]   // h = tohex(data[16:32])
		saltHead = payload[0:16]  // salt = data[0:16] + ...

	case 3:
		// if auth_length != 20 or len(data) < 36: continue
		// if auth_tlv_length < 24: continue
		if authDataLen != 20 || authTLVLen < 24 || len(payload) < 36 {
			fmt.Println()
			return
		}
		digest = payload[20:36]   // h = tohex(data[20:36])
		saltHead = payload[0:20]  // salt = data[0:20] + ...

	default:
		fmt.Println()
		return
	}

	// Build salt: saltHead + source_geoip(4) + zeros(12) + glbp_append_tlvs(...)
	salt := make([]byte, 0, 256)
	salt = append(salt, saltHead...)
	salt = append(salt, srcIPRaw...)         // source_geoip = ip_headers[-8:-4] = src IPv4
	salt = append(salt, make([]byte, 12)...) // b"\x00" * 12

	// glbp_append_tlvs: while tlv_type in (1, 2, 4): append full TLV; else break
	xOff := extraStart
	for xOff+1 < len(payload) {
		xt := payload[xOff]
		xl := int(payload[xOff+1])
		if xl < 2 || xOff+xl > len(payload) {
			break
		}
		if xt != 1 && xt != 2 && xt != 4 {
			break
		}
		salt = append(salt, payload[xOff:xOff+xl]...)
		xOff += xl
	}

	var dig [16]byte
	copy(dig[:], digest)

	// Output matches: "%s:$hsrp$%s$%s\n" % (index, tohex(salt), h)
	hashStr := fmt.Sprintf("%d:$hsrp$%x$%x", num, salt, digest)
	fmt.Printf("%s\n", hashStr)

	ctx.hashes = append(ctx.hashes, glbpHash{raw: hashStr, salt: salt, dig: dig, pktNum: num})
	fmt.Fprintln(ctx.hf, hashStr)
	ctx.hashesWritten++

	fmt.Println()
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

func crackHashes(hashes []glbpHash, wordlistPath string) error {
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

// computeHSRPMD5
//
// This tool stores the key in a 64-byte buffer (already zeroed). It places MD5-style
// padding into that buffer and calls MD5_Update once with the full 64 bytes,
// then continues with salt + key, then MD5_Final.
//
//	block[0:len]   = key
//	block[len]     = 0x80
//	block[56:60]   = LE(len*8)  ← block[14] as uint32 (byte offset 56)
//	block[60:64]   = 0x00…
//
//	result = MD5_Final( MD5_Init → Update(block_64) → Update(salt) → Update(key) )
func computeHSRPMD5(password, salt []byte) [16]byte {
	pwLen := len(password)
	if pwLen > 55 { // PLAINTEXT_LENGTH = 55
		pwLen = 55
	}
	pw := password[:pwLen]

	var block [64]byte           // zero-initialised
	copy(block[:], pw)
	block[pwLen] = 0x80
	binary.LittleEndian.PutUint32(block[56:60], uint32(pwLen)*8) // block[14] = len<<3

	h := md5.New()
	h.Write(block[:])  // MD5_Update(block, 64)
	h.Write(salt)      // MD5_Update(salt, salt_len)
	h.Write(pw)        // MD5_Update(key, len)

	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}
