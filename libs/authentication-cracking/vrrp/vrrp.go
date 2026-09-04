// Package vrrp extracts VRRPv2 MD5 authentication hashes from pcap/pcapng
// files and optionally cracks them — mirroring $hsrp$ cracking algorithm 
// (VRRP and HSRP share the same format and algorithm).
//
// Hash format (cracked with the hsrp format):
//
//	<N>:$hsrp$<20-byte-salt-hex>$<16-byte-digest-hex>
//
// Salt:   first 20 bytes of VRRP payload with checksum (bytes 6-7) zeroed.
// Digest: last 16 bytes of VRRP payload (MD5 auth data).
//
// Cracking:
//
//	MD5( [key+0x80+zeros+LE_bit_count]_64 || salt || key ) == digest
package vrrp

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

const tag = "\x1b[35m[VRRP]\x1b[0m"

// Cracker analyses a VRRP pcap/pcapng capture and optionally cracks MD5 hashes.
//
//	--vrrp --capture file.pcap[ng]             → print details + write vrrp-hashes.txt
//	--vrrp --capture file.pcap[ng] --crack     → above + dictionary attack
type Cracker struct {
	PcapFile string
	Wordlist string
	Crack    bool
}

type vrrpHash struct {
	raw    string
	salt   []byte
	dig    [16]byte
	pktNum int
}

type captureCtx struct {
	hf            *os.File
	hashes        []vrrpHash
	totalPkts     int
	vrrpPkts      int
	hashesWritten int
}

var vrrpAuthTypes = map[uint8]string{
	0:   "No authentication",
	1:   "Plain-text",
	254: "MD5",
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
		fmt.Printf("    To crack manually:\n")
		return nil
	}
	return crackHashes(hashes, c.Wordlist)
}

// ─── Format detection and top-level reader ────────────────────────────────────

func parsePcap(path string) ([]vrrpHash, error) {
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

	hf, err := os.Create("vrrp-hashes.txt")
	if err != nil {
		return nil, fmt.Errorf("create vrrp-hashes.txt: %w", err)
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
	fmt.Printf("VRRP packets found: %d\n", ctx.vrrpPkts)
	fmt.Printf("MD5 hashes written to vrrp-hashes.txt: %d\n", ctx.hashesWritten)

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
	rest := frame[14:]

	var srcIP, dstIP string
	var payload []byte

	switch etherType {
	case 0x0800: // IPv4
		if len(rest) < 20 {
			return
		}
		ihl := int(rest[0]&0x0f) * 4
		if ihl < 20 || len(rest) < ihl {
			return
		}
		if rest[9] != 112 { // IP protocol 112 = VRRP
			return
		}
		ipTotalLen := int(uint16(rest[2])<<8 | uint16(rest[3]))
		if ipTotalLen > len(rest) {
			ipTotalLen = len(rest)
		}
		if ipTotalLen <= ihl {
			return
		}
		srcIP = net.IP(rest[12:16]).String()
		dstIP = net.IP(rest[16:20]).String()
		payload = rest[ihl:ipTotalLen]

	case 0x86DD: // IPv6 — VRRPv3 uses IPv6; we parse the frame but will skip
		// VRRPv3 packets at handleVRRP (payload[0] != 0x21).
		if len(rest) < 40 {
			return
		}
		payloadLen := int(uint16(rest[4])<<8 | uint16(rest[5]))
		if rest[6] != 112 { // next header = VRRP
			return
		}
		srcIP = net.IP(rest[8:24]).String()
		dstIP = net.IP(rest[24:40]).String()
		end := 40 + payloadLen
		if end > len(rest) {
			end = len(rest)
		}
		payload = rest[40:end]

	default:
		return
	}

	handleVRRP(payload, srcIP, dstIP, fmtMAC(srcMAC), fmtMAC(dstMAC), ctx)
}

func fmtMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// ─── VRRP packet handler ──────────────────────────────────────────────────────
//
// VRRP (RFC 2338) header layout:
//
//	[0]   version(4b) | type(4b)   → 0x21 = VRRPv2 Advertisement
//	[1]   virtual router ID
//	[2]   priority
//	[3]   count IP addresses
//	[4]   authentication type      0=none, 1=plain-text, 254=MD5
//	[5]   advertisement interval (seconds)
//	[6-7] checksum                 ← zeroed in salt
//	[8+]  virtual IP addresses (4 bytes each × count)
//	      authentication data:
//	        type 1  : 8-byte null-terminated password
//	        type 254: 8-byte null pad + 16-byte MD5 digest
func handleVRRP(payload []byte, srcIP, dstIP, srcMAC, dstMAC string, ctx *captureCtx) {
	if len(payload) < 8 {
		return
	}
	// VRRPv2 Advertisement only (convention: data[0] == 0x21)
	if payload[0] != 0x21 {
		return
	}

	ctx.vrrpPkts++
	num := ctx.vrrpPkts

	version := (payload[0] >> 4) & 0x0f
	virtualRouterID := payload[1]
	priority := payload[2]
	countIPAddrs := int(payload[3])
	authTypeVal := payload[4]

	authTypeName, ok := vrrpAuthTypes[authTypeVal]
	if !ok {
		authTypeName = fmt.Sprintf("Unknown (%d)", authTypeVal)
	}

	// Parse virtual IP addresses
	var vips []string
	ipOffset := 8
	for i := 0; i < countIPAddrs && ipOffset+4 <= len(payload); i++ {
		vip := net.IPv4(payload[ipOffset], payload[ipOffset+1], payload[ipOffset+2], payload[ipOffset+3])
		vips = append(vips, vip.String())
		ipOffset += 4
	}
	authStart := 8 + countIPAddrs*4

	// Extract auth payload
	var plainTextPass string
	var md5Digest []byte
	if authTypeVal == 1 && authStart+8 <= len(payload) {
		plainTextPass = extractPlainText(payload[authStart : authStart+8])
	} else if authTypeVal == 254 && len(payload) >= 16 {
		md5Digest = payload[len(payload)-16:]
	}

	// ── Display ───────────────────────────────────────────────────────────────
	fmt.Printf("\n=== VRRP Packet #%d ===\n", num)
	fmt.Printf("%s\n", tag)
	fmt.Printf("- Source address: %s\n", srcIP)
	fmt.Printf("- Destination address: %s\n", dstIP)
	fmt.Printf("- Source MAC address: %s\n", srcMAC)
	fmt.Printf("- Destination MAC address: %s\n", dstMAC)
	fmt.Printf("- Protocol version: %d\n", version)
	fmt.Printf("- Virtual router ID: %d\n", virtualRouterID)
	fmt.Printf("- Router priority: %d\n", priority)
	fmt.Printf("- Authentication type: %s\n", authTypeName)

	if plainTextPass != "" {
		fmt.Printf("- Authentication string: %s\n", plainTextPass)
	} else if len(md5Digest) == 16 {
		fmt.Printf("- MD5 authentication data: %x\n", md5Digest)
	} else if authTypeName != "No authentication" {
		fmt.Printf("- Authentication data: Not readable\n")
	}

	switch len(vips) {
	case 0:
		fmt.Printf("- Virtual address: Not found\n")
	case 1:
		fmt.Printf("- Virtual address: %s\n", vips[0])
	default:
		fmt.Printf("- Virtual addresses: %s\n", strings.Join(vips, ", "))
	}

	// ── Hash generation (MD5 auth only) ──────────────────────────────────────
	// Salt: first 20 bytes of payload with checksum (bytes 6-7) zeroed.
	// Digest: last 16 bytes. Minimum packet size for 1 VIP = 36 bytes.
	if authTypeVal == 254 && len(md5Digest) == 16 && len(payload) >= 20 {
		salt := make([]byte, 20)
		copy(salt, payload[:20])
		salt[6] = 0
		salt[7] = 0

		var dig [16]byte
		copy(dig[:], md5Digest)

		hashStr := fmt.Sprintf("%d:$hsrp$%x$%x", num, salt, md5Digest)
		fmt.Printf("%s\n", hashStr)

		h := vrrpHash{raw: hashStr, salt: salt, dig: dig, pktNum: num}
		ctx.hashes = append(ctx.hashes, h)
		fmt.Fprintln(ctx.hf, hashStr)
		ctx.hashesWritten++
	}

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
//
// VRRP MD5 uses the same algorithm as HSRP:
//
//	MD5( [key + 0x80 + zeros + LE_bit_count]_64bytes || salt || key ) == digest
func crackHashes(hashes []vrrpHash, wordlistPath string) error {
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
// MD5( [key + 0x80 + zeros + LE_bit_count]_64bytes || salt || key ) = digest
func computeHSRPMD5(password, salt []byte) [16]byte {
	pwLen := len(password)
	if pwLen > 55 { // PLAINTEXT_LENGTH = 55
		pwLen = 55
	}
	pw := password[:pwLen]

	// Synthetic 64-byte first block: key with single-block MD5 padding.
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
