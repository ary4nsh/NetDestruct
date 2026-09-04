// Package ntp extracts NTP MD5/SHA authentication hashes from pcap/pcapng files
// and optionally cracks them.
//
// Hash formats (dynamic format with long-salt HEX prefix):
//
//	<N>:$dynamic_2001$<md5_hex>$HEX$<salt_hex>          (16-byte digest)
//	<N>:$dynamic_24$<sha1_hex>$HEX$<salt_hex>           (20-byte digest)
//	<N>:$dynamic_52$<sha224_hex>$HEX$<salt_hex>         (28-byte digest)
//	<N>:$dynamic_62$<sha256_hex>$HEX$<salt_hex>         (32-byte digest)
//	<N>:$dynamic_72$<sha384_hex>$HEX$<salt_hex>         (48-byte digest)
//	<N>:$dynamic_82$<sha512_hex>$HEX$<salt_hex>         (64-byte digest)
//
// Salt construction:
//
//	salt = ntp_payload[0:48]   (full NTP header through Transmit Timestamp)
//
// Key ID = ntp_payload[48:52] (4 bytes, skipped in hash; used for display only)
// Digest = ntp_payload[52:]   (length determines algorithm)
//
// Cracking — all algorithms use: hash_function(password || salt)
//
//	dynamic_2001 = md5($p.$s)    → MD5(password || salt)
//	dynamic_24   = sha1($p.$s)   → SHA1(password || salt)
//	dynamic_52   = sha224($p.$s) → SHA224(password || salt)
//	dynamic_62   = sha256($p.$s) → SHA256(password || salt)
//	dynamic_72   = sha384($p.$s) → SHA384(password || salt)
//	dynamic_82   = sha512($p.$s) → SHA512(password || salt)
package ntp

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

const tag = "\x1b[95m[NTP]\x1b[0m"

// Cracker analyses an NTP pcap/pcapng capture and optionally cracks hashes.
type Cracker struct {
	PcapFile string
	Wordlist string
	Crack    bool
}

type ntpHash struct {
	raw      string
	algo     string // "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"
	salt     []byte // NTP header bytes [0:48]
	dig      []byte // digest bytes
	pktNum   int
}

type captureCtx struct {
	hf            *os.File
	hashes        []ntpHash
	totalPkts     int
	ntpPkts       int
	hashesWritten int
}

var ntpModes = map[uint8]string{
	0: "Reserved", 1: "Symmetric Active", 2: "Symmetric Passive",
	3: "Client", 4: "Server", 5: "Broadcast",
	6: "NTP Control", 7: "Private",
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
		fmt.Printf("\n%s No crackable NTP hashes found in capture.\n", tag)
		return nil
	}
	if c.Wordlist == "" {
		fmt.Printf("\n%s --crack requires --wordlist <file>\n", tag)
		return nil
	}
	return crackHashes(hashes, c.Wordlist)
}

// ─── Format detection ─────────────────────────────────────────────────────────

func parsePcap(path string) ([]ntpHash, error) {
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

	hf, err := os.Create("ntp-hashes.txt")
	if err != nil {
		return nil, fmt.Errorf("create ntp-hashes.txt: %w", err)
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
	fmt.Printf("NTP authenticated packets found: %d\n", ctx.ntpPkts)
	fmt.Printf("Hashes written to ntp-hashes.txt: %d\n", ctx.hashesWritten)

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

	var srcIP, dstIP string

	switch etherType {
	case 0x0800: // IPv4
		if len(rest) < 20 {
			return
		}
		ihl := int(rest[0]&0x0f) * 4
		if ihl < 20 || len(rest) < ihl || rest[9] != 17 { // UDP
			return
		}
		ipTotalLen := int(uint16(rest[2])<<8 | uint16(rest[3]))
		if ipTotalLen > len(rest) {
			ipTotalLen = len(rest)
		}
		if ipTotalLen <= ihl+8 {
			return
		}
		srcIP = net.IP(rest[12:16]).String()
		dstIP = net.IP(rest[16:20]).String()
		udp := rest[ihl:]
		extractNTP(udp, srcIP, dstIP, fmtMAC(srcMAC), fmtMAC(dstMAC), ctx)

	case 0x86DD: // IPv6
		if len(rest) < 40 || rest[6] != 17 { // UDP next header
			return
		}
		payloadLen := int(uint16(rest[4])<<8 | uint16(rest[5]))
		if len(rest) < 40+payloadLen {
			return
		}
		srcIP = net.IP(rest[8:24]).String()
		dstIP = net.IP(rest[24:40]).String()
		udp := rest[40 : 40+payloadLen]
		extractNTP(udp, srcIP, dstIP, fmtMAC(srcMAC), fmtMAC(dstMAC), ctx)
	}
}

func extractNTP(udp []byte, srcIP, dstIP, srcMAC, dstMAC string, ctx *captureCtx) {
	if len(udp) < 8 {
		return
	}
	dstPort := uint16(udp[2])<<8 | uint16(udp[3])
	if dstPort != 123 {
		return
	}

	udpLen := int(uint16(udp[4])<<8 | uint16(udp[5]))
	payloadLen := udpLen - 8
	if payloadLen < 48 || len(udp) < 8+payloadLen {
		return // if len(data) < 48: continue
	}
	data := udp[8 : 8+payloadLen]

	handleNTP(data, srcIP, dstIP, srcMAC, dstMAC, ctx)
}

func fmtMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// ─── NTP payload handler ──────────────────────────────────────────────────────
//
// NTP packet layout (UDP payload):
//
//	[0]    LI(2b) | VN(3b) | Mode(3b)
//	[1]    Stratum
//	[2]    Poll interval (log2 seconds)
//	[3]    Precision (log2 seconds)
//	[4-7]  Root delay
//	[8-11] Root dispersion
//	[12-15] Reference ID
//	[16-23] Reference timestamp
//	[24-31] Origin timestamp
//	[32-39] Receive timestamp
//	[40-47] Transmit timestamp
//	[48-51] Key ID               — skipped in hash, shown in display
//	[52+]   MAC / hash           — length → algorithm
//
// Extraction:
//
//	salt = data[0:48]
//	data = data[48:]        (drop the NTP header)
//	data = data[4:]         (skip Key ID)
//	h    = data             (= original[52:])
//	len(h): 16→MD5, 20→SHA1, 28→SHA224, 32→SHA256, 48→SHA384, 64→SHA512
func handleNTP(data []byte, srcIP, dstIP, srcMAC, dstMAC string, ctx *captureCtx) {
	// Already checked len(data) >= 48 in extractNTP.
	// Need at least 52 bytes for Key ID + any hash.
	if len(data) < 53 {
		return // no auth data after key ID
	}

	salt := data[0:48]
	keyIDBytes := data[48:52]
	digest := data[52:] // after stripping key ID

	if len(digest) == 0 {
		return
	}

	// Decode NTP header fields for display
	firstByte := data[0]
	li := (firstByte >> 6) & 0x03
	version := (firstByte >> 3) & 0x07
	mode := firstByte & 0x07
	stratum := data[1]
	poll := data[2]
	keyID := uint32(keyIDBytes[0])<<24 | uint32(keyIDBytes[1])<<16 | uint32(keyIDBytes[2])<<8 | uint32(keyIDBytes[3])

	modeStr := ntpModes[mode]
	if modeStr == "" {
		modeStr = fmt.Sprintf("Unknown (%d)", mode)
	}

	// Determine algorithm from digest length
	var algoName, dynamicFmt string
	switch len(digest) {
	case 16:
		algoName, dynamicFmt = "MD5", "dynamic_2001"
	case 20:
		algoName, dynamicFmt = "SHA1", "dynamic_24"
	case 28:
		algoName, dynamicFmt = "SHA224", "dynamic_52"
	case 32:
		algoName, dynamicFmt = "SHA256", "dynamic_62"
	case 48:
		algoName, dynamicFmt = "SHA384", "dynamic_72"
	case 64:
		algoName, dynamicFmt = "SHA512", "dynamic_82"
	default:
		fmt.Printf("\n%s Unsupported hash length %d in packet from %s\n", tag, len(digest), srcIP)
		return
	}

	ctx.ntpPkts++
	num := ctx.ntpPkts

	// ── Display ───────────────────────────────────────────────────────────────
	fmt.Printf("\n=== NTP Packet #%d ===\n", num)
	fmt.Printf("%s\n", tag)
	fmt.Printf("- Source address: %s\n", srcIP)
	fmt.Printf("- Destination address: %s\n", dstIP)
	fmt.Printf("- Source MAC address: %s\n", srcMAC)
	fmt.Printf("- Destination MAC address: %s\n", dstMAC)
	fmt.Printf("- NTP version: %d\n", version)
	fmt.Printf("- Mode: %s (%d)\n", modeStr, mode)
	fmt.Printf("- Stratum: %d\n", stratum)
	fmt.Printf("- Poll interval: %d\n", poll)
	fmt.Printf("- Leap indicator: %d\n", li)
	fmt.Printf("- Authentication key ID: %d\n", keyID)
	fmt.Printf("- Hash algorithm: %s\n", algoName)
	fmt.Printf("- Hash: %x\n", digest)

	// ── Hash line ─────────────────────────────────────────────────────────────
	// Format: "<index>:$<fmt>$<hash_hex>$HEX$<salt_hex>"
	hashStr := fmt.Sprintf("%d:$%s$%x$HEX$%x", num, dynamicFmt, digest, salt)
	fmt.Printf("%s\n", hashStr)

	saltCopy := make([]byte, len(salt))
	copy(saltCopy, salt)
	digCopy := make([]byte, len(digest))
	copy(digCopy, digest)

	ctx.hashes = append(ctx.hashes, ntpHash{
		raw:    hashStr,
		algo:   algoName,
		salt:   saltCopy,
		dig:    digCopy,
		pktNum: num,
	})
	fmt.Fprintln(ctx.hf, hashStr)
	ctx.hashesWritten++

	fmt.Println()
}

// ─── Dictionary cracker ───────────────────────────────────────────────────────
//
// All NTP hash algorithms follow the same pattern: hash(password || salt)
// where salt = ntp_payload[0:48].
func crackHashes(hashes []ntpHash, wordlistPath string) error {
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
			if computeNTPHash(h.algo, password, h.salt, h.dig) {
				fmt.Printf("\n%s [+] CRACKED (%s): \"%s\"\n", tag, h.algo, string(password))
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

// computeNTPHash computes hash(password || salt) and compares to digest.
//
//	dynamic_2001 = md5($p.$s)    — MD5(password || salt)
//	dynamic_24   = sha1($p.$s)   — SHA1(password || salt)
//	dynamic_52   = sha224($p.$s) — SHA224(password || salt)
//	dynamic_62   = sha256($p.$s) — SHA256(password || salt)
//	dynamic_72   = sha384($p.$s) — SHA384(password || salt)
//	dynamic_82   = sha512($p.$s) — SHA512(password || salt)
func computeNTPHash(algo string, password, salt, digest []byte) bool {
	switch algo {
	case "MD5":
		h := md5.New()
		h.Write(password)
		h.Write(salt)
		return string(h.Sum(nil)) == string(digest)

	case "SHA1":
		h := sha1.New()
		h.Write(password)
		h.Write(salt)
		return string(h.Sum(nil)) == string(digest)

	case "SHA224":
		h := sha256.New224()
		h.Write(password)
		h.Write(salt)
		return string(h.Sum(nil)) == string(digest)

	case "SHA256":
		h := sha256.New()
		h.Write(password)
		h.Write(salt)
		return string(h.Sum(nil)) == string(digest)

	case "SHA384":
		h := sha512.New384()
		h.Write(password)
		h.Write(salt)
		return string(h.Sum(nil)) == string(digest)

	case "SHA512":
		h := sha512.New()
		h.Write(password)
		h.Write(salt)
		return string(h.Sum(nil)) == string(digest)
	}
	return false
}
