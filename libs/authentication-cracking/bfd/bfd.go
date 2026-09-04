// Package bfd extracts BFD Keyed-MD5 and Keyed-SHA1 authentication hashes from
// pcap/pcapng captures and optionally cracks them.
//
// Supported authentication types (RFC 5880):
//
//	Type 2 – Keyed MD5              → $netmd5$<salt_hex>$<digest_hex>
//	Type 3 – Meticulous Keyed MD5   → $netmd5$<salt_hex>$<digest_hex>
//	Type 4 – Keyed SHA1             → $netsha1$<salt_hex>$<digest_hex>
//	Type 5 – Meticulous Keyed SHA1  → $netsha1$<salt_hex>$<digest_hex>
//
// Salt construction:
//
//	salt   = bfd_payload[0:32]   (24-byte mandatory header + 8-byte auth prefix)
//	digest = bfd_payload[-16:]   (MD5, types 2/3)
//	digest = bfd_payload[-20:]   (SHA1, types 4/5)
//
// Cracking:
//
//	MD5  – MD5(salt  || password_null_padded_to_16_bytes)   PLAINTEXT_LENGTH=16
//	SHA1 – SHA1(salt || password_null_padded_to_20_bytes)   PLAINTEXT_LENGTH=20
package bfd

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

const tag = "\x1b[92m[BFD]\x1b[0m"

// Cracker analyses a BFD pcap/pcapng capture and optionally cracks hashes.
type Cracker struct {
	PcapFile string
	Wordlist string
	Crack    bool
}

type bfdHash struct {
	raw  string
	algo string // "MD5" or "SHA1"
	salt []byte // bfd_payload[0:32]
	dig  []byte // bfd_payload[-16:] or [-20:]
}

type captureCtx struct {
	hf            *os.File
	hashes        []bfdHash
	totalPkts     int
	bfdPkts       int
	hashesWritten int
}

var bfdStates = map[uint8]string{
	0: "AdminDown",
	1: "Down",
	2: "Init",
	3: "Up",
}

var bfdDiags = map[uint8]string{
	0: "No Diagnostic",
	1: "Control Detection Time Expired",
	2: "Echo Function Failed",
	3: "Neighbor Signaled Session Down",
	4: "Forwarding Plane Reset",
	5: "Path Down",
	6: "Concatenated Path Down",
	7: "Administratively Down",
	8: "Reverse Concatenated Path Down",
}

var bfdAuthTypes = map[uint8]string{
	0: "Reserved",
	1: "Simple Password",
	2: "Keyed MD5",
	3: "Meticulous Keyed MD5",
	4: "Keyed SHA1",
	5: "Meticulous Keyed SHA1",
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
		fmt.Printf("\n%s No crackable BFD hashes found in capture.\n", tag)
		return nil
	}
	if c.Wordlist == "" {
		fmt.Printf("\n%s --crack requires --wordlist <file>\n", tag)
		return nil
	}
	return crackHashes(hashes, c.Wordlist)
}

// ─── Format detection ─────────────────────────────────────────────────────────

func parsePcap(path string) ([]bfdHash, error) {
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

	hf, err := os.Create("bfd-hashes.txt")
	if err != nil {
		return nil, fmt.Errorf("create bfd-hashes.txt: %w", err)
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
	fmt.Printf("BFD authenticated packets found: %d\n", ctx.bfdPkts)
	fmt.Printf("Hashes written to bfd-hashes.txt: %d\n", ctx.hashesWritten)

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

// dispatchEth handles Ethernet frames — IPv4 only.
func dispatchEth(frame []byte, ctx *captureCtx) {
	if len(frame) < 14 {
		return
	}
	srcMAC := frame[6:12]
	dstMAC := frame[0:6]
	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	rest := frame[14:]

	// eth.type == ETH_TYPE_IP && ip.v == 4 only
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
	if (rest[0]>>4)&0x0f != 4 { // ip.v != 4
		return
	}
	if rest[9] != 17 { // not UDP
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
	udp := rest[ihl:]

	extractBFD(udp, srcIP, dstIP, fmtMAC(srcMAC), fmtMAC(dstMAC), ctx)
}

func extractBFD(udp []byte, srcIP, dstIP, srcMAC, dstMAC string, ctx *captureCtx) {
	if len(udp) < 8 {
		return
	}
	dstPort := uint16(udp[2])<<8 | uint16(udp[3])
	if dstPort != 3784 { // bfd-control
		return
	}

	udpLen := int(uint16(udp[4])<<8 | uint16(udp[5]))
	payloadLen := udpLen - 8
	if payloadLen < 25 || len(udp) < 8+payloadLen {
		return
	}
	data := udp[8 : 8+payloadLen]

	handleBFD(data, srcIP, dstIP, srcMAC, dstMAC, ctx)
}

func fmtMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// ─── BFD payload handler ──────────────────────────────────────────────────────
//
// BFD mandatory header (24 bytes, RFC 5880 Section 4.1):
//
//	[0]     Vers(7-5) | Diag(4-0)
//	[1]     Sta(7-6) | P(5) | F(4) | C(3) | A(2) | D(1) | M(0)
//	[2]     Detect Multiplier
//	[3]     Length
//	[4-7]   My Discriminator
//	[8-11]  Your Discriminator
//	[12-15] Desired Min TX Interval (µs)
//	[16-19] Required Min RX Interval (µs)
//	[20-23] Required Min Echo TX Interval (µs)
//
// Auth section layouts (offset 24):
//
//	Type 1 – Simple Password (RFC 5880 §4.3):
//	  [24]         Auth Type (1)
//	  [25]         Auth Len  (3 + password_len, password = 1–16 bytes)
//	  [26]         Auth Key ID
//	  [27:24+len]  Password (plaintext, no padding)
//
//	Types 2/3 – Keyed/Meticulous Keyed MD5 (RFC 5880 §4.4):
//	  [24]    Auth Type
//	  [25]    Auth Len (28 total = 3 hdr + 1 rsv + 4 seq + 16 digest + 4 key_id field)
//	  [26]    Auth Key ID
//	  [27]    Reserved
//	  [28-31] Sequence Number
//	  [32-47] Auth Key/Digest (16 bytes)
//
//	Types 4/5 – Keyed/Meticulous Keyed SHA1 (RFC 5880 §4.5):
//	  [28-31] Sequence Number
//	  [32-51] Auth Key/Digest (20 bytes)
//
//	salt = data[0:32];  h = data[-16:] (MD5) or data[-20:] (SHA1)
func handleBFD(data []byte, srcIP, dstIP, srcMAC, dstMAC string, ctx *captureCtx) {
	// Auth-present check:
	// Bit 2 (0x04) = A (Authentication Present), bit 0 (0x01) = M (Multipoint).
	if data[1]&0x05 == 0 {
		return
	}

	// Need at least 27 bytes to read auth_type + auth_len + auth_key_id.
	if len(data) < 27 {
		return
	}

	authType := data[24]
	authLen := data[25]
	authKeyID := data[26]

	// Decode common mandatory-header fields for display.
	vers := (data[0] >> 5) & 0x07
	diag := data[0] & 0x1f
	state := (data[1] >> 6) & 0x03
	detectMult := data[2]
	myDisc := binary.BigEndian.Uint32(data[4:8])
	yourDisc := binary.BigEndian.Uint32(data[8:12])
	desiredMinTX := binary.BigEndian.Uint32(data[12:16])
	reqMinRX := binary.BigEndian.Uint32(data[16:20])
	reqMinEchoTX := binary.BigEndian.Uint32(data[20:24])

	stateStr := bfdStates[state]
	if stateStr == "" {
		stateStr = fmt.Sprintf("Unknown (%d)", state)
	}
	diagStr := bfdDiags[diag]
	if diagStr == "" {
		diagStr = fmt.Sprintf("Unknown (%d)", diag)
	}
	authTypeStr := bfdAuthTypes[authType]
	if authTypeStr == "" {
		authTypeStr = fmt.Sprintf("Unknown (%d)", authType)
	}

	// ── Type 1: Simple Password ───────────────────────────────────────────────
	// Auth section: Type(1) + Len(1) + KeyID(1) + Password(1–16).
	// Auth Len covers all four fields, so password = data[27 : 24+authLen].
	if authType == 1 {
		pwLen := int(authLen) - 3 // subtract type+len+key_id overhead
		if pwLen < 1 || pwLen > 16 || len(data) < 24+int(authLen) {
			return
		}
		password := data[27 : 24+int(authLen)]

		ctx.bfdPkts++
		num := ctx.bfdPkts

		fmt.Printf("\n=== BFD Packet #%d ===\n", num)
		fmt.Printf("%s\n", tag)
		fmt.Printf("- Source address: %s\n", srcIP)
		fmt.Printf("- Destination address: %s\n", dstIP)
		fmt.Printf("- Source MAC address: %s\n", srcMAC)
		fmt.Printf("- Destination MAC address: %s\n", dstMAC)
		fmt.Printf("- BFD version: %d\n", vers)
		fmt.Printf("- State: %s (%d)\n", stateStr, state)
		fmt.Printf("- Diagnostic: %s (%d)\n", diagStr, diag)
		fmt.Printf("- Detect multiplier: %d\n", detectMult)
		fmt.Printf("- My discriminator: %d\n", myDisc)
		fmt.Printf("- Your discriminator: %d\n", yourDisc)
		fmt.Printf("- Desired min TX interval: %d us\n", desiredMinTX)
		fmt.Printf("- Required min RX interval: %d us\n", reqMinRX)
		fmt.Printf("- Required min echo TX interval: %d us\n", reqMinEchoTX)
		fmt.Printf("- Authentication type: %s (%d)\n", authTypeStr, authType)
		fmt.Printf("- Auth length: %d\n", authLen)
		fmt.Printf("- Auth key ID: %d\n", authKeyID)
		fmt.Printf("- Password: %s\n", string(password))
		fmt.Println()
		return
	}

	// ── Types 2/3/4/5: keyed hash — need 32 bytes for salt at data[0:32] ─────
	if len(data) < 32 {
		return
	}

	salt := data[0:32]
	seqNum := binary.BigEndian.Uint32(data[28:32])

	var algo string
	var digest []byte

	switch authType {
	case 2, 3: // Keyed MD5, Meticulous Keyed MD5
		if len(data) < 48 {
			return
		}
		algo = "MD5"
		digest = data[len(data)-16:]
	case 4, 5: // Keyed SHA1, Meticulous Keyed SHA1
		if len(data) < 52 {
			return
		}
		algo = "SHA1"
		digest = data[len(data)-20:]
	default:
		return
	}

	ctx.bfdPkts++
	num := ctx.bfdPkts

	// ── Display ───────────────────────────────────────────────────────────────
	fmt.Printf("\n=== BFD Packet #%d ===\n", num)
	fmt.Printf("%s\n", tag)
	fmt.Printf("- Source address: %s\n", srcIP)
	fmt.Printf("- Destination address: %s\n", dstIP)
	fmt.Printf("- Source MAC address: %s\n", srcMAC)
	fmt.Printf("- Destination MAC address: %s\n", dstMAC)
	fmt.Printf("- BFD version: %d\n", vers)
	fmt.Printf("- State: %s (%d)\n", stateStr, state)
	fmt.Printf("- Diagnostic: %s (%d)\n", diagStr, diag)
	fmt.Printf("- Detect multiplier: %d\n", detectMult)
	fmt.Printf("- My discriminator: %d\n", myDisc)
	fmt.Printf("- Your discriminator: %d\n", yourDisc)
	fmt.Printf("- Desired min TX interval: %d us\n", desiredMinTX)
	fmt.Printf("- Required min RX interval: %d us\n", reqMinRX)
	fmt.Printf("- Required min echo TX interval: %d us\n", reqMinEchoTX)
	fmt.Printf("- Authentication type: %s (%d)\n", authTypeStr, authType)
	fmt.Printf("- Auth length: %d\n", authLen)
	fmt.Printf("- Auth key ID: %d\n", authKeyID)
	fmt.Printf("- Sequence number: %d\n", seqNum)
	fmt.Printf("- Hash: %x\n", digest)

	// ── Hash line ───────────────────────────────────────────────────────────────
	// No packet index prefix.
	var hashStr string
	switch algo {
	case "MD5":
		hashStr = fmt.Sprintf("$netmd5$%x$%x", salt, digest)
	case "SHA1":
		hashStr = fmt.Sprintf("$netsha1$%x$%x", salt, digest)
	}
	fmt.Printf("%s\n", hashStr)

	saltCopy := bytes.Clone(salt)
	digCopy := bytes.Clone(digest)

	ctx.hashes = append(ctx.hashes, bfdHash{
		raw:  hashStr,
		algo: algo,
		salt: saltCopy,
		dig:  digCopy,
	})
	fmt.Fprintln(ctx.hf, hashStr)
	ctx.hashesWritten++

	fmt.Println()
}

// ─── Dictionary cracker ───────────────────────────────────────────────────────
//
// BFD cracking algorithms:
//
//	MD5  — MD5(salt  || password_null_padded_to_16)  PLAINTEXT_LENGTH=16
//	SHA1 — SHA1(salt || password_null_padded_to_20)  PLAINTEXT_LENGTH=20
//
// passwords shorter than PLAINTEXT_LENGTH are zero-padded,
// and passwords longer than PLAINTEXT_LENGTH are truncated to PLAINTEXT_LENGTH.
func crackHashes(hashes []bfdHash, wordlistPath string) error {
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
			if computeBFDHash(h.algo, password, h.salt, h.dig) {
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

// computeBFDHash computes the BFD keyed hash and compares it to the packet digest.
//
// MD5:  MD5(salt  || pw_null_padded_16)  — net-md5 format, PLAINTEXT_LENGTH=16
// SHA1: SHA1(salt || pw_null_padded_20)  — net-sha1 format, PLAINTEXT_LENGTH=20
func computeBFDHash(algo string, password, salt, digest []byte) bool {
	switch algo {
	case "MD5":
		var pw [16]byte // zero-initialised → null padding
		n := len(password)
		if n > 16 {
			n = 16
		}
		copy(pw[:], password[:n])

		h := md5.New()
		h.Write(salt)
		h.Write(pw[:])
		return string(h.Sum(nil)) == string(digest)

	case "SHA1":
		var pw [20]byte
		n := len(password)
		if n > 20 {
			n = 20
		}
		copy(pw[:], password[:n])

		h := sha1.New()
		h.Write(salt)
		h.Write(pw[:])
		return string(h.Sum(nil)) == string(digest)
	}
	return false
}
