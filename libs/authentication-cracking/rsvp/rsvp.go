// Package rsvp extracts RSVP INTEGRITY-object authentication hashes from
// pcap/pcapng captures and optionally cracks them.
//
// RSVP uses HMAC-MD5 or HMAC-SHA1 for message authentication (RFC 2747).
// The INTEGRITY object (class=4) appears at offset 8 in the RSVP payload
// (immediately after the 8-byte RSVP common header), and contains:
//
//	Bytes 0-1:  Object length (including this 4-byte header) — big-endian uint16
//	Byte  2:    Class-Num = 4 (INTEGRITY)
//	Byte  3:    C-Type    = 1
//	Byte  4:    Flags
//	Byte  5:    Reserved
//	Bytes 6-11: Key Identifier (6 bytes)
//	Bytes 12-19: Sequence Number (64-bit big-endian)
//	Bytes 20+:  Keyed Message Digest (16 bytes MD5, 20 bytes SHA1)
//
// Salt for HMAC = full RSVP payload with the digest bytes replaced by zeros.
//
// Hash format:
//
//	<pkt_idx>:$rsvp$<algo>$<salt_hex>$<hash_hex>
//
// where algo 1 = HMAC-MD5, 2 = HMAC-SHA1.
// algo values 3-6 (SHA224/256/384/512) can appear in hand-crafted hash files
// (e.g. from BIND RNDC/TSIG) and are also supported by the cracker.
//
// Cracking algorithm:
//
//	Standard RFC 2104 HMAC with the chosen hash function:
//	  HMAC(key, salt) where key is the RSVP shared secret.
package rsvp

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
)

const (
	tag         = "\x1b[93m[RSVP]\x1b[0m"
	ipProtoRSVP = 46 // 0x2E — IP protocol number for RSVP
)

var msgTypeNames = map[byte]string{
	1: "Path",
	2: "Resv",
	3: "PathErr",
	4: "ResvErr",
	5: "PathTear",
	6: "ResvTear",
	7: "ResvConf",
}

// Cracker analyses a RSVP pcap/pcapng capture and optionally cracks hashes.
type Cracker struct {
	PcapFile string
	Wordlist string
	Crack    bool
}

type rsvpHash struct {
	raw      string
	algoType int
	salt     []byte
	dig      []byte
}

type captureCtx struct {
	hashes    []rsvpHash
	totalPkts int
	hf        *os.File
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
		fmt.Printf("\n%s No crackable RSVP hashes found in capture.\n", tag)
		return nil
	}
	if c.Wordlist == "" {
		fmt.Printf("\n%s --crack requires --wordlist <file>\n", tag)
		return nil
	}
	return crackHashes(hashes, c.Wordlist)
}

// ─── Format detection ─────────────────────────────────────────────────────────

func parsePcap(path string) ([]rsvpHash, error) {
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

	hf, err := os.Create("rsvp-hashes.txt")
	if err != nil {
		return nil, fmt.Errorf("create rsvp-hashes.txt: %w", err)
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
	fmt.Printf("RSVP INTEGRITY hashes found: %d\n", len(ctx.hashes))
	fmt.Printf("Hashes written to rsvp-hashes.txt: %d\n", len(ctx.hashes))

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
			return fmt.Errorf("invalid block length %d for block type 0x%08x", blockLen, blockType)
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
	case 1: // Ethernet
		dispatchEth(data, ctx)
	case 113: // Linux SLL cooked capture — re-frame as Ethernet-like
		if len(data) < 16 {
			return
		}
		fake := make([]byte, 14+len(data[16:]))
		fake[12] = data[14]
		fake[13] = data[15]
		copy(fake[14:], data[16:])
		dispatchEth(fake, ctx)
	}
}

// dispatchEth decodes an Ethernet frame (optionally 802.1Q-tagged) and
// routes IPv4 and IPv6 packets to the appropriate IP handler.
func dispatchEth(frame []byte, ctx *captureCtx) {
	if len(frame) < 14 {
		return
	}
	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	offset := 14
	if etherType == 0x8100 { // 802.1Q VLAN tag
		if len(frame) < 18 {
			return
		}
		etherType = uint16(frame[16])<<8 | uint16(frame[17])
		offset = 18
	}

	ip := frame[offset:]
	switch etherType {
	case 0x0800: // IPv4
		handleIPv4(ip, ctx)
	case 0x86DD: // IPv6
		handleIPv6(ip, ctx)
	}
}

// handleIPv4 extracts the RSVP payload from an IPv4 datagram.
func handleIPv4(data []byte, ctx *captureCtx) {
	if len(data) < 20 {
		return
	}
	if data[9] != ipProtoRSVP {
		return
	}
	ihl := int(data[0]&0xF) * 4
	if ihl < 20 || len(data) < ihl {
		return
	}
	srcIP := net.IP(data[12:16]).String()
	dstIP := net.IP(data[16:20]).String()
	handleRSVP(data[ihl:], srcIP, dstIP, ctx)
}

// handleIPv6 extracts the RSVP payload from an IPv6 datagram.
// Extension headers are not followed — assumes RSVP is the first next-header.
func handleIPv6(data []byte, ctx *captureCtx) {
	if len(data) < 40 {
		return
	}
	if data[6] != ipProtoRSVP {
		return
	}
	srcIP := net.IP(data[8:24]).String()
	dstIP := net.IP(data[24:40]).String()
	handleRSVP(data[40:], srcIP, dstIP, ctx)
}

// ─── RSVP INTEGRITY object parser ────────────────────────────────────────────
//
// logic:
//
//  offset = 8                            // skip 8-byte RSVP common header
//  length = data[offset:offset+2]        // INTEGRITY object length
//  object_class = data[offset+2]         // must be 4
//  hash_length = length - 20
//  h = data[offset+20 : offset+20+hash_length]
//  algo_type = 1 if hash_length == 16 else 2
//  salt = data.replace(h, '\x00' * len(h))   // replaces ALL occurrences
//
// Output: "<pkt_idx>:$rsvp$<algo>$<salt_hex>$<hash_hex>"
func handleRSVP(data []byte, srcIP, dstIP string, ctx *captureCtx) {
	const objOffset = 8 // INTEGRITY object starts after 8-byte RSVP common header

	if len(data) < objOffset+20 {
		return
	}

	objLen := int(binary.BigEndian.Uint16(data[objOffset : objOffset+2]))
	if data[objOffset+2] != 4 { // class must be INTEGRITY
		return
	}

	hashLen := objLen - 20 // 20 = 4-byte obj header + 16-byte fixed INTEGRITY fields
	if hashLen < 16 || hashLen > 64 {
		return
	}
	if len(data) < objOffset+20+hashLen {
		return
	}

	h := make([]byte, hashLen)
	copy(h, data[objOffset+20:objOffset+20+hashLen])

	var algoType int
	if hashLen == 16 {
		algoType = 1 // HMAC-MD5
	} else {
		algoType = 2 // HMAC-SHA1 (hashLen == 20)
	}

	// Salt = RSVP payload with ALL occurrences of h replaced by zeros.
	// This matches Python's bytes.replace(h, b"\x00" * len(h)) exactly.
	salt := bytes.ReplaceAll(data, h, make([]byte, hashLen))

	// Extract display fields from the RSVP common header.
	rsvpVersion := int((data[0] >> 4) & 0xF)
	msgTypeByte := data[1]
	rsvpTotalLen := binary.BigEndian.Uint16(data[6:8])

	// Extract INTEGRITY object fields (relative to object start at objOffset).
	keyID := data[objOffset+6 : objOffset+12]
	seqNum := binary.BigEndian.Uint64(data[objOffset+12 : objOffset+20])

	msgName, ok := msgTypeNames[msgTypeByte]
	if !ok {
		msgName = fmt.Sprintf("Unknown (%d)", msgTypeByte)
	} else {
		msgName = fmt.Sprintf("%s (%d)", msgName, msgTypeByte)
	}

	var algoName string
	if algoType == 1 {
		algoName = "HMAC-MD5 (type 1)"
	} else {
		algoName = "HMAC-SHA1 (type 2)"
	}

	pktIdx := ctx.totalPkts
	hashStr := fmt.Sprintf("%d:$rsvp$%d$%x$%x", pktIdx, algoType, salt, h)

	fmt.Printf("\n=== RSVP Packet #%d ===\n", len(ctx.hashes)+1)
	fmt.Printf("%s\n", tag)
	fmt.Printf("- Source IP: %s\n", srcIP)
	fmt.Printf("- Destination IP: %s\n", dstIP)
	fmt.Printf("- RSVP version: %d\n", rsvpVersion)
	fmt.Printf("- Message type: %s\n", msgName)
	fmt.Printf("- RSVP total length: %d bytes\n", rsvpTotalLen)
	fmt.Printf("- Algorithm: %s\n", algoName)
	fmt.Printf("- Key ID: %x\n", keyID)
	fmt.Printf("- Sequence number: %d (0x%016x)\n", seqNum, seqNum)
	fmt.Printf("- Hash: %x\n", h)
	fmt.Printf("%s\n\n", hashStr)

	ctx.hashes = append(ctx.hashes, rsvpHash{
		raw:      hashStr,
		algoType: algoType,
		salt:     bytes.Clone(salt),
		dig:      h,
	})
	fmt.Fprintln(ctx.hf, hashStr)
}

// ─── Dictionary cracker ───────────────────────────────────────────────────────

func crackHashes(hashes []rsvpHash, wordlistPath string) error {
	wl, err := os.Open(wordlistPath)
	if err != nil {
		return fmt.Errorf("open wordlist %s: %w", wordlistPath, err)
	}
	defer wl.Close()

	fmt.Printf("\n%s Starting dictionary attack on %d hash(es) using %s...\n",
		tag, len(hashes), wordlistPath)

	cracked := 0
	tested := 0
	sc := bufio.NewScanner(wl)
	sc.Buffer(make([]byte, 0, 65536), 1024*1024)

	for sc.Scan() {
		password := []byte(sc.Text())
		tested++
		for i, h := range hashes {
			result := computeHMAC(h.algoType, password, h.salt)
			if bytes.Equal(result, h.dig) {
				fmt.Printf("\n%s [+] CRACKED: \"%s\"\n", tag, string(password))
				fmt.Printf("    Hash #%d: %s\n", i+1, h.raw)
				cracked++
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read wordlist: %w", err)
	}

	fmt.Printf("\n%s Tested %d passwords. Cracked %d / %d hashes.\n",
		tag, tested, cracked, len(hashes))
	return nil
}

// ─── HMAC computation ─────────────────────────────────────────────────────────
//
// All six types from rsvp_fmt_plug.c are supported.  Types 1 and 2 are the
// only ones pcap_parser_rsvp produces from network traffic; types 3-6 appear
// in hand-crafted hash files (BIND RNDC, TSIG, OMAPI, etc.) and are supported
// for completeness so this cracker can handle any $rsvp$ file.
//
// The algorithm is standard RFC 2104 HMAC, which Go's crypto/hmac implements
// exactly.  The key handling (hash-the-key if len > block_size, zero-pad ipad
// and opad to the full block) is done transparently by hmac.New.
func computeHMAC(algoType int, key, data []byte) []byte {
	var newHash func() hash.Hash
	switch algoType {
	case 1:
		newHash = md5.New
	case 2:
		newHash = sha1.New
	case 3:
		newHash = sha256.New224
	case 4:
		newHash = sha256.New
	case 5:
		newHash = sha512.New384
	case 6:
		newHash = sha512.New
	default:
		return nil
	}
	mac := hmac.New(newHash, key)
	mac.Write(data)
	return mac.Sum(nil)
}
