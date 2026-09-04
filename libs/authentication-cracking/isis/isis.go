// Package isis extracts IS-IS authentication hashes from pcap/pcapng captures
// and optionally cracks them.
//
// IS-IS (Intermediate System to Intermediate System) is a Layer 2 routing
// protocol carried directly in 802.3 Ethernet frames using an LLC header:
//
//	Ethernet dst/src (12 bytes) | 802.3 length (<0x0600) (2 bytes)
//	LLC: DSAP=0xFE, SSAP=0xFE, Control=0x03 (3 bytes)
//	IS-IS PDU starting with discriminator byte 0x83
//
// 802.1Q-tagged frames are also supported (4-byte VLAN tag inserted between
// the MAC addresses and the 802.3 length field).
//
// Supported Authentication TLV (type 0x0A) variants:
//
//	HMAC-MD5  (RFC 5304): length=17, auth_type=0x36, hash=16 bytes
//	  TLV value: [auth_type][hash(16)]
//	  Salt: IS-IS PDU with hash bytes replaced by 16 zero bytes
//	  Format: <idx>:$rsvp$1$<salt_hex>$<hash_hex>
//
//	HMAC-SHA1   (RFC 5310): length=23, auth_type=0x03, hash=20 bytes
//	  TLV value: [auth_type][key_id(2)][hash(20)]
//	  Salt: IS-IS PDU with hash bytes removed (not zeroed)
//	  Format: <idx>:$ospf$1$<salt_hex>$<hash_hex>
//
//	HMAC-SHA256 (RFC 5310): length=35, auth_type=0x03, hash=32 bytes
//	  TLV value: [auth_type][key_id(2)][hash(32)]
//	  Salt: IS-IS PDU with hash bytes removed (not zeroed)
//	  Format: <idx>:$ospf$2$<salt_hex>$<hash_hex>
//
// The TLV start offset within the IS-IS PDU is read from the
// header_length_indicator field (data[1]), making this robust across all PDU
// types (P2P Hello, LAN Hello, LSP, CSNP, PSNP).
//
// For LSP PDUs (types 0x12 / 0x14), the Remaining Lifetime (data[10:12]) and
// Checksum (data[24:26]) fields are zeroed before salt computation per RFC 5304.
package isis

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const tag = "\x1b[90m[IS-IS]\x1b[0m"

// algoType constants
const (
	algoHMACMD5    = 1
	algoHMACSHA1   = 2
	algoHMACSHA256 = 3
)

var pduTypeNames = map[byte]string{
	0x0F: "L1 LAN Hello",
	0x10: "L2 LAN Hello",
	0x11: "P2P Hello",
	0x12: "L1 LSP",
	0x14: "L2 LSP",
	0x18: "L1 CSNP",
	0x19: "L2 CSNP",
	0x1A: "L1 PSNP",
	0x1B: "L2 PSNP",
}

var algoNames = map[int]string{
	algoHMACMD5:    "HMAC-MD5",
	algoHMACSHA1:   "HMAC-SHA1",
	algoHMACSHA256: "HMAC-SHA256",
}

// Cracker analyses an IS-IS pcap/pcapng capture and optionally cracks hashes.
type Cracker struct {
	PcapFile string
	Wordlist string
	Crack    bool
}

type isisHash struct {
	raw      string
	algoType int
	salt     []byte
	dig      []byte
}

type captureCtx struct {
	hashes    []isisHash
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
		fmt.Printf("\n%s No crackable IS-IS hashes found in capture.\n", tag)
		return nil
	}
	if c.Wordlist == "" {
		fmt.Printf("\n%s --crack requires --wordlist <file>\n", tag)
		return nil
	}
	return crackHashes(hashes, c.Wordlist)
}

// ─── Format detection ─────────────────────────────────────────────────────────

func parsePcap(path string) ([]isisHash, error) {
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

	hf, err := os.Create("isis-hashes.txt")
	if err != nil {
		return nil, fmt.Errorf("create isis-hashes.txt: %w", err)
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
	fmt.Printf("IS-IS auth hashes found: %d\n", len(ctx.hashes))
	fmt.Printf("Hashes written to isis-hashes.txt: %d\n", len(ctx.hashes))

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
	case 113: // Linux SLL — re-frame as Ethernet-like
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

// dispatchEth handles standard 802.3 and 802.1Q-tagged 802.3 frames.
// IS-IS is carried in 802.3 frames (EtherType/Length field < 0x0600) with
// an LLC header DSAP=0xFE, SSAP=0xFE, Control=0x03.
func dispatchEth(frame []byte, ctx *captureCtx) {
	if len(frame) < 14 {
		return
	}
	dstMAC := fmtMAC(frame[0:6])
	srcMAC := fmtMAC(frame[6:12])

	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	llcOffset := 14

	if etherType == 0x8100 { // 802.1Q VLAN tag
		if len(frame) < 18 {
			return
		}
		etherType = uint16(frame[16])<<8 | uint16(frame[17])
		llcOffset = 18
	}

	// IS-IS uses 802.3 frames (length < 1500), not Ethernet II (EtherType >= 0x0600)
	if etherType >= 0x0600 {
		return
	}

	if len(frame) < llcOffset+4 {
		return
	}
	if frame[llcOffset] != 0xFE || frame[llcOffset+1] != 0xFE || frame[llcOffset+2] != 0x03 {
		return
	}

	isisPDU := frame[llcOffset+3:]
	if len(isisPDU) < 9 || isisPDU[0] != 0x83 {
		return
	}

	handleISIS(isisPDU, srcMAC, dstMAC, ctx)
}

// ─── IS-IS PDU parser ─────────────────────────────────────────────────────────
//
// IS-IS common header (8 bytes, same for all PDU types):
//
//	Byte 0: Intradomain Routing Protocol Discriminator = 0x83
//	Byte 1: Length Indicator (header length in bytes)
//	Byte 2: Version/Protocol ID Extension = 1
//	Byte 3: ID Length (0 = default 6-byte system ID)
//	Byte 4: R/R/R/PDU-Type (bits 4-0)
//	Byte 5: Version = 1
//	Byte 6: Reserved
//	Byte 7: Maximum Area Addresses
//
// TLVs begin at byte data[header_length_indicator].
//
// For LSP PDUs (type 0x12 / 0x14), Remaining Lifetime (data[10:12]) and
// Checksum (data[24:26]) are zeroed before salt computation per RFC 5304.
//
// Auth TLV variants:
//
//	HMAC-MD5  (RFC 5304): tlvLen=17, auth_type=0x36, hash 16B at tlv+3
//	HMAC-SHA1 (RFC 5310): tlvLen=23, auth_type=0x03, key_id(2B), hash 20B at tlv+5
//	HMAC-SHA256 (RFC 5310): tlvLen=35, auth_type=0x03, key_id(2B), hash 32B at tlv+5
func handleISIS(data []byte, srcMAC, dstMAC string, ctx *captureCtx) {
	hdrLen := int(data[1])
	if hdrLen < 8 || len(data) < hdrLen {
		return
	}

	pduTypeByte := data[4] & 0x1F

	// For LSP PDUs, zero Remaining Lifetime and Checksum before computing salt.
	// Remaining Lifetime = data[10:12], Checksum = data[24:26] (per RFC 5304 §3.1)
	pduData := data
	if (pduTypeByte == 0x12 || pduTypeByte == 0x14) && len(data) >= 26 {
		d := make([]byte, len(data))
		copy(d, data)
		d[10], d[11] = 0, 0
		d[24], d[25] = 0, 0
		pduData = d
	}

	// Walk TLVs to find the Authentication TLV (type 0x0A)
	for offset := hdrLen; offset+2 <= len(pduData); {
		tlvType := pduData[offset]
		tlvLen := int(pduData[offset+1])
		if tlvLen == 0 || offset+2+tlvLen > len(pduData) {
			break
		}

		var algoType int
		var hashLen int
		var hashOff int // offset of hash within pduData
		var zeroSalt bool // true=replace hash with zeros, false=remove hash bytes

		switch {
		case tlvType == 0x0A && tlvLen == 17 && pduData[offset+2] == 0x36:
			// HMAC-MD5: [auth_type(1)][hash(16)]
			algoType = algoHMACMD5
			hashLen = 16
			hashOff = offset + 3
			zeroSalt = true

		case tlvType == 0x0A && tlvLen == 23 && pduData[offset+2] == 0x03:
			// HMAC-SHA1: [auth_type(1)][key_id(2)][hash(20)]
			algoType = algoHMACSHA1
			hashLen = 20
			hashOff = offset + 5
			zeroSalt = false

		case tlvType == 0x0A && tlvLen == 35 && pduData[offset+2] == 0x03:
			// HMAC-SHA256: [auth_type(1)][key_id(2)][hash(32)]
			algoType = algoHMACSHA256
			hashLen = 32
			hashOff = offset + 5
			zeroSalt = false
		}

		if algoType != 0 && hashOff+hashLen <= len(pduData) {
			h := make([]byte, hashLen)
			copy(h, pduData[hashOff:hashOff+hashLen])

			var salt []byte
			if zeroSalt {
				// MD5: replace hash bytes with zeros
				salt = bytes.ReplaceAll(pduData, h, make([]byte, hashLen))
			} else {
				// SHA: remove hash bytes entirely
				salt = bytes.ReplaceAll(pduData, h, []byte{})
			}

			var hashStr string
			switch algoType {
			case algoHMACMD5:
				hashStr = fmt.Sprintf("%d:$rsvp$1$%x$%x", ctx.totalPkts, salt, h)
			case algoHMACSHA1:
				hashStr = fmt.Sprintf("%d:$ospf$1$%x$%x", ctx.totalPkts, salt, h)
			case algoHMACSHA256:
				hashStr = fmt.Sprintf("%d:$ospf$2$%x$%x", ctx.totalPkts, salt, h)
			}

			pduName, ok := pduTypeNames[pduTypeByte]
			if !ok {
				pduName = fmt.Sprintf("Unknown (0x%02x)", pduTypeByte)
			}

			var sysIDStr string
			if (pduTypeByte == 0x0F || pduTypeByte == 0x10 || pduTypeByte == 0x11) && len(pduData) >= 15 {
				sysIDStr = fmtSysID(pduData[9:15])
			}

			fmt.Printf("\n=== IS-IS Packet #%d ===\n", len(ctx.hashes)+1)
			fmt.Printf("%s\n", tag)
			fmt.Printf("- Destination MAC: %s\n", dstMAC)
			fmt.Printf("- Source MAC: %s\n", srcMAC)
			fmt.Printf("- PDU type: %s\n", pduName)
			fmt.Printf("- Header length: %d bytes\n", hdrLen)
			if sysIDStr != "" {
				fmt.Printf("- System ID: %s\n", sysIDStr)
			}
			fmt.Printf("- Authentication: %s\n", algoNames[algoType])
			fmt.Printf("- Hash: %x\n", h)
			fmt.Printf("%s\n\n", hashStr)

			ctx.hashes = append(ctx.hashes, isisHash{
				raw:      hashStr,
				algoType: algoType,
				salt:     bytes.Clone(salt),
				dig:      h,
			})
			fmt.Fprintln(ctx.hf, hashStr)
			return
		}

		offset += 2 + tlvLen
	}
}

// ─── Dictionary cracker ───────────────────────────────────────────────────────

func crackHashes(hashes []isisHash, wordlistPath string) error {
	wl, err := os.Open(wordlistPath)
	if err != nil {
		return fmt.Errorf("open wordlist %s: %w", wordlistPath, err)
	}
	defer wl.Close()

	fmt.Printf("\n%s Starting dictionary attack on %d hash(es) using %s...\n",
		tag, len(hashes), wordlistPath)

	done := make([]bool, len(hashes))
	numDone := 0
	tested := 0

	sc := bufio.NewScanner(wl)
	sc.Buffer(make([]byte, 0, 65536), 1024*1024)

	for sc.Scan() {
		if numDone == len(hashes) {
			break
		}
		password := []byte(sc.Text())
		tested++
		for i, h := range hashes {
			if done[i] {
				continue
			}
			// computeHMAC always returns 16 bytes; compare against first 16
			// bytes of dig (BINARY_SIZE=16 for all ospf$ variants)
			result := computeHMAC(h.algoType, password, h.salt)
			if bytes.Equal(result, h.dig[:16]) {
				fmt.Printf("\n%s [+] CRACKED: \"%s\"\n", tag, string(password))
				fmt.Printf("    Hash #%d: %s\n", i+1, h.raw)
				done[i] = true
				numDone++
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read wordlist: %w", err)
	}

	fmt.Printf("\n%s Tested %d passwords. Cracked %d / %d hashes.\n",
		tag, tested, numDone, len(hashes))
	return nil
}

// ─── HMAC computation ─────────────────────────────────────────────────────────
//
// HMAC-MD5 (RFC 5304): standard HMAC-MD5, compare all 16 bytes.
//
// HMAC-SHA1 / SHA256 (RFC 5709):
//
//   1. Key derivation: zero-pad password to digestLen bytes; if password is
//      longer than digestLen, replace with Hash(password) instead.
//
//   2. HMAC data: salt || ospf_apad[0:digestLen]
//      where ospf_apad = {0x87,0x8F,0xE1,0xF3} × 16 (64 bytes).
//
//   3. Compute HMAC-SHAx(derived_key, extended_data).
//
//   4. Return only the first 16 bytes (BINARY_SIZE = 16); compare that
//      against the first 16 bytes of the stored digest.

var ospfApad = []byte{
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
	0x87, 0x8F, 0xE1, 0xF3, 0x87, 0x8F, 0xE1, 0xF3,
}

// computeHMAC returns the authentication check value for the given password
// and salt. The length of the returned slice is:
//   - 16 bytes for HMAC-MD5 (full digest)
//   - 16 bytes for HMAC-SHA1 / SHA256 (truncated per BINARY_SIZE=16)
func computeHMAC(algoType int, password, salt []byte) []byte {
	switch algoType {
	case algoHMACMD5:
		mac := hmac.New(md5.New, password)
		mac.Write(salt)
		return mac.Sum(nil)

	case algoHMACSHA1:
		// Key: zero-pad (or SHA1-hash) password to 20 bytes
		key := make([]byte, 20)
		if len(password) <= 20 {
			copy(key, password)
		} else {
			h := sha1.Sum(password)
			copy(key, h[:])
		}
		// Data: salt || ospf_apad[0:20]
		data := make([]byte, len(salt)+20)
		copy(data, salt)
		copy(data[len(salt):], ospfApad[:20])
		// HMAC-SHA1, truncate to 16 bytes
		mac := hmac.New(sha1.New, key)
		mac.Write(data)
		return mac.Sum(nil)[:16]

	case algoHMACSHA256:
		// Key: zero-pad (or SHA256-hash) password to 32 bytes
		key := make([]byte, 32)
		if len(password) <= 32 {
			copy(key, password)
		} else {
			h := sha256.Sum256(password)
			copy(key, h[:])
		}
		// Data: salt || ospf_apad[0:32]
		data := make([]byte, len(salt)+32)
		copy(data, salt)
		copy(data[len(salt):], ospfApad[:32])
		// HMAC-SHA256, truncate to 16 bytes
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil)[:16]
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func fmtMAC(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		b[0], b[1], b[2], b[3], b[4], b[5])
}

func fmtSysID(b []byte) string {
	return fmt.Sprintf("%04x.%04x.%04x",
		uint16(b[0])<<8|uint16(b[1]),
		uint16(b[2])<<8|uint16(b[3]),
		uint16(b[4])<<8|uint16(b[5]))
}
