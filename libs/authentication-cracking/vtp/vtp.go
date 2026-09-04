// Package vtp extracts VTP MD5 authentication hashes from pcap/pcapng captures
// and optionally cracks them.
//
// VTP authentication requires cross-packet matching: the MD5 hash lives in a
// Summary Advertisement, while the VLAN data needed for verification comes from
// a matching Subset Advertisement (same 4-byte revision number).  Both must be
// present in the capture for a crackable hash to be produced.
//
// Hash format:
//
//	<summary_pkt_idx>:$vtp$<version>$<vlans_len>$<vlans_hex>$<salt_len>$<salt_hex>$<hash_hex>
//
// where:
//
//	summary_pkt_idx = 1-based index of the Summary Advertisement in the capture
//	salt            = full raw bytes of the Summary Advertisement packet
//	vlans_hex       = Subset Advertisement payload starting at byte 40
//	hash_hex        = salt[56:72] (MD5 stored in the Summary Advertisement)
//
// Cracking algorithm:
//
//  1. Derive 16-byte "secret" from the password (PLAINTEXT_LENGTH = 55):
//       secret = MD5( cyclic_repeat(password, 1563 × 64 bytes) )
//       The password cycles to fill each 64-byte block; 1563 blocks ≈ 100 KB.
//
//  2. Normalise the 72-byte VTP Summary Advertisement packet (vtp_summary_packet):
//       zero out: followers (byte 2), update_timestamp (bytes 44-55),
//                 md5_checksum (bytes 56-71).
//
//  3. Compute the authentication hash:
//       MD5(secret ‖ normalised_vsp(72B) ‖ [trailer if version≠1] ‖ vlans_data ‖ secret)
package vtp

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
)

const tag = "\x1b[35m[VTP]\x1b[0m"

// Cracker analyses a VTP pcap/pcapng capture and optionally cracks hashes.
type Cracker struct {
	PcapFile string
	Wordlist string
	Crack    bool
}

type vtpHash struct {
	raw       string
	salt      []byte // full Summary Advertisement bytes
	vlansData []byte // Subset Advertisement data[40:]
	dig       []byte // expected MD5 digest = salt[56:72]
}

type summaryEntry struct {
	pktIdx int
	data   []byte
	srcMAC string
	dstMAC string
}

type vtpPair struct {
	entry     summaryEntry
	vlansData []byte
}

type captureCtx struct {
	subsets   map[string][]byte       // revision_key → vlans_data
	summaries map[string]summaryEntry // revision_key → summary entry
	totalPkts int
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
		fmt.Printf("\n%s No crackable VTP hashes found in capture.\n", tag)
		return nil
	}
	if c.Wordlist == "" {
		fmt.Printf("\n%s --crack requires --wordlist <file>\n", tag)
		return nil
	}
	return crackHashes(hashes, c.Wordlist)
}

// ─── Format detection ─────────────────────────────────────────────────────────

func parsePcap(path string) ([]vtpHash, error) {
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

	ctx := &captureCtx{
		subsets:   make(map[string][]byte),
		summaries: make(map[string]summaryEntry),
	}

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

	return matchAndDisplay(ctx)
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
	}
}

// dispatchEth extracts VTP data from Ethernet (with optional 802.1Q tag)
// and Cisco LLC/SNAP framing:
//
//	offset = 14 normally, 18 if EtherType==0x8100 (802.1Q)
//	VTP payload = frame[offset+8:] if frame[offset:offset+2] == \xaa\xaa
func dispatchEth(frame []byte, ctx *captureCtx) {
	if len(frame) < 14 {
		return
	}
	srcMAC := fmtMAC(frame[6:12])
	dstMAC := fmtMAC(frame[0:6])

	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	offset := 14
	if etherType == 0x8100 { // 802.1Q VLAN tag
		if len(frame) < 18 {
			return
		}
		offset = 18
	}

	payload := frame[offset:]
	if len(payload) <= 8 {
		return
	}

	// Cisco SNAP: \xaa\xaa\x03\x00\x00\x0c or any \xaa\xaa prefix
	if payload[0] != 0xaa || payload[1] != 0xaa {
		return
	}
	vtpData := payload[8:]
	if len(vtpData) < 40 {
		return
	}

	handleVTP(vtpData, srcMAC, dstMAC, ctx)
}

func fmtMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// ─── VTP packet handler ───────────────────────────────────────────────────────
//
// VTP Summary Advertisement (salt) layout (72+ bytes):
//
//	[0]     VTP version (1 or 2)
//	[1]     Code (1 = Summary, 2 = Subset)
//	[2]     Followers
//	[3]     Domain name length
//	[4:36]  Domain name (32 bytes, zero-padded)
//	[36:40] Configuration revision (BE uint32)
//	[40:44] Updater identity IP (BE uint32)
//	[44:56] Update timestamp (12 ASCII bytes: YYMMDDHHMMSS)
//	[56:72] MD5 checksum (the hash)
//	[72:]   Trailer bytes (VTP version 2 only)
//
// Subset Advertisement:
//
//	[0:36]  Same header fields
//	[36:40] Configuration revision (must match Summary)
//	[40:]   VLAN information data
//
// This tool uses revision bytes data[36:40] as the correlation key.
func handleVTP(vtpData []byte, srcMAC, dstMAC string, ctx *captureCtx) {
	version := vtpData[0]
	code := vtpData[1]

	// Only process VTPv1 and VTPv2
	if version != 1 && version != 2 {
		return
	}

	revKey := string(vtpData[36:40]) // 4 raw bytes used as map key

	switch code {
	case 2: // Subset Advertisement — store vlans_data (data[40:])
		vlans := make([]byte, len(vtpData[40:]))
		copy(vlans, vtpData[40:])
		ctx.subsets[revKey] = vlans

	case 1: // Summary Advertisement — must have at least 72 bytes for hash
		if len(vtpData) < 72 {
			return
		}
		salt := make([]byte, len(vtpData))
		copy(salt, vtpData)
		ctx.summaries[revKey] = summaryEntry{
			pktIdx: ctx.totalPkts,
			data:   salt,
			srcMAC: srcMAC,
			dstMAC: dstMAC,
		}
	}
}

// ─── Cross-packet matching and display ───────────────────────────────────────
//
// After reading the entire capture, pair each Subset with its matching Summary
// (same revision), display the result, and write the hash line to vtp-hashes.txt.
// Output ordering is by the Summary's global packet index.
func matchAndDisplay(ctx *captureCtx) ([]vtpHash, error) {
	// Collect matched pairs, sorted by summary packet index for determinism.
	var pairs []vtpPair
	for rev, vlans := range ctx.subsets {
		summ, ok := ctx.summaries[rev]
		if !ok {
			continue
		}
		pairs = append(pairs, vtpPair{entry: summ, vlansData: vlans})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].entry.pktIdx < pairs[j].entry.pktIdx
	})

	hf, err := os.Create("vtp-hashes.txt")
	if err != nil {
		return nil, fmt.Errorf("create vtp-hashes.txt: %w", err)
	}
	defer hf.Close()

	var hashes []vtpHash
	for n, p := range pairs {
		salt := p.entry.data
		vlans := p.vlansData
		digest := salt[56:72]

		version := int(salt[0])
		dnLen := int(salt[3])
		if dnLen > 32 {
			dnLen = 32
		}
		domainName := string(salt[4 : 4+dnLen])
		revision := binary.BigEndian.Uint32(salt[36:40])
		updaterIP := fmt.Sprintf("%d.%d.%d.%d", salt[40], salt[41], salt[42], salt[43])
		timestamp := string(salt[44:56])

		// ── Display ───────────────────────────────────────────────────────────
		fmt.Printf("\n=== VTP Packet #%d ===\n", n+1)
		fmt.Printf("%s\n", tag)
		fmt.Printf("- Source MAC address: %s\n", p.entry.srcMAC)
		fmt.Printf("- Destination MAC address: %s\n", p.entry.dstMAC)
		fmt.Printf("- VTP version: %d\n", version)
		fmt.Printf("- Message type: Summary Advertisement\n")
		fmt.Printf("- Domain name: %s\n", domainName)
		fmt.Printf("- Domain name length: %d\n", dnLen)
		fmt.Printf("- Configuration revision: %d\n", revision)
		fmt.Printf("- Updater identity: %s\n", updaterIP)
		fmt.Printf("- Update timestamp: %s\n", timestamp)
		fmt.Printf("- VLAN data length: %d bytes\n", len(vlans))
		fmt.Printf("- Hash: %x\n", digest)

		// ── Hash line ─────────────────────────────────────────────────────────
		// Format: summary_pkt_idx:$vtp$version$vlans_len$vlans_hex$salt_len$salt_hex$hash_hex
		hashStr := fmt.Sprintf("%d:$vtp$%d$%d$%x$%d$%x$%x",
			p.entry.pktIdx, version, len(vlans), vlans, len(salt), salt, digest)
		fmt.Printf("%s\n", hashStr)

		saltCopy := bytes.Clone(salt)
		vlansCopy := bytes.Clone(vlans)
		digCopy := bytes.Clone(digest)
		hashes = append(hashes, vtpHash{raw: hashStr, salt: saltCopy, vlansData: vlansCopy, dig: digCopy})
		fmt.Fprintln(hf, hashStr)
		fmt.Println()
	}

	fmt.Printf("\n=== SUMMARY ===\n")
	fmt.Printf("Total packets processed: %d\n", ctx.totalPkts)
	fmt.Printf("VTP pairs found: %d\n", len(pairs))
	fmt.Printf("Hashes written to vtp-hashes.txt: %d\n", len(pairs))

	return hashes, nil
}

// ─── Dictionary cracker ───────────────────────────────────────────────────────

func crackHashes(hashes []vtpHash, wordlistPath string) error {
	wl, err := os.Open(wordlistPath)
	if err != nil {
		return fmt.Errorf("open wordlist %s: %w", wordlistPath, err)
	}
	defer wl.Close()

	fmt.Printf("\n%s Starting dictionary attack on %d hash(es) using %s...\n", tag, len(hashes), wordlistPath)

	// Track which hashes have already been cracked so that only the first
	// matching password is reported per hash.  
	// VTP's cyclic secret derivation means passwords that produce
	// the same repeating byte sequence (e.g. "123", "123123", "123123123")
	// all compute to the same secret; without this guard every one of them
	// would be printed as a "cracked" result.
	done := make([]bool, len(hashes))
	numDone := 0
	tested := 0

	sc := bufio.NewScanner(wl)
	sc.Buffer(make([]byte, 0, 65536), 1024*1024)

	for sc.Scan() {
		if numDone == len(hashes) {
			break // all hashes cracked — stop early
		}

		password := []byte(sc.Text())
		tested++

		// Truncate to PLAINTEXT_LENGTH = 55 before secret derivation.
		pw := password
		if len(pw) > 55 {
			pw = pw[:55]
		}

		// Derive the VTP secret once per password candidate — this is the
		// expensive step (1563 × 64-byte MD5 blocks ≈ 100 KB per candidate).
		secret := deriveVTPSecret(pw)

		for i, h := range hashes {
			if done[i] {
				continue // already have a result for this hash
			}
			result := computeVTPMD5WithSecret(secret, h.salt, h.vlansData)
			if bytes.Equal(result[:], h.dig) {
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

	fmt.Printf("\n%s Tested %d passwords. Cracked %d / %d hashes.\n", tag, tested, numDone, len(hashes))
	return nil
}

// ─── VTP cracking algorithm ───────────────────────────────────────────────────
//
//	PLAINTEXT_LENGTH = 55  (passwords longer than 55 bytes are truncated)
//
// Step 1 — derive secret once per password candidate (deriveVTPSecret):
//   fill 1563 × 64-byte blocks by cycling the password, then MD5 the whole.
//
// Step 2 — build normalised vtp_summary_packet (72 bytes) from the salt:
//   version=salt[0], code=salt[1], followers=0, domain_name_length=salt[3],
//   domain_name=salt[4:4+dnLen], revision=salt[36:40], updater=salt[40:44],
//   update_timestamp=zeros(12), md5_checksum=zeros(16).
//
// Step 3 — final hash (computeVTPMD5WithSecret):
//   MD5(secret ‖ vsp(72) ‖ [trailer=salt[72:] if version≠1] ‖ vlansData ‖ secret)
//
// The cracker derives the secret once and calls computeVTPMD5WithSecret for
// each hash, avoiding redundant work when cracking multiple hashes at once.

// computeVTPMD5WithSecret computes the VTP authentication hash given a
// pre-derived 16-byte secret, the full Summary Advertisement salt, and the
// Subset Advertisement VLAN data.
func computeVTPMD5WithSecret(secret [16]byte, salt, vlansData []byte) [16]byte {
	vsp := buildNormalisedVSP(salt)

	h := md5.New()
	h.Write(secret[:])
	h.Write(vsp)
	if salt[0] != 1 && len(salt) > 72 { // trailer only for version ≠ 1
		h.Write(salt[72:])
	}
	h.Write(vlansData)
	h.Write(secret[:])

	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// deriveVTPSecret implements vtp_secret_derive from vtp_fmt_plug.c.
// The password is cycled to fill 1563 consecutive 64-byte blocks (≈100 KB),
// which are fed to a single MD5 context, producing the 16-byte "secret".
func deriveVTPSecret(password []byte) [16]byte {
	var out [16]byte
	if len(password) == 0 {
		return out
	}
	h := md5.New()
	var buf [64]byte
	pwLen := len(password)
	pos := 0
	for i := 0; i < 1563; i++ {
		for j := 0; j < 64; j++ {
			buf[j] = password[pos]
			pos++
			if pos == pwLen {
				pos = 0
			}
		}
		h.Write(buf[:])
	}
	copy(out[:], h.Sum(nil))
	return out
}

// buildNormalisedVSP constructs the 72-byte vtp_summary_packet used for MAC
// calculation, zeroing out followers, update_timestamp, and md5_checksum fields.
func buildNormalisedVSP(salt []byte) []byte {
	vsp := make([]byte, 72) // zero-initialised
	vsp[0] = salt[0]        // version
	vsp[1] = salt[1]        // code
	// vsp[2] = 0            followers — stays zero
	dnLen := int(salt[3])
	if dnLen > 32 {
		dnLen = 32
	}
	vsp[3] = byte(dnLen)
	copy(vsp[4:4+dnLen], salt[4:4+dnLen])  // domain_name (dnLen bytes only)
	copy(vsp[36:40], salt[36:40])           // revision
	copy(vsp[40:44], salt[40:44])           // updater IP
	// vsp[44:56] = zeros  (update_timestamp — stays zero)
	// vsp[56:72] = zeros  (md5_checksum — stays zero)
	return vsp
}
