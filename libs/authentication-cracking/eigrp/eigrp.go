// Package eigrp extracts EIGRP MD5 / HMAC-SHA-256 authentication hashes from
// pcap/pcapng files and optionally cracks them.
//
// Hash format:
//
//	<N>:$eigrp$<algo>$<salt_hex>$<have_extra>$<extra_or_x>$1$<src_ip>$<digest_hex>
//
// Cracking:
//
//	MD5:      MD5(salt || password_padded_to_16 || extra_salt) == digest
//	SHA-256:  HMAC-SHA256(key='\n'+password+ip, data=salt)[:16] == digest
package eigrp

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

const tag = "\x1b[96m[EIGRP]\x1b[0m"

// Cracker analyses an EIGRP pcap/pcapng capture and optionally cracks hashes.
type Cracker struct {
	PcapFile string
	Wordlist string
	Crack    bool
}

type eigrpHash struct {
	raw       string
	algoType  int
	salt      []byte
	haveExtra bool
	extraSalt []byte
	srcIP     string
	dig       [16]byte
}

type captureCtx struct {
	hf            *os.File
	hashes        []eigrpHash
	totalPkts     int
	eigrpPkts     int
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
		fmt.Printf("\n%s No crackable hashes found in capture.\n", tag)
		return nil
	}
	if c.Wordlist == "" {
		fmt.Printf("\n%s --crack requires --wordlist <file>\n", tag)
		return nil
	}
	return crackHashes(hashes, c.Wordlist)
}

// ─── Format detection and top-level reader ────────────────────────────────────

func parsePcap(path string) ([]eigrpHash, error) {
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

	hf, err := os.Create("eigrp-hashes.txt")
	if err != nil {
		return nil, fmt.Errorf("create eigrp-hashes.txt: %w", err)
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
		return nil, fmt.Errorf("unrecognised file format (magic=0x%08x)", magic)
	}
	if err != nil {
		return nil, err
	}

	fmt.Printf("\n=== SUMMARY ===\n")
	fmt.Printf("Total packets processed: %d\n", ctx.totalPkts)
	fmt.Printf("EIGRP packets found: %d\n", ctx.eigrpPkts)
	fmt.Printf("MD5/SHA-256 hashes written to eigrp-hashes.txt: %d\n", ctx.hashesWritten)

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
			return fmt.Errorf("invalid block length %d", blockLen)
		}

		rem := make([]byte, blockLen-8)
		if _, err := io.ReadFull(f, rem); err != nil {
			return fmt.Errorf("read block body: %w", err)
		}
		body := rem[:blockLen-12]

		switch blockType {
		case 0x00000001: // IDB
			if len(body) >= 4 {
				lt := uint32(order.Uint16(body[0:2]))
				ifaces = append(ifaces, lt)
			}
		case 0x00000006: // EPB
			if len(body) >= 20 {
				ifaceID := order.Uint32(body[0:4])
				capturedLen := order.Uint32(body[12:16])
				if uint32(len(body)) >= 20+capturedLen {
					pkt := body[20 : 20+capturedLen]
					lt := ifaceLinkType(ifaces, ifaceID)
					ctx.totalPkts++
					if ctx.totalPkts%100 == 0 {
						fmt.Printf("Processed %d packets...\n", ctx.totalPkts)
					}
					dispatchFrame(pkt, lt, ctx)
				}
			}
		case 0x00000003: // SPB
			if len(body) >= 4 {
				capturedLen := uint32(len(body) - 4)
				pkt := body[4 : 4+capturedLen]
				lt := ifaceLinkType(ifaces, 0)
				ctx.totalPkts++
				dispatchFrame(pkt, lt, ctx)
			}
		case 0x00000002: // OPB
			if len(body) >= 20 {
				ifaceID := uint32(order.Uint16(body[0:2]))
				capturedLen := order.Uint32(body[12:16])
				if uint32(len(body)) >= 20+capturedLen {
					pkt := body[20 : 20+capturedLen]
					lt := ifaceLinkType(ifaces, ifaceID)
					ctx.totalPkts++
					dispatchFrame(pkt, lt, ctx)
				}
			}
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
			return nil, fmt.Errorf("seek past SHB: %w", err)
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

	switch etherType {
	case 0x0800: // IPv4
		if len(ip) < 20 {
			return
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl {
			return
		}
		if ip[9] != 88 { // EIGRP
			return
		}
		ipTotal := int(binary.BigEndian.Uint16(ip[2:4]))
		if ipTotal > len(ip) {
			ipTotal = len(ip)
		}
		srcIP := net.IP(ip[12:16]).String()
		dstIP := net.IP(ip[16:20]).String()
		payload := ip[ihl:ipTotal]
		handleEIGRP(payload, srcIP, dstIP, fmtMAC(srcMAC), fmtMAC(dstMAC), false, ctx)

	case 0x86DD: // IPv6
		if len(ip) < 40 {
			return
		}
		if ip[6] != 88 { // EIGRP next-header (no extension-header support)
			return
		}
		payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
		if 40+payloadLen > len(ip) {
			payloadLen = len(ip) - 40
		}
		srcIP := net.IP(ip[8:24]).String()
		dstIP := net.IP(ip[24:40]).String()
		payload := ip[40 : 40+payloadLen]
		handleEIGRP(payload, srcIP, dstIP, fmtMAC(srcMAC), fmtMAC(dstMAC), true, ctx)
	}
}

func fmtMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// ─── EIGRP packet handler ──────────────────────────────────────────────────────

// handleEIGRP parses an EIGRP payload, prints details, and
// writes a hash line to eigrp-hashes.txt.
//
// EIGRP header layout (20 bytes):
//
//	[0]    version
//	[1]    opcode (1=Update, 5=Hello, …)
//	[2-3]  checksum  ← zeroed in salt
//	[4-7]  flags     ← bytes 4-5 zeroed in salt
//	[8-11] sequence
//	[12-15] ack
//	[16-17] virtual router ID
//	[18-19] autonomous system
//	[20+]  TLVs
//
// Authentication TLV (type 0x0002) value layout (after 4-byte TLV header):
//
//	[0-1]  auth type   (2=MD5, 3=HMAC-SHA-256)
//	[2-3]  hash length (16 for MD5, 32 for SHA-256)
//	[4-7]  key ID      (4 bytes)
//	[8-11] key sequence (4 bytes)
//	[12-19] null pad   (8 bytes)
//	[20+]  digest      (hash_length bytes)
//
// Digest offset in packet = authTLVOffset + 4 (TLV header) + 20 (auth fields) = authTLVOffset + 24.
func handleEIGRP(payload []byte, srcIP, dstIP, srcMAC, dstMAC string, isIPv6 bool, ctx *captureCtx) {
	if len(payload) < 40 {
		return
	}
	version := payload[0]
	if version != 2 {
		return
	}
	opcode := payload[1]
	flags := binary.BigEndian.Uint32(payload[4:8])

	// Update+Init packets don't include the password in the hash.
	if opcode == 1 && flags == 1 {
		return
	}

	vrID := binary.BigEndian.Uint16(payload[16:18])
	as := binary.BigEndian.Uint16(payload[18:20])

	// ── Scan TLVs ────────────────────────────────────────────────────────────
	var kValues [6]uint8
	hasKValues := false
	authOffset := -1
	algoType := 0
	hashLen := 0

	// Keep track of TLV data for extra-salt computation.
	// These are only populated if the relevant TLVs appear after the auth TLV.
	var paramsTLV []byte // full Parameters TLV bytes (type 1)
	var paramsTLVData []byte // Parameters TLV minus last 2 bytes
	var versionTLV []byte // full Software Version TLV bytes (type 4)
	var peerTLV []byte // 7-byte Peer Topology snippet (type 0x00f5)
	var internalRoutes []byte // concatenated Internal Route TLVs (type 0x0602)
	haveExtra := false
	var extraSaltBytes []byte
	pastAuth := false

	offset := 20
	for offset+4 <= len(payload) {
		tlvType := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
		tlvLength := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		if tlvLength < 4 || offset+tlvLength > len(payload) {
			break
		}
		tlvData := payload[offset+4 : offset+tlvLength]

		if !pastAuth {
			// Before (or at) the auth TLV
			switch tlvType {
			case 0x0001: // Parameters TLV — extract K values
				if len(tlvData) >= 6 {
					copy(kValues[:], tlvData[:6])
					hasKValues = true
				}
			case 0x0002: // Authentication TLV
				if len(tlvData) >= 4 {
					at := int(binary.BigEndian.Uint16(tlvData[0:2]))
					hl := int(binary.BigEndian.Uint16(tlvData[2:4]))
					if (at == 2 || at == 3) && hl >= 16 {
						algoType = at
						hashLen = hl
						authOffset = offset
						pastAuth = true
					}
				}
			}
		} else {
			// TLVs appearing AFTER the auth TLV — used for extra salt.
			switch tlvType {
			case 0x0001: // Parameters TLV
				if len(tlvData) >= 6 {
					copy(kValues[:], tlvData[:6])
					hasKValues = true
				}
				paramsTLV = payload[offset : offset+tlvLength]
				if tlvLength >= 6 {
					paramsTLVData = payload[offset : offset+tlvLength-2]
				}

			case 0x0004: // Software Version TLV
				versionTLV = payload[offset : offset+tlvLength]

			case 0x00f5: // Peer Topology ID List
				if offset+6 <= len(payload) {
					peerTLV = append(payload[offset:offset+6], 0x00)
				}
				haveExtra = true
				extraSaltBytes = paramsTLVData

			case 0x0003: // Sequence TLV — includes params + version + peer in extra salt
				haveExtra = true
				extraSaltBytes = append(paramsTLV, versionTLV...)
				extraSaltBytes = append(extraSaltBytes, peerTLV...)

			case 0x00f2: // Internal Route (MTR)
				end := offset + 22
				if end > len(payload) {
					end = len(payload)
				}
				extraSaltBytes = append(payload[offset:end], 0x00)
				haveExtra = true

			case 0x0602: // Internal Route (Update Flags==0) — possibly multiple
				internalRoutes = append(internalRoutes, payload[offset:offset+tlvLength]...)
				haveExtra = true
			}
		}
		offset += tlvLength
	}

	if authOffset == -1 {
		return // No auth TLV found
	}

	// Append internal routes (minus last 20 bytes) to extra salt
	if len(internalRoutes) > 20 {
		extraSaltBytes = append(extraSaltBytes, internalRoutes[:len(internalRoutes)-20]...)
	}

	// ── Digest extraction ─────────────────────────────────────────────────────
	// digestOffset = authTLVOffset + TLV_header(4) + auth_type(2) + hash_len(2)
	//              + key_id(4) + key_seq(4) + null_pad(8)
	//            = authTLVOffset + 24
	const authFieldsBeforeDigest = 24 // 4 (TLV hdr) + 20 (auth fields)
	digestOffset := authOffset + authFieldsBeforeDigest
	if digestOffset+hashLen > len(payload) {
		return // Malformed
	}
	digest := payload[digestOffset : digestOffset+hashLen]
	var dig16 [16]byte
	copy(dig16[:], digest[:16])

	// ── Salt construction ─────────────────────────────────────────────────────
	// bytes 2-5 are zeroed (checksum 2-3 + first two flag bytes 4-5).
	var salt []byte
	if algoType == 2 { // MD5: salt = everything before the digest
		salt = make([]byte, digestOffset)
		copy(salt, payload[:digestOffset])
		salt[2] = 0; salt[3] = 0; salt[4] = 0; salt[5] = 0
	} else { // SHA-256: salt = full packet with bytes 2-5 zeroed + digest zeroed
		salt = make([]byte, len(payload))
		copy(salt, payload)
		salt[2] = 0; salt[3] = 0; salt[4] = 0; salt[5] = 0
		for i := digestOffset; i < digestOffset+hashLen && i < len(salt); i++ {
			salt[i] = 0
		}
	}

	// ── Display ───────────────────────────────────────────────────────────────
	ctx.eigrpPkts++
	num := ctx.eigrpPkts

	fmt.Printf("\n=== EIGRP Packet #%d ===\n", num)
	fmt.Printf("%s\n", tag)
	if isIPv6 {
		fmt.Printf("EIGRP (IPv6):\n")
	} else {
		fmt.Printf("EIGRP (IPv4):\n")
	}
	dstHint := dstIP
	if dstIP == "ff02::a" {
		dstHint = "ff02::a (multicast)"
	}
	fmt.Printf("- Source address: %s\n", srcIP)
	fmt.Printf("- Destination address: %s\n", dstHint)
	fmt.Printf("- Source MAC address: %s\n", srcMAC)
	fmt.Printf("- Destination MAC address: %s\n", dstMAC)
	fmt.Printf("- Protocol version: %d\n", version)
	fmt.Printf("- Virtual router ID: %d\n", vrID)
	fmt.Printf("- Autonomous system: %d\n", as)

	authName := "Unknown"
	switch algoType {
	case 2:
		authName = "MD5"
	case 3:
		authName = "SHA256"
	}
	fmt.Printf("- Authentication type: %s\n", authName)
	fmt.Printf("- Authentication length: %d\n", hashLen)
	fmt.Printf("- Digest: %x\n", digest[:16])

	if hasKValues {
		fmt.Printf("- K values: K1=%d, K2=%d, K3=%d, K4=%d, K5=%d, K6=%d\n",
			kValues[0], kValues[1], kValues[2], kValues[3], kValues[4], kValues[5])
	}
	fmt.Println()

	// ── Hash line ─────────────────────────────────────────────────────────────
	extraFlagStr := "0"
	extraFieldStr := "x"
	if haveExtra && len(extraSaltBytes) > 0 {
		extraFlagStr = "1"
		extraFieldStr = fmt.Sprintf("%x", extraSaltBytes)
	}
	hashStr := fmt.Sprintf("%d:$eigrp$%d$%x$%s$%s$1$%s$%x",
		num, algoType, salt, extraFlagStr, extraFieldStr, srcIP, digest[:16])
	fmt.Printf("%s\n\n", hashStr)

	h := eigrpHash{
		raw:       hashStr,
		algoType:  algoType,
		salt:      salt,
		haveExtra: haveExtra && len(extraSaltBytes) > 0,
		extraSalt: extraSaltBytes,
		srcIP:     srcIP,
		dig:       dig16,
	}
	ctx.hashes = append(ctx.hashes, h)
	ctx.hf.WriteString(hashStr + "\n")
	ctx.hashesWritten++
}

// ─── Dictionary cracker ───────────────────────────────────────────────────────

func crackHashes(hashes []eigrpHash, wordlistPath string) error {
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
		password := sc.Text()
		tested++

		for i, h := range hashes {
			ok := false
			switch h.algoType {
			case 2: // MD5
				got := eigrpMD5(h.salt, password, h.extraSalt)
				ok = got == h.dig
				if !ok && h.haveExtra {
					// Some Hello packets export trailing TLV data as extra salt
					// even though the router didn't include it in the MAC.
					got = eigrpMD5(h.salt, password, nil)
					ok = got == h.dig
				}
			case 3: // HMAC-SHA-256
				got := eigrpHMACSHA256(h.salt, password, h.srcIP)
				ok = got == h.dig
			}
			if ok {
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

// eigrpMD5 implements MD5 computation:
//
//	MD5( salt || password || zero_pad_to_16 || extra_salt )
func eigrpMD5(salt []byte, password string, extraSalt []byte) [16]byte {
	pw := []byte(password)
	h := md5.New()
	h.Write(salt)
	h.Write(pw)
	if len(pw) < 16 {
		h.Write(make([]byte, 16-len(pw)))
	}
	if len(extraSalt) > 0 {
		h.Write(extraSalt)
	}
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// eigrpHMACSHA256 implements EIGRP HMAC-SHA-256 algorithm:
//
//	HMAC-SHA256( key='\n'+password+ip, data=salt )[:16]
func eigrpHMACSHA256(salt []byte, password, ip string) [16]byte {
	key := append([]byte{'\n'}, []byte(password)...)
	key = append(key, []byte(ip)...)
	mac := hmac.New(sha256.New, key)
	mac.Write(salt)
	var out [16]byte
	copy(out[:], mac.Sum(nil)[:16])
	return out
}
