// Package tacacs extracts and decrypts TACACS+ sessions from pcap captures.
//
// TACACS+ (RFC 8907) uses TCP port 49. Every packet body is encrypted with a
// pseudo-random pad derived from MD5:
//
//	Pad_1 = MD5(session_id || secret || version_byte || seq_no)
//	Pad_n = MD5(session_id || secret || version_byte || seq_no || Pad_n-1)
//	plaintext = ciphertext XOR (Pad_1 || Pad_2 || ...)
//
// Cracking works by trying candidate passwords against AUTHEN_REPLY packets
// (even seq_no, from the server). A decrypted reply is valid when:
//
//	status ∈ [0x01..0x07] ∪ {0x21}
//	no_flags ∈ {0x00, 0x01}
//	6 + server_msg_len + data_len == body_length
//
// Hash format:
//
//	$tacacs-plus$0$<session_id_hex>$<ciphertext_hex>$<version_hex><seq_no_hex>
package tacacs

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

const tag = "\x1b[90m[TACACS+]\x1b[0m"

// TACACS+ type constants
const (
	tacAuthen = 0x01
	tacAuthor = 0x02
	tacAcct   = 0x03

	flagUnencrypted = 0x04

	authenLogin    = 0x01
	authenChpass   = 0x02
	authenSendauth = 0x04

	authenTypeASCII    = 0x01
	authenTypePAP      = 0x02
	authenTypeCHAP     = 0x03
	authenTypeARAP     = 0x04
	authenTypeMSCHAP   = 0x05
	authenTypeMSCHAPv2 = 0x06

	authenSvcNone   = 0x00
	authenSvcLogin  = 0x01
	authenSvcEnable = 0x02
	authenSvcPPP    = 0x03
	authenSvcARAP   = 0x04
	authenSvcPT     = 0x05
	authenSvcRCMD   = 0x06
	authenSvcX25    = 0x07
	authenSvcNASI   = 0x08

	replyPass    = 0x01
	replyFail    = 0x02
	replyGetdata = 0x03
	replyGetuser = 0x04
	replyGetpass = 0x05
	replyRestart = 0x06
	replyError   = 0x07
	replyFollow  = 0x21

	authorPassAdd  = 0x01
	authorPassRepl = 0x02
	authorFail     = 0x10
	authorError    = 0x11
	authorFollow   = 0x21

	acctSuccess = 0x01
	acctError   = 0x02
	acctFollow  = 0x21
)

type tacacsPkt struct {
	pktIdx  int
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPort uint16
	version byte
	pktType byte
	seqNo   byte
	flags   byte
	sessID  [4]byte
	body    []byte
}

type session struct {
	id      [4]byte
	packets []*tacacsPkt
}

type captureCtx struct {
	sessions     map[[4]byte]*session
	sessionOrder [][4]byte
	pktIdx       int
	totalPkts    int
	hf           *os.File
	hashCount    int
}

// Cracker parses TACACS+ from a pcap and optionally cracks the shared secret.
type Cracker struct {
	PcapFile string
	Wordlist string
	Crack    bool
}

// ─── Entry point ─────────────────────────────────────────────────────────────

func (c *Cracker) Run() error {
	ctx, err := parsePcap(c.PcapFile)
	if err != nil {
		return err
	}
	if !c.Crack {
		return nil
	}
	if len(ctx.sessions) == 0 {
		fmt.Printf("\n%s No TACACS+ sessions found.\n", tag)
		return nil
	}
	if c.Wordlist == "" {
		fmt.Printf("\n%s --crack requires --wordlist <file>\n", tag)
		return nil
	}
	return crackSessions(ctx, c.Wordlist)
}

// ─── Pcap parsing ────────────────────────────────────────────────────────────

func parsePcap(path string) (*captureCtx, error) {
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

	hf, err := os.Create("tacacs-plus-hashes.txt")
	if err != nil {
		return nil, fmt.Errorf("create tacacs-plus-hashes.txt: %w", err)
	}
	defer hf.Close()

	ctx := &captureCtx{
		sessions: make(map[[4]byte]*session),
		hf:       hf,
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
		return nil, fmt.Errorf("unrecognised file format (magic=0x%08x)", magic)
	}
	if err != nil {
		return nil, err
	}

	fmt.Printf("\n=== SUMMARY ===\n")
	fmt.Printf("Total packets processed: %d\n", ctx.totalPkts)
	fmt.Printf("TACACS+ sessions found: %d\n", len(ctx.sessions))
	fmt.Printf("Hashes written to tacacs-plus-hashes.txt: %d\n", ctx.hashCount)

	return ctx, nil
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

// ─── Pcapng reader ───────────────────────────────────────────────────────────

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
			if len(body) >= 2 {
				ifaces = append(ifaces, uint32(order.Uint16(body[0:2])))
			}
		case 0x00000006: // EPB
			if len(body) < 20 {
				break
			}
			ifaceID := order.Uint32(body[0:4])
			capLen := order.Uint32(body[12:16])
			if uint32(len(body)) < 20+capLen {
				break
			}
			ctx.totalPkts++
			dispatchFrame(body[20:20+capLen], ifaceLinkType(ifaces, ifaceID), ctx)
		case 0x00000003: // SPB
			if len(body) >= 4 {
				ctx.totalPkts++
				dispatchFrame(body[4:], ifaceLinkType(ifaces, 0), ctx)
			}
		case 0x00000002: // OPB
			if len(body) >= 20 {
				ifaceID := uint32(order.Uint16(body[0:2]))
				capLen := order.Uint32(body[12:16])
				if uint32(len(body)) >= 20+capLen {
					ctx.totalPkts++
					dispatchFrame(body[20:20+capLen], ifaceLinkType(ifaces, ifaceID), ctx)
				}
			}
		}
	}
	return nil
}

func parseSHBHeader(f *os.File) (binary.ByteOrder, error) {
	var p [8]byte
	if _, err := io.ReadFull(f, p[:]); err != nil {
		return nil, err
	}
	bom := uint32(p[4])<<24 | uint32(p[5])<<16 | uint32(p[6])<<8 | uint32(p[7])
	var order binary.ByteOrder
	var blen uint32
	switch bom {
	case 0x1A2B3C4D:
		order = binary.BigEndian
		blen = binary.BigEndian.Uint32(p[0:4])
	case 0x4D3C2B1A:
		order = binary.LittleEndian
		blen = binary.LittleEndian.Uint32(p[0:4])
	default:
		return nil, fmt.Errorf("invalid SHB BOM 0x%08x", bom)
	}
	if rem := int64(blen) - 12; rem > 0 {
		if _, err := f.Seek(rem, io.SeekCurrent); err != nil {
			return nil, err
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
	case 1: // Ethernet II
		dispatchEth(data, ctx)
	case 113: // Linux SLL
		if len(data) >= 16 {
			fake := make([]byte, 14+len(data[16:]))
			fake[12] = data[14]
			fake[13] = data[15]
			copy(fake[14:], data[16:])
			dispatchEth(fake, ctx)
		}
	}
}

func dispatchEth(frame []byte, ctx *captureCtx) {
	if len(frame) < 14 {
		return
	}
	etype := uint16(frame[12])<<8 | uint16(frame[13])
	payload := frame[14:]

	if etype == 0x8100 { // 802.1Q
		if len(frame) < 18 {
			return
		}
		etype = uint16(frame[16])<<8 | uint16(frame[17])
		payload = frame[18:]
	}
	if etype == 0x0800 {
		dispatchIPv4(payload, ctx)
	}
}

func dispatchIPv4(data []byte, ctx *captureCtx) {
	if len(data) < 20 {
		return
	}
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || len(data) < ihl {
		return
	}
	proto := data[9]
	if proto != 0x06 { // TCP only
		return
	}
	srcIP := fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15])
	dstIP := fmt.Sprintf("%d.%d.%d.%d", data[16], data[17], data[18], data[19])
	dispatchTCP(data[ihl:], srcIP, dstIP, ctx)
}

func dispatchTCP(data []byte, srcIP, dstIP string, ctx *captureCtx) {
	if len(data) < 20 {
		return
	}
	srcPort := uint16(data[0])<<8 | uint16(data[1])
	dstPort := uint16(data[2])<<8 | uint16(data[3])
	if srcPort != 49 && dstPort != 49 {
		return
	}
	dataOff := int(data[12]>>4) * 4
	if dataOff < 20 || len(data) < dataOff {
		return
	}
	payload := data[dataOff:]
	if len(payload) < 12 {
		return
	}
	handleTACACS(payload, srcIP, dstIP, srcPort, dstPort, ctx)
}

// ─── TACACS+ packet parser ────────────────────────────────────────────────────

func handleTACACS(data []byte, srcIP, dstIP string, srcPort, dstPort uint16, ctx *captureCtx) {
	if len(data) < 12 {
		return
	}
	version := data[0]
	pktType := data[1]
	seqNo := data[2]
	flags := data[3]
	var sessID [4]byte
	copy(sessID[:], data[4:8])
	bodyLen := binary.BigEndian.Uint32(data[8:12])

	if uint32(len(data)) < 12+bodyLen {
		return
	}
	body := make([]byte, bodyLen)
	copy(body, data[12:12+bodyLen])

	ctx.pktIdx++
	pkt := &tacacsPkt{
		pktIdx:  ctx.pktIdx,
		srcIP:   srcIP,
		dstIP:   dstIP,
		srcPort: srcPort,
		dstPort: dstPort,
		version: version,
		pktType: pktType,
		seqNo:   seqNo,
		flags:   flags,
		sessID:  sessID,
		body:    body,
	}

	// Register into session map
	s, ok := ctx.sessions[sessID]
	if !ok {
		s = &session{id: sessID}
		ctx.sessions[sessID] = s
		ctx.sessionOrder = append(ctx.sessionOrder, sessID)
	}
	s.packets = append(s.packets, pkt)

	encrypted := flags&flagUnencrypted == 0
	sessHex := hex.EncodeToString(sessID[:])
	bodyHex := hex.EncodeToString(body)

	encStr := "0x00 (encrypted)"
	if !encrypted {
		encStr = fmt.Sprintf("0x%02X (unencrypted)", flags)
	}

	encLabel := "Encrypted Request"
	if srcPort == 49 {
		encLabel = "Encrypted Reply"
	}

	fmt.Printf("\n=== TACACS+ Packet #%d ===\n", pkt.pktIdx)
	fmt.Printf("- Source address: %s\n", srcIP)
	fmt.Printf("- Source port: %d\n", srcPort)
	fmt.Printf("- Destination address: %s\n", dstIP)
	fmt.Printf("- Destination port: %d\n", dstPort)
	fmt.Printf("- Session ID: %s\n", sessHex)
	fmt.Printf("- Packet type: %d (%s)\n", pktType, typeName(pktType))
	fmt.Printf("- Role: %s\n", roleName(pktType, seqNo, dstPort))
	fmt.Printf("- Sequence number: %d\n", seqNo)
	fmt.Printf("- Protocol version: 0x%02X\n", version)
	fmt.Printf("- Flags: %s\n", encStr)
	fmt.Printf("- Body length: %d bytes\n", bodyLen)
	fmt.Printf("- %s: %s\n", encLabel, bodyHex)

	// Write hash for server replies (even seq_no from port 49) — auth type only
	if pktType == tacAuthen && seqNo%2 == 0 && srcPort == 49 && encrypted && bodyLen >= 6 {
		hashLine := fmt.Sprintf("$tacacs-plus$0$%s$%s$%02x%02x\n", sessHex, bodyHex, version, seqNo)
		fmt.Printf("\n$tacacs-plus$0$%s$%s$%02x%02x\n", sessHex, bodyHex, version, seqNo)
		if _, err := ctx.hf.WriteString(hashLine); err == nil {
			ctx.hashCount++
		}
	}
}

// ─── Cracking ─────────────────────────────────────────────────────────────────

func crackSessions(ctx *captureCtx, wordlistPath string) error {
	wf, err := os.Open(wordlistPath)
	if err != nil {
		return fmt.Errorf("open wordlist: %w", err)
	}
	defer wf.Close()

	// Collect all candidate targets: AUTHEN_REPLY packets (even seq, from port 49)
	type target struct {
		s   *session
		pkt *tacacsPkt
	}
	var targets []target

	for _, id := range ctx.sessionOrder {
		s := ctx.sessions[id]
		for _, p := range s.packets {
			if p.pktType == tacAuthen && p.seqNo%2 == 0 && p.srcPort == 49 &&
				p.flags&flagUnencrypted == 0 && len(p.body) >= 6 {
				targets = append(targets, target{s, p})
				break
			}
		}
	}

	if len(targets) == 0 {
		fmt.Printf("\n%s No AUTH_REPLY packets found for cracking.\n", tag)
		return nil
	}

	fmt.Printf("\n%s Cracking %d session(s) against wordlist %s ...\n\n", tag, len(ctx.sessions), wordlistPath)

	// Track which sessions are cracked
	cracked := make(map[[4]byte]string)

	scanner := bufio.NewScanner(wf)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)

	for scanner.Scan() {
		password := scanner.Text()
		if password == "" {
			continue
		}
		key := []byte(password)

		for _, t := range targets {
			if _, done := cracked[t.s.id]; done {
				continue
			}
			if tryDecrypt(t.pkt, key) {
				cracked[t.s.id] = password
			}
		}
		if len(cracked) == len(ctx.sessions) {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read wordlist: %w", err)
	}

	// When exactly one key was found for the pcap, use it for all sessions
	// (TACACS+ devices typically share a single key across sessions).
	uniqueKeys := make(map[string]bool)
	for _, k := range cracked {
		uniqueKeys[k] = true
	}
	var fallbackKey string
	if len(uniqueKeys) == 1 {
		for k := range uniqueKeys {
			fallbackKey = k
		}
	}

	// Report results — iterate in capture order
	for _, id := range ctx.sessionOrder {
		s := ctx.sessions[id]
		sessHex := hex.EncodeToString(s.id[:])
		key, found := cracked[s.id]
		if !found {
			if fallbackKey == "" {
				fmt.Printf("\n=== TACACS+ Session %s ===\n", sessHex)
				fmt.Printf("- Result: NOT CRACKED\n")
				continue
			}
			key = fallbackKey
		}
		fmt.Printf("\n=== TACACS+ Session %s ===\n", sessHex)
		fmt.Printf("- Key found: \x1b[32m%q\x1b[0m\n", key)
		printSession(s, []byte(key))
	}
	return nil
}

// tryDecrypt checks whether the given key correctly decrypts the AUTHEN_REPLY body.
func tryDecrypt(p *tacacsPkt, key []byte) bool {
	if len(p.body) < 6 {
		return false
	}
	pad := computePad(p.sessID, key, p.version, p.seqNo)
	plain := make([]byte, 6)
	for i := 0; i < 6; i++ {
		plain[i] = p.body[i] ^ pad[i%16]
	}
	status := plain[0]
	noFlags := plain[1]
	srvMsgLen := uint16(plain[2])<<8 | uint16(plain[3])
	dataLen := uint16(plain[4])<<8 | uint16(plain[5])

	statusOK := (status >= replyPass && status <= replyError) || status == replyFollow
	flagsOK := noFlags == 0x00 || noFlags == 0x01
	lenOK := 6+uint32(srvMsgLen)+uint32(dataLen) == uint32(len(p.body))

	return statusOK && flagsOK && lenOK
}

// computePad generates the first 16-byte MD5 pad block.
// MD5(session_id || key || version_byte || seq_no_byte)
func computePad(sessID [4]byte, key []byte, version, seqNo byte) []byte {
	h := md5.New()
	h.Write(sessID[:])
	h.Write(key)
	h.Write([]byte{version, seqNo})
	return h.Sum(nil)
}

// decryptBody decrypts a full TACACS+ body using the chained MD5 pad.
func decryptBody(body []byte, sessID [4]byte, key []byte, version, seqNo byte) []byte {
	plain := make([]byte, len(body))
	var prevPad []byte
	for i := 0; i < len(body); i += 16 {
		var pad []byte
		if prevPad == nil {
			pad = computePad(sessID, key, version, seqNo)
		} else {
			h := md5.New()
			h.Write(sessID[:])
			h.Write(key)
			h.Write([]byte{version, seqNo})
			h.Write(prevPad)
			pad = h.Sum(nil)
		}
		for j := 0; j < 16 && i+j < len(body); j++ {
			plain[i+j] = body[i+j] ^ pad[j]
		}
		prevPad = pad
	}
	return plain
}

// ─── Decrypted session display ────────────────────────────────────────────────

func printSession(s *session, key []byte) {
	sessHex := hex.EncodeToString(s.id[:])
	for _, p := range s.packets {
		role := roleName(p.pktType, p.seqNo, p.dstPort)
		encStr := "0x00 (encrypted)"
		if p.flags&flagUnencrypted != 0 {
			encStr = fmt.Sprintf("0x%02X (unencrypted)", p.flags)
		}

		fmt.Printf("\n=== TACACS+ Packet #%d (%s, seq=%d) ===\n", p.pktIdx, role, p.seqNo)
		fmt.Printf("- Source address: %s\n", p.srcIP)
		fmt.Printf("- Source port: %d\n", p.srcPort)
		fmt.Printf("- Destination address: %s\n", p.dstIP)
		fmt.Printf("- Destination port: %d\n", p.dstPort)
		fmt.Printf("- Session ID: %s\n", sessHex)
		fmt.Printf("- Packet type: %d (%s)\n", p.pktType, typeName(p.pktType))
		fmt.Printf("- Sequence number: %d\n", p.seqNo)
		fmt.Printf("- Protocol version: 0x%02X\n", p.version)
		fmt.Printf("- Flags: %s\n", encStr)
		fmt.Printf("- Body length: %d bytes\n", len(p.body))
		pktEncLabel := "Encrypted Request"
		pktDecLabel := "Decrypted Request"
		if p.srcPort == 49 {
			pktEncLabel = "Encrypted Reply"
			pktDecLabel = "Decrypted Reply"
		}
		fmt.Printf("- %s: %s\n", pktEncLabel, hex.EncodeToString(p.body))
		fmt.Printf("- %s:\n", pktDecLabel)

		var plain []byte
		if p.flags&flagUnencrypted != 0 {
			plain = p.body
		} else {
			plain = decryptBody(p.body, p.sessID, key, p.version, p.seqNo)
		}
		printBodyDecoded(p.pktType, p.seqNo, p.dstPort, plain)
	}
}

func printBodyDecoded(pktType, seqNo byte, dstPort uint16, plain []byte) {
	switch pktType {
	case tacAuthen:
		if seqNo == 1 {
			printAuthenStart(plain)
		} else if seqNo%2 == 1 {
			printAuthenContinue(plain)
		} else {
			printAuthenReply(plain)
		}
	case tacAuthor:
		if dstPort == 49 {
			printAuthorRequest(plain)
		} else {
			printAuthorReply(plain)
		}
	case tacAcct:
		if dstPort == 49 {
			printAcctRequest(plain)
		} else {
			printAcctReply(plain)
		}
	default:
		fmt.Printf("    - Raw body: %s\n", hex.EncodeToString(plain))
	}
}

func printAuthenStart(b []byte) {
	if len(b) < 8 {
		fmt.Printf("    - Body: (truncated)\n")
		return
	}
	userLen := int(b[4])
	portLen := int(b[5])
	remLen := int(b[6])
	dataLen := int(b[7])
	off := 8
	user := safeSlice(b, off, userLen)
	off += userLen
	port := safeSlice(b, off, portLen)
	off += portLen
	rem := safeSlice(b, off, remLen)
	off += remLen
	data := safeSlice(b, off, dataLen)

	fmt.Printf("    - Action: %s (%d)\n", authenActionName(b[0]), b[0])
	fmt.Printf("    - Privilege Level: %d\n", b[1])
	fmt.Printf("    - Authentication type: %s (%d)\n", authenTypeName(b[2]), b[2])
	fmt.Printf("    - Service: %s (%d)\n", authenSvcName(b[3]), b[3])
	fmt.Printf("    - User len: %d\n", userLen)
	if userLen > 0 {
		fmt.Printf("    - User: %s\n", displayStr(user))
	}
	fmt.Printf("    - Port len: %d\n", portLen)
	if portLen > 0 {
		fmt.Printf("    - Port: %s\n", displayStr(port))
	}
	fmt.Printf("    - Remaddr len: %d\n", remLen)
	if remLen > 0 {
		fmt.Printf("    - Remote Address: %s\n", displayStr(rem))
	}
	fmt.Printf("    - Data length: %d\n", dataLen)
	if dataLen > 0 {
		fmt.Printf("    - Data: %s\n", displayStr(data))
	}
}

func printAuthenReply(b []byte) {
	if len(b) < 6 {
		fmt.Printf("    - Body: (truncated)\n")
		return
	}
	srvMsgLen := int(b[2])<<8 | int(b[3])
	dataLen := int(b[4])<<8 | int(b[5])
	off := 6
	srvMsg := safeSlice(b, off, srvMsgLen)
	off += srvMsgLen
	data := safeSlice(b, off, dataLen)

	flagStr := fmt.Sprintf("0x%02x", b[1])
	if b[1]&0x01 != 0 {
		flagStr = fmt.Sprintf("0x%02x(NoEcho)", b[1])
	}
	fmt.Printf("    - Status: %s (0x%02X)\n", authenReplyStatusName(b[0]), b[0])
	fmt.Printf("    - Flags: %s\n", flagStr)
	fmt.Printf("    - Server message length: %d\n", srvMsgLen)
	if srvMsgLen > 0 {
		fmt.Printf("    - Server message: %s\n", escapedStr(srvMsg))
	}
	fmt.Printf("    - Data length: %d\n", dataLen)
	if dataLen > 0 {
		fmt.Printf("    - Data: %s\n", escapedStr(data))
	}
}

func printAuthenContinue(b []byte) {
	if len(b) < 5 {
		fmt.Printf("    - Body: (truncated)\n")
		return
	}
	userMsgLen := int(b[0])<<8 | int(b[1])
	dataLen := int(b[2])<<8 | int(b[3])
	off := 5
	userMsg := safeSlice(b, off, userMsgLen)
	off += userMsgLen
	data := safeSlice(b, off, dataLen)

	flagStr := fmt.Sprintf("0x%02x", b[4])
	if b[4]&0x01 != 0 {
		flagStr = fmt.Sprintf("0x%02x(Abort)", b[4])
	}
	fmt.Printf("    - Flags: %s\n", flagStr)
	fmt.Printf("    - User length: %d\n", userMsgLen)
	if userMsgLen > 0 {
		fmt.Printf("    - User: %s\n", displayStr(userMsg))
	}
	fmt.Printf("    - Data length: %d\n", dataLen)
	if dataLen > 0 {
		fmt.Printf("    - Data: %s\n", displayStr(data))
	}
}

func printAuthorRequest(b []byte) {
	if len(b) < 8 {
		fmt.Printf("    - Body: (truncated)\n")
		return
	}
	argCnt := int(b[7])
	if len(b) < 8+argCnt {
		fmt.Printf("    - Body: (truncated)\n")
		return
	}
	userLen := int(b[4])
	portLen := int(b[5])
	remLen := int(b[6])
	argLens := b[8 : 8+argCnt]
	off := 8 + argCnt
	user := safeSlice(b, off, userLen)
	off += userLen
	port := safeSlice(b, off, portLen)
	off += portLen
	rem := safeSlice(b, off, remLen)
	off += remLen
	fmt.Printf("    - Authentication method: %s\n", authenMethodName(b[0]))
	fmt.Printf("    - Privilege level: 0x%02X\n", b[1])
	fmt.Printf("    - Authentication type: %s\n", authenTypeName(b[2]))
	fmt.Printf("    - Service: %s\n", authenSvcName(b[3]))
	fmt.Printf("    - User len: %d\n", userLen)
	if userLen > 0 {
		fmt.Printf("    - User: %s\n", displayStr(user))
	}
	fmt.Printf("    - Port len: %d\n", portLen)
	if portLen > 0 {
		fmt.Printf("    - Port: %s\n", displayStr(port))
	}
	fmt.Printf("    - Remaddr len: %d\n", remLen)
	if remLen > 0 {
		fmt.Printf("    - Remote Address: %s\n", displayStr(rem))
	}
	for i, al := range argLens {
		arg := safeSlice(b, off, int(al))
		off += int(al)
		fmt.Printf("    - Argument %d: %s\n", i, displayStr(arg))
	}
}

func printAuthorReply(b []byte) {
	if len(b) < 6 {
		fmt.Printf("    - Body: (truncated)\n")
		return
	}
	argCnt := int(b[1])
	srvMsgLen := int(b[2])<<8 | int(b[3])
	dataLen := int(b[4])<<8 | int(b[5])
	if len(b) < 6+argCnt {
		fmt.Printf("    - Body: (truncated)\n")
		return
	}
	argLens := b[6 : 6+argCnt]
	off := 6 + argCnt
	srvMsg := safeSlice(b, off, srvMsgLen)
	off += srvMsgLen
	data := safeSlice(b, off, dataLen)
	fmt.Printf("    - Status: %s (0x%02X)\n", authorStatusName(b[0]), b[0])
	fmt.Printf("    - Server message length: %d\n", srvMsgLen)
	if srvMsgLen > 0 {
		fmt.Printf("    - Server message: %s\n", escapedStr(srvMsg))
	}
	fmt.Printf("    - Data length: %d\n", dataLen)
	if dataLen > 0 {
		fmt.Printf("    - Data: %s\n", escapedStr(data))
	}
	for i, al := range argLens {
		arg := safeSlice(b, off, int(al))
		off += int(al)
		fmt.Printf("    - Argument %d: %s\n", i, string(arg))
	}
}

func printAcctRequest(b []byte) {
	if len(b) < 9 {
		fmt.Printf("    - Body: (truncated)\n")
		return
	}
	argCnt := int(b[8])
	if len(b) < 9+argCnt {
		fmt.Printf("    - Body: (truncated)\n")
		return
	}
	userLen := int(b[5])
	portLen := int(b[6])
	remLen := int(b[7])
	argLens := b[9 : 9+argCnt]
	off := 9 + argCnt
	user := safeSlice(b, off, userLen)
	off += userLen
	port := safeSlice(b, off, portLen)
	off += portLen
	rem := safeSlice(b, off, remLen)
	off += remLen
	fmt.Printf("    - Accounting flags: 0x%02X\n", b[0])
	fmt.Printf("    - Authentication method: %s\n", authenMethodName(b[1]))
	fmt.Printf("    - Privilege level: 0x%02X\n", b[2])
	fmt.Printf("    - Authentication type: %s\n", authenTypeName(b[3]))
	fmt.Printf("    - Service: %s\n", authenSvcName(b[4]))
	fmt.Printf("    - User len: %d\n", userLen)
	if userLen > 0 {
		fmt.Printf("    - User: %s\n", displayStr(user))
	}
	fmt.Printf("    - Port len: %d\n", portLen)
	if portLen > 0 {
		fmt.Printf("    - Port: %s\n", displayStr(port))
	}
	fmt.Printf("    - Remaddr len: %d\n", remLen)
	if remLen > 0 {
		fmt.Printf("    - Remote Address: %s\n", displayStr(rem))
	}
	for i, al := range argLens {
		arg := safeSlice(b, off, int(al))
		off += int(al)
		fmt.Printf("    - Argument %d: %s\n", i, displayStr(arg))
	}
}

func printAcctReply(b []byte) {
	if len(b) < 5 {
		fmt.Printf("    - Body: (truncated)\n")
		return
	}
	srvMsgLen := int(b[0])<<8 | int(b[1])
	dataLen := int(b[2])<<8 | int(b[3])
	off := 5
	srvMsg := safeSlice(b, off, srvMsgLen)
	off += srvMsgLen
	data := safeSlice(b, off, dataLen)
	fmt.Printf("    - Status: %s (0x%02X)\n", acctStatusName(b[4]), b[4])
	fmt.Printf("    - Server message length: %d\n", srvMsgLen)
	if srvMsgLen > 0 {
		fmt.Printf("    - Server message: %s\n", escapedStr(srvMsg))
	}
	fmt.Printf("    - Data length: %d\n", dataLen)
	if dataLen > 0 {
		fmt.Printf("    - Data: %s\n", escapedStr(data))
	}
}

// ─── Name helpers ─────────────────────────────────────────────────────────────

func typeName(t byte) string {
	switch t {
	case tacAuthen:
		return "Authentication"
	case tacAuthor:
		return "Authorization"
	case tacAcct:
		return "Accounting"
	}
	return fmt.Sprintf("0x%02X", t)
}

func roleName(pktType, seqNo byte, dstPort uint16) string {
	if pktType == tacAuthen {
		switch {
		case seqNo == 1:
			return "Authentication Start"
		case seqNo%2 == 0:
			return "Authentication Reply"
		default:
			return "Authentication Continue"
		}
	}
	if pktType == tacAuthor {
		if dstPort == 49 {
			return "Authorization Request"
		}
		return "Authorization Reply"
	}
	if pktType == tacAcct {
		if dstPort == 49 {
			return "Accounting Request"
		}
		return "Accounting Reply"
	}
	return fmt.Sprintf("TYPE_0x%02X", pktType)
}

func authenActionName(a byte) string {
	switch a {
	case authenLogin:
		return "Inbound Login"
	case authenChpass:
		return "Change password request"
	case authenSendauth:
		return "Send Authentication"
	}
	return fmt.Sprintf("Unknown (%d)", a)
}

func authenTypeName(t byte) string {
	switch t {
	case authenTypeASCII:
		return "ASCII"
	case authenTypePAP:
		return "PAP"
	case authenTypeCHAP:
		return "CHAP"
	case authenTypeARAP:
		return "ARAP"
	case authenTypeMSCHAP:
		return "MSCHAP"
	case authenTypeMSCHAPv2:
		return "MSCHAPv2"
	}
	return fmt.Sprintf("Unknown (%d)", t)
}

func authenSvcName(s byte) string {
	switch s {
	case authenSvcNone:
		return "None"
	case authenSvcLogin:
		return "Login"
	case authenSvcEnable:
		return "Enable"
	case authenSvcPPP:
		return "PPP"
	case authenSvcARAP:
		return "ARAP"
	case authenSvcPT:
		return "PT"
	case authenSvcRCMD:
		return "RCMD"
	case authenSvcX25:
		return "X.25"
	case authenSvcNASI:
		return "NASI"
	}
	return fmt.Sprintf("Unknown (%d)", s)
}

func authenReplyStatusName(s byte) string {
	switch s {
	case replyPass:
		return "Authentication Passed"
	case replyFail:
		return "Authentication Failed"
	case replyGetdata:
		return "Send Data"
	case replyGetuser:
		return "Send Username"
	case replyGetpass:
		return "Send Password"
	case replyRestart:
		return "Restart"
	case replyError:
		return "Error"
	case replyFollow:
		return "Follow"
	}
	return fmt.Sprintf("Unknown (0x%02x)", s)
}

func authorStatusName(s byte) string {
	switch s {
	case authorPassAdd:
		return "PASS_ADD"
	case authorPassRepl:
		return "PASS_REPL"
	case authorFail:
		return "FAIL"
	case authorError:
		return "ERROR"
	case authorFollow:
		return "FOLLOW"
	}
	return fmt.Sprintf("0x%02X", s)
}

func acctStatusName(s byte) string {
	switch s {
	case acctSuccess:
		return "SUCCESS"
	case acctError:
		return "ERROR"
	case acctFollow:
		return "FOLLOW"
	}
	return fmt.Sprintf("0x%02X", s)
}

func authenMethodName(m byte) string {
	names := map[byte]string{
		0x00: "NOT_SET", 0x01: "NONE", 0x02: "KRB5", 0x03: "LINE",
		0x04: "ENABLE", 0x05: "LOCAL", 0x06: "TACACSPLUS",
		0x08: "GUEST", 0x09: "RADIUS", 0x0A: "KRB4", 0x0B: "RCMD",
	}
	if n, ok := names[m]; ok {
		return n
	}
	return fmt.Sprintf("0x%02X", m)
}

func safeSlice(b []byte, off, n int) []byte {
	if n <= 0 {
		return nil
	}
	if off+n > len(b) {
		if off < len(b) {
			return b[off:]
		}
		return nil
	}
	return b[off : off+n]
}

func escapedStr(b []byte) string {
	s := string(b)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

func displayStr(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, `\x%02x`, c)
		}
	}
	return sb.String()
}
