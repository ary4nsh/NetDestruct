package smbvers

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unicode/utf16"
)

const (
	samDesiredAccess     = 0x02000000 // MAXIMUM_ALLOWED
	samDomainOpenAccess  = 0x02000000 // MAXIMUM_ALLOWED
	samEnumMaxLen        = 0xffff
	samUserNormalAccount = 0x00000010

	opSamrConnect                     = 0
	opSamrLookupDomainInSamServer     = 5
	opSamrEnumerateDomainsInSamServer = 6
	opSamrOpenDomain                  = 7
	opSamrEnumerateUsersInDomain       = 13
	opSamrEnumerateGroupsInDomain      = 11
	opSamrEnumerateAliasesInDomain      = 15
	opSamrQueryInformationDomain      = 8
	opSamrQueryDisplayInformation     = 40

	opNetrShareEnumAll  = 15
	opNetrServerGetInfo = 21

	opRpcEnumPrinters = 0

	domainPasswordInfo = 1
	domainLogoffInfo   = 3
	domainLockoutInfo  = 12
	domainDisplayUser  = 1
	win32InsufficientBuffer = 122
)

type samDomain struct {
	Name   string
	SID    string
	SIDRaw []byte
}

// EnumUser is a SAM account with optional display metadata.
type EnumUser struct {
	RID         uint32
	Name        string
	FullName    string
	ACB         uint32
	Description string
}

// EnumGroup is a SAM group or alias name and RID.
type EnumGroup struct {
	RID  uint32
	Name string
	Type string
}

// EnumShare is an SMB share name, type label, and remark.
type EnumShare struct {
	Name    string
	Type    string
	Comment string
}

// ShareAccess holds share mapping/listing test results.
type ShareAccess struct {
	Mapping string
	Listing string
}

// EnumPrinter is a spoolss printer entry.
type EnumPrinter struct {
	Name        string
	Description string
	Comment     string
	Flags       uint32
}

// PasswordPolicy holds domain password policy fields.
type PasswordPolicy struct {
	MinLength          uint16
	HistoryLength      uint16
	PasswordProperties uint32
	MaxPasswordAge     samrAge
	MinPasswordAge     samrAge
	LockoutThreshold   uint16
	LockoutDuration    int64
	LockoutWindow      int64
	ForceLogoff        samrAge
}

// samrAge mirrors SAMR OLD_LARGE_INTEGER for policy formatting.
type samrAge struct {
	LowPart  uint32
	HighPart int32
}

// ServerInfo holds OS metadata.
type ServerInfo struct {
	PlatformID uint32
	Major      uint32
	Minor      uint32
	Type       uint32
	TypeString string
	Name       string
}

func samrConnect(s *SMBSession) ([]byte, error) {
	w := newNDRWriter()
	w.u32(0)
	w.u32(samDesiredAccess)
	return s.samrCall(opSamrConnect, w.bytes())
}

func decodeSamrError(stub []byte) error {
	if len(stub) < 4 {
		return nil
	}
	st := binary.LittleEndian.Uint32(stub[len(stub)-4:])
	if st == 0 || st == 0x00000105 {
		return nil
	}
	return fmt.Errorf("samr status 0x%08x", st)
}

func samrEnumDomains(s *SMBSession, serverHandle []byte) ([]samDomain, error) {
	var all []samDomain
	ctx := uint32(0)
	for {
		w := newNDRWriter()
		w.b = append(w.b, serverHandle...)
		w.u32(ctx)
		w.u32(samEnumMaxLen)
		resp, err := s.samrCall(opSamrEnumerateDomainsInSamServer, w.bytes())
		if err != nil {
			return all, fmt.Errorf("enumerate domains (ctx=%d stub=%d): %w", ctx, len(w.bytes()), err)
		}
		doms, next, err := decodeDomainEnum(resp)
		if err != nil {
			return all, err
		}
		all = append(all, doms...)
		if next == 0 || len(doms) == 0 {
			break
		}
		ctx = next
	}
	return all, nil
}

// beginDomainInfoUnion positions the reader past the PSAMPR_DOMAIN_INFO_BUFFER
// pointer and union tag. NDRUNION pads to a DWORD after the USHORT tag.
func beginDomainInfoUnion(r *ndrReader, wantClass uint16) error {
	ref, ok := r.u32()
	if !ok || ref == 0 {
		return fmt.Errorf("null domain info buffer")
	}
	tag, ok := r.u16()
	if !ok {
		return fmt.Errorf("short domain info tag")
	}
	r.align(4)
	if tag != wantClass {
		return fmt.Errorf("unexpected domain info class %d (want %d)", tag, wantClass)
	}
	return nil
}

func decodeDomainPasswordInfo(stub []byte) (*PasswordPolicy, error) {
	r := newNDRReader(stub)
	if err := beginDomainInfoUnion(r, domainPasswordInfo); err != nil {
		return nil, err
	}
	minLen, ok := r.u16()
	if !ok {
		return nil, fmt.Errorf("short password policy")
	}
	hist, ok := r.u16()
	if !ok {
		return nil, fmt.Errorf("short password policy")
	}
	props, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short password policy")
	}
	maxLow, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short password policy")
	}
	maxHigh, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short password policy")
	}
	minLow, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short password policy")
	}
	minHigh, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short password policy")
	}
	return &PasswordPolicy{
		MinLength:          minLen,
		HistoryLength:      hist,
		PasswordProperties: props,
		MaxPasswordAge:     samrAge{LowPart: maxLow, HighPart: int32(maxHigh)},
		MinPasswordAge:     samrAge{LowPart: minLow, HighPart: int32(minHigh)},
	}, nil
}

func decodeDomainLockoutInfo(stub []byte, pol *PasswordPolicy) error {
	r := newNDRReader(stub)
	if err := beginDomainInfoUnion(r, domainLockoutInfo); err != nil {
		return err
	}
	// LARGE_INTEGER (hyper) requires 8-byte alignment.
	r.align(8)
	lockDur, ok := r.u64()
	if !ok {
		return fmt.Errorf("short lockout policy")
	}
	lockWin, ok := r.u64()
	if !ok {
		return fmt.Errorf("short lockout policy")
	}
	thresh, ok := r.u16()
	if !ok {
		return fmt.Errorf("short lockout policy")
	}
	pol.LockoutDuration = int64(lockDur)
	pol.LockoutWindow = int64(lockWin)
	pol.LockoutThreshold = thresh
	return nil
}

func decodeDomainLogoffInfo(stub []byte, pol *PasswordPolicy) error {
	r := newNDRReader(stub)
	if err := beginDomainInfoUnion(r, domainLogoffInfo); err != nil {
		return err
	}
	low, ok := r.u32()
	if !ok {
		return fmt.Errorf("short logoff policy")
	}
	high, ok := r.u32()
	if !ok {
		return fmt.Errorf("short logoff policy")
	}
	pol.ForceLogoff = samrAge{LowPart: low, HighPart: int32(high)}
	return nil
}

func filetimeToSamrAge(v int64) samrAge {
	return samrAge{LowPart: uint32(v), HighPart: int32(v >> 32)}
}

func decodeShareEnum(stub []byte) ([]EnumShare, error) {
	r := newNDRReader(stub)
	level, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short share enum")
	}
	_ = level
	tag, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short share switch")
	}
	_ = tag
	ctrRef, ok := r.u32()
	if !ok || ctrRef == 0 {
		return nil, nil
	}
	entries, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("bad share entries")
	}
	bufRef, ok := r.u32()
	if !ok || bufRef == 0 || entries == 0 {
		return nil, nil
	}
	max, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("bad share array")
	}
	if max < entries {
		entries = max
	}

	type meta struct {
		namePtr, remarkPtr uint32
		typ                uint32
	}
	metas := make([]meta, 0, entries)
	for i := uint32(0); i < entries; i++ {
		namePtr, ok := r.u32()
		if !ok {
			break
		}
		typ, ok := r.u32()
		if !ok {
			break
		}
		remarkPtr, ok := r.u32()
		if !ok {
			break
		}
		metas = append(metas, meta{namePtr: namePtr, remarkPtr: remarkPtr, typ: typ})
	}

	out := make([]EnumShare, 0, len(metas))
	for _, m := range metas {
		sh := EnumShare{Type: shareTypeLabel(m.typ)}
		if m.namePtr != 0 {
			if s, ok := r.readDeferredWString(); ok {
				sh.Name = s
			}
		}
		if m.remarkPtr != 0 {
			if s, ok := r.readDeferredWString(); ok {
				sh.Comment = s
			}
		}
		out = append(out, sh)
	}
	return out, nil
}

func shareTypeLabel(t uint32) string {
	switch t & 0x0FFFFFFF {
	case 0:
		return "Disk"
	case 1:
		return "Print"
	case 2:
		return "Device"
	case 3:
		return "IPC"
	default:
		return fmt.Sprintf("0x%x", t)
	}
}

func decodeServerInfo(stub []byte) (*ServerInfo, error) {
	r := newNDRReader(stub)
	ref, ok := r.u32()
	if !ok || ref == 0 {
		return nil, fmt.Errorf("no server info")
	}
	platform, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short server info")
	}
	name, ok := r.readConformantVaryingWString()
	if !ok {
		return nil, fmt.Errorf("short server name")
	}
	major, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short version")
	}
	minor, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short version")
	}
	typ, ok := r.u32()
	if !ok {
		return nil, fmt.Errorf("short type")
	}
	return &ServerInfo{
		PlatformID: platform,
		Major:      major,
		Minor:      minor,
		Type:       typ,
		TypeString: decodeServerTypeString(typ),
		Name:       name,
	}, nil
}

func (r *ndrReader) u64() (uint64, bool) {
	if r.off+8 > len(r.data) {
		return 0, false
	}
	v := binary.LittleEndian.Uint64(r.data[r.off : r.off+8])
	r.off += 8
	return v, true
}

func samrOpenDomainByName(s *SMBSession, serverHandle []byte, name string) ([]byte, error) {
	sidResp, err := samrLookupDomain(s, serverHandle, name)
	if err != nil {
		return nil, err
	}
	sidRaw, _, err := parseDomainSID(sidResp)
	if err != nil {
		return nil, err
	}
	w := newNDRWriter()
	w.b = append(w.b, serverHandle...)
	w.u32(samDomainOpenAccess)
	w.sid(sidRaw)
	return s.samrCall(opSamrOpenDomain, w.bytes())
}

func samrOpenAccountDomain(s *SMBSession, serverHandle []byte) ([]byte, error) {
	domains, err := samrEnumDomains(s, serverHandle)
	if err != nil {
		return nil, err
	}
	var pick *samDomain
	for i := range domains {
		d := &domains[i]
		if d.Name == "Builtin" {
			continue
		}
		pick = d
		break
	}
	if pick == nil && len(domains) > 0 {
		pick = &domains[0]
	}
	if pick == nil || pick.Name == "" {
		return nil, fmt.Errorf("no account domain")
	}
	return samrOpenDomainByName(s, serverHandle, pick.Name)
}

func decodeDomainEnum(stub []byte) ([]samDomain, uint32, error) {
	if err := decodeSamrError(stub); err != nil {
		return nil, 0, err
	}
	r := newNDRReader(stub)
	next, ok := r.u32()
	if !ok {
		return nil, 0, fmt.Errorf("short enum domains response")
	}
	bufRef, ok := r.u32()
	if !ok || bufRef == 0 {
		return nil, next, nil
	}
	entriesRead, ok := r.u32()
	if !ok {
		return nil, next, fmt.Errorf("bad domain buffer")
	}
	arrRef, ok := r.u32()
	if !ok || arrRef == 0 {
		return nil, next, nil
	}
	_, ok = r.u32()
	if !ok {
		return nil, next, fmt.Errorf("bad domain array max")
	}
	_, ok = r.u32()
	if !ok {
		return nil, next, fmt.Errorf("bad domain array offset")
	}
	actual, ok := r.u32()
	if !ok {
		return nil, next, fmt.Errorf("bad domain array actual")
	}
	if actual == 0 {
		actual = entriesRead
	}

	type entryRef struct {
		nameRef uint32
		sidRef  uint32
	}
	var refs []entryRef
	for i := uint32(0); i < actual; i++ {
		_, ok := r.u16()
		if !ok {
			break
		}
		_, ok = r.u16()
		if !ok {
			break
		}
		nameRef, ok := r.u32()
		if !ok {
			break
		}
		sidRef, ok := r.u32()
		if !ok {
			break
		}
		refs = append(refs, entryRef{nameRef: nameRef, sidRef: sidRef})
	}

	var out []samDomain
	for _, ref := range refs {
		if ref.nameRef == 0 {
			continue
		}
		name, ok := r.readConformantVaryingWString()
		if !ok || name == "" {
			continue
		}
		var sidRaw []byte
		var sidStr string
		if ref.sidRef != 0 {
			sidRaw, sidStr, ok = r.readSIDRaw()
			if !ok {
				sidRaw, sidStr = nil, ""
			}
		}
		out = append(out, samDomain{Name: name, SID: sidStr, SIDRaw: sidRaw})
	}
	if len(out) == 0 {
		names := extractUTF16DomainNames(stub)
		sids := extractSIDCandidates(stub)
		for i, name := range names {
			d := samDomain{Name: name}
			if i < len(sids) {
				d.SIDRaw = sids[i]
				d.SID = formatSID(sids[i])
			}
			out = append(out, d)
		}
	}
	return out, next, nil
}

func extractSIDCandidates(data []byte) [][]byte {
	var out [][]byte
	for i := 0; i+8 <= len(data); i++ {
		rev, cnt := data[i], data[i+1]
		if rev != 1 || cnt > 15 {
			continue
		}
		need := 8 + int(cnt)*4
		if i+need > len(data) {
			continue
		}
		raw := append([]byte(nil), data[i:i+need]...)
		out = append(out, raw)
	}
	return out
}

func extractUTF16DomainNames(stub []byte) []string {
	var names []string
	seen := map[string]bool{}
	for i := 0; i+4 <= len(stub); i += 2 {
		if stub[i] == 0 && stub[i+1] == 0 {
			continue
		}
		if stub[i+1] != 0 || stub[i] < 0x20 {
			continue
		}
		name, next := readUTF16At(stub, i)
		if name == "" || seen[name] {
			i = next - 2
			continue
		}
		if isLikelyDomainName(name) {
			seen[name] = true
			names = append(names, name)
		}
		i = next - 2
	}
	return names
}

func readUTF16At(data []byte, off int) (string, int) {
	var runes []rune
	for off+2 <= len(data) {
		c := binary.LittleEndian.Uint16(data[off : off+2])
		off += 2
		if c == 0 {
			break
		}
		runes = append(runes, rune(c))
	}
	return string(runes), off
}

func isLikelyDomainName(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func samrLookupDomain(s *SMBSession, serverHandle []byte, name string) ([]byte, error) {
	chars := utf16.Encode([]rune(name))
	byteLen := uint16(len(chars) * 2)
	w := newNDRWriter()
	w.b = append(w.b, serverHandle...)
	// RPC_UNICODE_STRING: Length == MaximumLength, no trailing NUL
	w.u16(byteLen)
	w.u16(byteLen)
	w.u32(0x20000)
	w.u32(uint32(len(chars)))
	w.u32(0)
	w.u32(uint32(len(chars)))
	w.align(2)
	for _, c := range chars {
		w.u16(c)
	}
	return s.samrCall(opSamrLookupDomainInSamServer, w.bytes())
}

func parseDomainSID(stub []byte) ([]byte, string, error) {
	r := newNDRReader(stub)
	ref, ok := r.u32()
	if !ok || ref == 0 {
		return nil, "", fmt.Errorf("no domain sid")
	}
	// RPC_SID is a conformant struct: SubAuthorityCount ULONG, then SID body.
	if _, ok = r.u32(); !ok {
		return nil, "", fmt.Errorf("short sid count")
	}
	sidRaw, sidStr, ok := r.readSIDRaw()
	if !ok {
		return nil, "", fmt.Errorf("short domain sid")
	}
	return sidRaw, sidStr, nil
}

func parseContextHandle(stub []byte) ([]byte, error) {
	if len(stub) < 20 {
		return nil, fmt.Errorf("short context handle")
	}
	h := append([]byte(nil), stub[:20]...)
	if len(stub) >= 24 {
		st := binary.LittleEndian.Uint32(stub[len(stub)-4:])
		// Heuristic: when handle is all zero and trailing NTSTATUS is set, treat as failure.
		zero := true
		for _, b := range h {
			if b != 0 {
				zero = false
				break
			}
		}
		if zero && st != 0 && st != 0x00000105 {
			return nil, fmt.Errorf("samr status 0x%08x", st)
		}
	}
	return h, nil
}

func samrEnumRIDs(s *SMBSession, domainHandle []byte, opnum uint16, userAccountControl *uint32) ([]ridName, error) {
	const statusMoreEntries = 0x00000105
	var all []ridName
	ctx := uint32(0)
	for {
		w := newNDRWriter()
		w.b = append(w.b, domainHandle...)
		w.u32(ctx)
		if userAccountControl != nil {
			w.u32(*userAccountControl)
		}
		w.u32(samEnumMaxLen)
		resp, err := s.samrCall(opnum, w.bytes())
		if err != nil {
			if len(all) > 0 {
				return all, nil
			}
			return nil, err
		}
		items, next, status, err := decodeRIDEnumResponse(resp)
		if err != nil {
			if len(all) > 0 {
				return all, nil
			}
			return nil, err
		}
		all = append(all, items...)
		// Continue only on STATUS_MORE_ENTRIES.
		// EnumerationContext alone is opaque and may be non-zero on success.
		if status != statusMoreEntries {
			break
		}
		if next == ctx && len(items) == 0 {
			break
		}
		ctx = next
		if len(all) > 100000 {
			break
		}
	}
	return all, nil
}

func decodeRIDEnumResponse(stub []byte) ([]ridName, uint32, uint32, error) {
	if len(stub) < 8 {
		return nil, 0, 0, fmt.Errorf("short rid enum response")
	}
	// Trailing CountReturned + ErrorCode (NTSTATUS).
	status := binary.LittleEndian.Uint32(stub[len(stub)-4:])
	r := newNDRReader(stub)
	next, ok := r.u32()
	if !ok {
		return nil, 0, status, fmt.Errorf("short enumeration context")
	}
	items, err := decodeRIDEnumBuffer(stub[r.off : len(stub)-8])
	if err != nil {
		return nil, next, status, err
	}
	return items, next, status, nil
}

// EnumerateSAMUsers lists users via SAMR QueryDisplayInformation.
func EnumerateSAMUsers(s *SMBSession) ([]EnumUser, error) {
	srvResp, err := samrConnect(s)
	if err != nil {
		return nil, err
	}
	srvHandle, err := parseContextHandle(srvResp)
	if err != nil {
		return nil, err
	}
	domResp, err := samrOpenAccountDomain(s, srvHandle)
	if err != nil {
		return nil, err
	}
	domHandle, err := parseContextHandle(domResp)
	if err != nil {
		return nil, err
	}
	return samrQueryDisplayUsers(s, domHandle)
}

func samrQueryDisplayUsers(s *SMBSession, domainHandle []byte) ([]EnumUser, error) {
	var out []EnumUser
	var index uint32
	for {
		w := newNDRWriter()
		w.b = append(w.b, domainHandle...)
		w.u32(domainDisplayUser)
		w.u32(index)
		w.u32(0x200)
		w.u32(0x3fff)
		resp, err := s.samrCall(opSamrQueryDisplayInformation, w.bytes())
		if err != nil {
			if len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
		batch, totalReturned, err := decodeDisplayUsers(resp)
		if err != nil {
			if len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
		out = append(out, batch...)
		if len(batch) == 0 || totalReturned == 0 {
			break
		}
		// Advance by last entry Index (1-based display index).
		last := batch[len(batch)-1]
		if last.RID == 0 {
			break
		}
		index += uint32(len(batch))
		if uint32(len(batch)) < 0x200 && totalReturned < 0x3fff {
			break
		}
		if index > 100000 {
			break
		}
	}
	return out, nil
}

func decodeDisplayUsers(stub []byte) ([]EnumUser, uint32, error) {
	if err := decodeSamrError(stub); err != nil {
		return nil, 0, err
	}
	r := newNDRReader(stub)
	_, ok := r.u32() // TotalAvailable
	if !ok {
		return nil, 0, fmt.Errorf("short display info")
	}
	totalReturned, ok := r.u32()
	if !ok {
		return nil, 0, fmt.Errorf("short display info")
	}
	tag, ok := r.u32() // DOMAIN_DISPLAY_INFORMATION
	if !ok {
		return nil, 0, fmt.Errorf("short display switch")
	}
	_ = tag
	entriesRead, ok := r.u32()
	if !ok {
		return nil, 0, fmt.Errorf("short display buffer")
	}
	bufRef, ok := r.u32()
	if !ok || bufRef == 0 || entriesRead == 0 {
		return nil, totalReturned, nil
	}
	maxCount, ok := r.u32()
	if !ok {
		return nil, 0, fmt.Errorf("short display array")
	}
	if maxCount < entriesRead {
		entriesRead = maxCount
	}

	type meta struct {
		index, rid, acb uint32
		nameLen, commentLen, fullLen uint16
		namePtr, commentPtr, fullPtr uint32
	}
	metas := make([]meta, 0, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		var m meta
		var ok bool
		if m.index, ok = r.u32(); !ok {
			break
		}
		if m.rid, ok = r.u32(); !ok {
			break
		}
		if m.acb, ok = r.u32(); !ok {
			break
		}
		if m.nameLen, m.namePtr, ok = r.readRPCUnicodeHeader(); !ok {
			break
		}
		if m.commentLen, m.commentPtr, ok = r.readRPCUnicodeHeader(); !ok {
			break
		}
		if m.fullLen, m.fullPtr, ok = r.readRPCUnicodeHeader(); !ok {
			break
		}
		metas = append(metas, m)
	}

	out := make([]EnumUser, 0, len(metas))
	for _, m := range metas {
		u := EnumUser{RID: m.rid, ACB: m.acb}
		if m.namePtr != 0 {
			if s, ok := r.readDeferredWString(); ok {
				u.Name = s
			}
		}
		if m.commentPtr != 0 {
			if s, ok := r.readDeferredWString(); ok {
				u.Description = s
			}
		}
		if m.fullPtr != 0 {
			if s, ok := r.readDeferredWString(); ok {
				u.FullName = s
			}
		}
		out = append(out, u)
	}
	return out, totalReturned, nil
}

// EnumerateSAMGroups lists builtin aliases and domain groups via SAMR.
func EnumerateSAMGroups(s *SMBSession) ([]EnumGroup, error) {
	srvResp, err := samrConnect(s)
	if err != nil {
		return nil, err
	}
	srvHandle, err := parseContextHandle(srvResp)
	if err != nil {
		return nil, err
	}

	var out []EnumGroup

	if domResp, err := samrOpenDomainByName(s, srvHandle, "Builtin"); err == nil {
		if domHandle, err := parseContextHandle(domResp); err == nil {
			if aliases, err := samrEnumRIDs(s, domHandle, opSamrEnumerateAliasesInDomain, nil); err == nil {
				for _, item := range aliases {
					out = append(out, EnumGroup{RID: item.RID, Name: item.Name, Type: "builtin"})
				}
			}
		}
	}

	if domResp, err := samrOpenAccountDomain(s, srvHandle); err == nil {
		if domHandle, err := parseContextHandle(domResp); err == nil {
			if groups, err := samrEnumRIDs(s, domHandle, opSamrEnumerateGroupsInDomain, nil); err == nil {
				for _, item := range groups {
					out = append(out, EnumGroup{RID: item.RID, Name: item.Name, Type: "domain"})
				}
			}
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no groups returned")
	}
	sortEnumGroups(out)
	return out, nil
}

// EnumeratePrinters lists local printers via spoolss RpcEnumPrinters.
func EnumeratePrinters(s *SMBSession) ([]EnumPrinter, error) {
	// Probe with a NULL buffer to learn pcbNeeded.
	_, _, err := spoolEnumPrinters(s, 0, false)
	needed := uint32(4096)
	if err != nil {
		var insuf *spoolInsufficientBuffer
		if !asSpoolInsufficient(err, &insuf) {
			return nil, err
		}
		needed = insuf.Needed
	}
	if needed == 0 {
		needed = 4096
	}
	buf, count, err := spoolEnumPrinters(s, needed, true)
	if err != nil {
		return nil, err
	}
	return decodePrinterEnumBuffer(buf, count)
}

type spoolInsufficientBuffer struct {
	Needed uint32
}

func (e *spoolInsufficientBuffer) Error() string {
	return fmt.Sprintf("spool enum needed %d", e.Needed)
}

func asSpoolInsufficient(err error, out **spoolInsufficientBuffer) bool {
	if e, ok := err.(*spoolInsufficientBuffer); ok {
		*out = e
		return true
	}
	return false
}

func spoolEnumPrinters(s *SMBSession, bufSize uint32, withBuf bool) ([]byte, uint32, error) {
	host, _ := s.HostPort()
	w := newNDRWriter()
	w.u32(printerEnumLocal)
	w.uniqueWString(`\\` + host)
	w.align(4)
	w.u32(1) // Level = PRINTER_INFO_1
	if withBuf && bufSize > 0 {
		w.u32(0x20004) // pPrinterEnum referent
		w.u32(bufSize) // conformant max_count
		w.b = append(w.b, make([]byte, bufSize)...)
		w.u32(bufSize) // cbBuf
	} else {
		w.u32(0) // pPrinterEnum = NULL
		w.u32(0) // cbBuf
	}
	resp, err := s.spoolCall(opRpcEnumPrinters, w.bytes())
	if err != nil {
		return nil, 0, err
	}
	return decodeSpoolEnumPrintersResp(resp)
}

func decodeSpoolEnumPrintersResp(stub []byte) ([]byte, uint32, error) {
	r := newNDRReader(stub)
	ref, ok := r.u32()
	if !ok {
		return nil, 0, fmt.Errorf("short spool enum response")
	}
	var buf []byte
	if ref != 0 {
		maxCount, ok := r.u32()
		if !ok {
			return nil, 0, fmt.Errorf("short spool buffer")
		}
		if r.off+int(maxCount) > len(r.data) {
			return nil, 0, fmt.Errorf("short spool buffer data")
		}
		buf = append([]byte(nil), r.data[r.off:r.off+int(maxCount)]...)
		r.off += int(maxCount)
	}
	needed, ok := r.u32()
	if !ok {
		return nil, 0, fmt.Errorf("short spool needed")
	}
	returned, ok := r.u32()
	if !ok {
		return nil, 0, fmt.Errorf("short spool returned")
	}
	status, ok := r.u32()
	if !ok {
		return nil, 0, fmt.Errorf("short spool status")
	}
	if status == win32InsufficientBuffer {
		return nil, 0, &spoolInsufficientBuffer{Needed: needed}
	}
	if status != 0 {
		return nil, 0, fmt.Errorf("spool enum status 0x%08x", status)
	}
	return buf, returned, nil
}

// QueryPasswordPolicy reads domain password / lockout / logoff policy via SAMR.
func QueryPasswordPolicy(s *SMBSession) (*PasswordPolicy, error) {
	srvResp, err := samrConnect(s)
	if err != nil {
		return nil, err
	}
	srvHandle, err := parseContextHandle(srvResp)
	if err != nil {
		return nil, err
	}
	domResp, err := samrOpenAccountDomain(s, srvHandle)
	if err != nil {
		return nil, err
	}
	domHandle, err := parseContextHandle(domResp)
	if err != nil {
		return nil, err
	}

	passResp, err := samrQueryDomainInfo(s, domHandle, domainPasswordInfo)
	if err != nil {
		return nil, err
	}
	pol, err := decodeDomainPasswordInfo(passResp)
	if err != nil {
		return nil, err
	}
	if lockResp, err := samrQueryDomainInfo(s, domHandle, domainLockoutInfo); err == nil {
		_ = decodeDomainLockoutInfo(lockResp, pol)
	}
	if logoffResp, err := samrQueryDomainInfo(s, domHandle, domainLogoffInfo); err == nil {
		_ = decodeDomainLogoffInfo(logoffResp, pol)
	}
	return pol, nil
}

func samrQueryDomainInfo(s *SMBSession, domHandle []byte, infoClass uint16) ([]byte, error) {
	w := newNDRWriter()
	w.b = append(w.b, domHandle...)
	w.u16(infoClass)
	resp, err := s.samrCall(opSamrQueryInformationDomain, w.bytes())
	if err != nil {
		return nil, err
	}
	if err := decodeSamrError(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// EnumerateShares lists shares via SRVSVC NetrShareEnum.
func EnumerateShares(s *SMBSession) ([]EnumShare, error) {
	host, _ := s.HostPort()
	w := newNDRWriter()
	w.uniqueWString(host)
	w.u32(1)        // Level
	w.u32(1)        // SHARE_ENUM_STRUCT.Level / switch
	w.u32(0x20004)  // ShareInfo container pointer
	w.u32(0)        // EntriesRead
	w.u32(0)        // Buffer (NULL)
	w.u32(0xffffffff)
	w.u32(0x20008) // ResumeHandle pointer
	w.u32(0)       // ResumeHandle value
	resp, err := s.srvsCall(opNetrShareEnumAll, w.bytes())
	if err != nil {
		return nil, err
	}
	return decodeShareEnum(resp)
}

// QueryServerInfo reads server/OS metadata via NetrServerGetInfo level 101.
func QueryServerInfo(s *SMBSession) (*ServerInfo, error) {
	host, _ := s.HostPort()
	w := newNDRWriter()
	w.uniqueWString(`\\` + host)
	w.u32(101)
	resp, err := s.srvsCall(opNetrServerGetInfo, w.bytes())
	if err != nil {
		return nil, err
	}
	return decodeServerInfo(resp)
}

// TestRPCSession returns true when IPC$ and SAMR bind succeed.
func TestRPCSession(s *SMBSession) bool {
	if err := s.TreeConnectIPC(); err != nil {
		return false
	}
	return s.PipeBind("samr", uuidSAMR, rpcVersionMajorMinor(1, 0))
}

// SessionProbe describes a working SMB/RPC session type.
type SessionProbe struct {
	Label   string
	User    string
	Pass    string
	Outcome LoginOutcome
	Status  uint32
	RPCOK   bool
}

// ProbeSessions tries null, password (when user is set), and guest session logons.
func ProbeSessions(host string, port int, user, pass, domain string) []SessionProbe {
	var out []SessionProbe

	nullOut, nullSt, _ := TryLoginWithStatus(host, port, "", "", domain)
	out = append(out, SessionProbe{
		Label:   "null",
		Outcome: nullOut,
		Status:  mapNullSessionStatus(nullSt),
	})

	if user != "" {
		authOut, authSt, _ := TryLoginWithStatus(host, port, user, pass, domain)
		out = append(out, SessionProbe{
			Label:   "password",
			User:    user,
			Pass:    pass,
			Outcome: authOut,
			Status:  authSt,
		})
	}

	guestUser := randomGuestUser()
	guestOut, guestSt, _ := TryLoginWithStatus(host, port, guestUser, "", domain)
	out = append(out, SessionProbe{
		Label:   "guest",
		User:    guestUser,
		Outcome: guestOut,
		Status:  guestSt,
	})
	return out
}

func mapNullSessionStatus(st uint32) uint32 {
	if st == ntStatusLogonFailure {
		return stAccessDenied
	}
	return st
}

func rpcSessionWorks(host string, port int, user, pass, domain string) bool {
	s, out, err := OpenSMBSession(host, port, user, pass, domain)
	if err != nil || (out != LoginSuccess && out != LoginGuest) {
		return false
	}
	defer s.Close()
	return TestRPCSession(s)
}

// BestEnumSession opens the best available session for RPC enumeration.
func BestEnumSession(host string, port int, user, pass, domain string) (*SMBSession, SessionProbe, error) {
	if user != "" {
		s, out, err := OpenSMBSession(host, port, user, pass, domain)
		if err != nil {
			return nil, SessionProbe{}, fmt.Errorf("authenticated logon failed: %w", err)
		}
		if out != LoginSuccess && out != LoginGuest {
			s.Close()
			return nil, SessionProbe{}, fmt.Errorf("authenticated logon: %s", out.Message())
		}
		if err := s.TreeConnectIPC(); err != nil {
			s.Close()
			return nil, SessionProbe{}, fmt.Errorf("IPC$ tree connect: %w", err)
		}
		if !s.PipeBind("samr", uuidSAMR, rpcVersionMajorMinor(1, 0)) {
			s.Close()
			return nil, SessionProbe{}, fmt.Errorf("SAMR RPC bind failed")
		}
		return s, SessionProbe{
			Label:   "password",
			User:    user,
			Pass:    pass,
			Outcome: out,
			RPCOK:   true,
		}, nil
	}

	probes := ProbeSessions(host, port, "", "", domain)
	for _, p := range probes {
		s, out, err := OpenSMBSession(host, port, p.User, p.Pass, domain)
		if err != nil {
			continue
		}
		if out != LoginSuccess && out != LoginGuest {
			s.Close()
			continue
		}
		if err := s.TreeConnectIPC(); err != nil {
			s.Close()
			continue
		}
		if !s.PipeBind("samr", uuidSAMR, rpcVersionMajorMinor(1, 0)) {
			s.Close()
			continue
		}
		p.Outcome = out
		p.RPCOK = true
		return s, p, nil
	}
	return nil, SessionProbe{}, fmt.Errorf("no RPC session available")
}

func randomGuestUser() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return "nx_" + hex.EncodeToString(b)
}
