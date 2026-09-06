package snmp

import (
	"fmt"
	"strconv"
	"strings"
)

const snmpSetRequestPDU = 0xa3

var oidNamePrefixes = map[string][]int{
	"iso":      {1},
	"org":      {1, 3},
	"dod":      {1, 3, 6},
	"internet": {1, 3, 6, 1},
	"mgmt":     {1, 3, 6, 1, 2},
	"mib-2":    {1, 3, 6, 1, 2, 1},
}

// ParseOIDSpec parses numeric OIDs (1.3.6.1…), iso-prefixed forms (iso.3.6.1…), or a symbolic MIB suffix.
func ParseOIDSpec(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	if s == "" {
		return nil, fmt.Errorf("empty OID")
	}
	if !strings.Contains(s, ".") {
		if oid, ok := lookupSymbolicOID(s); ok {
			return oid, nil
		}
		return nil, fmt.Errorf("unknown symbolic OID %q", s)
	}

	if oid, ok := resolveSymbolicOIDSpec(s); ok {
		return oid, nil
	}

	parts := strings.Split(s, ".")
	var oid []int
	start := 0
	if pref, ok := oidNamePrefixes[strings.ToLower(parts[0])]; ok {
		oid = append(oid, pref...)
		start = 1
	}
	for i := start; i < len(parts); i++ {
		p := strings.TrimSpace(parts[i])
		if p == "" {
			return nil, fmt.Errorf("invalid OID %q", s)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID component %q in %q", p, s)
		}
		oid = append(oid, n)
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("OID must have at least two components: %q", s)
	}
	return oid, nil
}

func lookupSymbolicOID(name string) ([]int, bool) {
	if mibTrie == nil || len(mibTrie) == 0 {
		buildMibTrie()
	}
	name = strings.ToLower(name)
	for _, e := range mibNames {
		if strings.EqualFold(e.name, name) {
			return append([]int(nil), e.oid...), true
		}
	}
	return nil, false
}

// resolveSymbolicOIDSpec resolves forms like sysLocation.0 or system.sysDescr.0.
func resolveSymbolicOIDSpec(s string) ([]int, bool) {
	parts := strings.Split(s, ".")
	for end := len(parts); end >= 1; end-- {
		prefix := strings.Join(parts[:end], ".")
		oid, ok := lookupSymbolicOID(prefix)
		if !ok {
			continue
		}
		out := append([]int(nil), oid...)
		for _, p := range parts[end:] {
			p = strings.TrimSpace(p)
			if p == "" {
				return nil, false
			}
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 {
				return nil, false
			}
			out = append(out, n)
		}
		return out, true
	}
	return nil, false
}

// EncodeSetValue encodes a SET value (INTEGER if numeric, OCTET STRING otherwise).
func EncodeSetValue(raw string) ([]byte, error) {
	s := strings.TrimSpace(raw)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			s = s[1 : len(s)-1]
			return asn1OctetString([]byte(s)), nil
		}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n >= int64(int(^uint(0)>>1)) || n < int64(-int(^uint(0)>>1)-1) {
			return nil, fmt.Errorf("integer out of range: %d", n)
		}
		return asn1Int(int(n)), nil
	}
	return asn1OctetString([]byte(s)), nil
}

func BuildSetRequest(community string, reqID, version int, oid []int, valueEnc []byte) []byte {
	return buildSetRequest(community, reqID, version, oid, valueEnc)
}

func buildSetRequest(community string, reqID, version int, oid []int, valueEnc []byte) []byte {
	varBind := asn1Seq(append(encodeOID(oid), valueEnc...))
	varBindList := asn1Seq(varBind)
	pduBody := append(append(append(asn1Int(reqID), asn1Int(0)...), asn1Int(0)...), varBindList...)
	setPDU := asn1TLV(snmpSetRequestPDU, pduBody)
	msg := append(append(append(asn1Int(version), asn1OctetString([]byte(community))...), setPDU...), []byte{}...)
	return asn1Seq(msg)
}

func ParseSetResponse(b []byte, reqID, version int) (*VarBind, error) {
	return parseSetResponse(b, reqID, version)
}

func parseSetResponse(b []byte, reqID, version int) (*VarBind, error) {
	i := 0
	if readByte(b, &i) != 0x30 {
		return nil, fmt.Errorf("invalid snmp packet")
	}
	if _, ok := readLength(b, &i); !ok {
		return nil, fmt.Errorf("invalid snmp length")
	}
	if readByte(b, &i) != 0x02 {
		return nil, fmt.Errorf("missing snmp version")
	}
	ver, ok := readInt(b, &i)
	if !ok {
		return nil, fmt.Errorf("invalid snmp version")
	}
	if ver != version {
		return nil, fmt.Errorf("unexpected snmp version %d (expected %d)", ver, version)
	}
	if readByte(b, &i) != 0x04 {
		return nil, fmt.Errorf("missing community")
	}
	if _, ok := readOctets(b, &i); !ok {
		return nil, fmt.Errorf("invalid community")
	}
	if readByte(b, &i) != 0xa2 {
		return nil, fmt.Errorf("expected response PDU")
	}
	if _, ok := readLength(b, &i); !ok {
		return nil, fmt.Errorf("invalid pdu length")
	}
	if readByte(b, &i) != 0x02 {
		return nil, fmt.Errorf("missing request id")
	}
	gotReqID, ok := readInt(b, &i)
	if !ok {
		return nil, fmt.Errorf("invalid request id")
	}
	if gotReqID != reqID {
		return nil, fmt.Errorf("request id mismatch")
	}
	if readByte(b, &i) != 0x02 {
		return nil, fmt.Errorf("missing error status")
	}
	errStatus, ok := readInt(b, &i)
	if !ok {
		return nil, fmt.Errorf("invalid error status")
	}
	if readByte(b, &i) != 0x02 {
		return nil, fmt.Errorf("missing error index")
	}
	errIndex, ok := readInt(b, &i)
	if !ok {
		return nil, fmt.Errorf("invalid error index")
	}
	if errStatus != 0 {
		return nil, fmt.Errorf("snmp error status %d at index %d (%s)", errStatus, errIndex, snmpErrorName(errStatus))
	}
	if readByte(b, &i) != 0x30 {
		return nil, fmt.Errorf("missing varbind list")
	}
	if _, ok := readLength(b, &i); !ok {
		return nil, fmt.Errorf("invalid varbind list length")
	}
	if readByte(b, &i) != 0x30 {
		return nil, fmt.Errorf("missing varbind")
	}
	if _, ok := readLength(b, &i); !ok {
		return nil, fmt.Errorf("invalid varbind length")
	}
	if readByte(b, &i) != 0x06 {
		return nil, fmt.Errorf("missing oid in response")
	}
	oidRaw, ok := readOctets(b, &i)
	if !ok {
		return nil, fmt.Errorf("invalid oid in response")
	}
	oid, err := decodeOID(oidRaw)
	if err != nil {
		return nil, err
	}
	tag := readByte(b, &i)
	val, ok := readOctets(b, &i)
	if !ok {
		return nil, fmt.Errorf("invalid value in response")
	}
	return &VarBind{OID: oid, Tag: tag, Data: val}, nil
}

func snmpErrorName(status int) string {
	switch status {
	case 0:
		return "noError"
	case 1:
		return "tooBig"
	case 2:
		return "noSuchName"
	case 3:
		return "badValue"
	case 4:
		return "readOnly"
	case 5:
		return "genErr"
	case 6:
		return "noAccess"
	case 7:
		return "wrongType"
	case 8:
		return "wrongLength"
	case 9:
		return "wrongEncoding"
	case 10:
		return "wrongValue"
	case 11:
		return "noCreation"
	case 12:
		return "inconsistentValue"
	case 13:
		return "resourceUnavailable"
	case 14:
		return "notWritable"
	case 15:
		return "inconsistentName"
	case 16:
		return "authorizationError"
	case 17:
		return "notWritable"
	case 18:
		return "inconsistentName"
	default:
		return "unknown"
	}
}
