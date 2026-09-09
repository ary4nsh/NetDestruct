package dot1qpoison

import (
	"strings"

	"netdestruct/libs/intelligence-gathering/cdpenum"
	"netdestruct/libs/intelligence-gathering/dtpenum"
	"netdestruct/libs/vlan-bypassing/dot1qdouble"
)

const (
	dot1qTag    = "\x1b[97m[802.1Q]\x1b[0m"
	icmpTag     = "\x1b[34m[ICMP]\x1b[0m"
	cdpTag      = "\x1b[34m[CDP]\x1b[0m"
	dtpTag      = "\x1b[38;5;208m[DTP]\x1b[0m"
	arpTag      = "\x1b[38;5;208m[ARP]\x1b[0m"
	successTag  = "\x1b[32m"
	successTagEnd = "\x1b[0m"
)

type printResult struct {
	Tag    string
	SrcMAC string
	DstMAC string
	Body   string
}

func printReceived(frame []byte, strippedVLAN uint16) (printResult, bool) {
	if src, body, ok := cdpenum.FormatReceived(frame); ok {
		return printResult{Tag: cdpTag, SrcMAC: src, Body: body}, true
	}
	if pkt, ok := dtpenum.TryFormat(frame); ok {
		return printResult{Tag: dtpTag, SrcMAC: pkt.SourceMAC, Body: pkt.Body}, true
	}

	pkt, ok := dot1qdouble.FormatPacket(frame, strippedVLAN)
	if !ok {
		return printResult{}, false
	}

	tag := dot1qTag
	if pkt.IsICMP {
		tag = icmpTag
	} else if strings.Contains(pkt.Body, "Address Resolution Protocol") {
		tag = arpTag
	}
	return printResult{Tag: tag, SrcMAC: pkt.SrcMAC, DstMAC: pkt.DstMAC, Body: pkt.Body}, true
}
