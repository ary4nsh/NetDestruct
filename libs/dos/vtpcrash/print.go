package vtpcrash

import (
	"netdestruct/libs/intelligence-gathering/dtpenum"
)

const (
	vtpTag = "\x1b[35m[VTP]\x1b[0m"
	dtpTag = "\x1b[38;5;208m[DTP]\x1b[0m"
)

type printResult struct {
	Tag    string
	SrcMAC string
	Body   string
}

func printReceived(frame []byte, iface string, frameNum int) (printResult, bool) {
	if src, body, ok := formatVTPFrame(frame, iface, frameNum); ok {
		return printResult{Tag: vtpTag, SrcMAC: src, Body: body}, true
	}
	if pkt, ok := dtpenum.TryFormat(frame); ok {
		return printResult{Tag: dtpTag, SrcMAC: pkt.SourceMAC, Body: pkt.Body}, true
	}
	return printResult{}, false
}
