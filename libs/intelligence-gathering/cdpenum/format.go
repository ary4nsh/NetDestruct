package cdpenum

// FormatReceived decodes a CDP frame for display. Returns source MAC, body, and ok.
func FormatReceived(frame []byte) (srcMAC, body string, ok bool) {
	pkt, ok := parseCDPFrame(frame)
	if !ok {
		return "", "", false
	}
	return pkt.SourceMAC, formatCDP(pkt), true
}
