package dtpenum

// FormattedDTP holds decoded DTP output for display.
type FormattedDTP struct {
	SourceMAC string
	Body      string
}

// TryFormat decodes a DTP frame for display.
func TryFormat(frame []byte) (FormattedDTP, bool) {
	pkt, ok := parseDTPFrame(frame)
	if !ok {
		return FormattedDTP{}, false
	}
	return FormattedDTP{
		SourceMAC: pkt.SourceMAC,
		Body:      formatDTP(pkt),
	}, true
}
