package smbvers

import "io"

// Dialect and capability probing across SMBv1 and SMB 2.x/3.x.

var knownSMB2Dialects = []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}

type dialectProbe struct {
	Dialects     []string
	Capabilities map[string]uint32 // dialect label -> masked capability flags
}

func probeSMBDialects(host string, port int, maxDialect uint16) dialectProbe {
	out := dialectProbe{Capabilities: map[string]uint32{}}

	if probeSMB1Dialect(host, port) {
		out.Dialects = append(out.Dialects, "SMBv1")
	}

	for _, d := range knownSMB2Dialects {
		if maxDialect != 0 && d > maxDialect {
			break
		}
		res, err := negotiateSMB2(host, port, buildSMB2NegotiateSingle(d))
		if err != nil {
			continue
		}
		label := smbDialectLabel(d)
		out.Dialects = append(out.Dialects, label)
		out.Capabilities[label] = maskServerCapabilities(d, res.ServerCapabilities)
		if d == maxDialect {
			break
		}
	}
	return out
}

func probeSMB1Dialect(host string, port int) bool {
	conn, err := dial(host, port)
	if err != nil {
		return false
	}
	defer conn.Close()
	if port == portNBSS {
		if _, err := conn.Write(netbiosSessionRequest()); err != nil {
			return false
		}
		ack := make([]byte, 4)
		if _, err := io.ReadFull(conn, ack); err != nil || ack[0] != 0x82 {
			return false
		}
	}
	if err := netbiosWrite(conn, buildSMB1NegotiateNTLM012()); err != nil {
		return false
	}
	resp, err := netbiosRead(conn)
	if err != nil {
		return false
	}
	payload := smbPayload(resp)
	if len(payload) >= 5 && payload[0] == 0xfe {
		return false
	}
	return payload[0] == 0xff && payload[4] == 0x72
}
