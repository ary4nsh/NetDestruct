package smbvers

import (
	"fmt"
)

type enumDialectReport struct {
	Supported         map[string]bool
	Preferred         string
	SMB1Only          bool
	SigningRequired   bool
	PreferredSigning  bool
}

var enumDialectOrder = []struct {
	label   string
	dialect uint16
	smb1    bool
}{
	{"SMB 1.0", 0, true},
	{"SMB 2.0.2", 0x0202, false},
	{"SMB 2.1", 0x0210, false},
	{"SMB 3.0", 0x0300, false},
	{"SMB 3.1.1", 0x0311, false},
}

func probeEnumDialects(host string, port int) (*enumDialectReport, error) {
	report := &enumDialectReport{Supported: map[string]bool{}}
	var lastSupported uint16
	var lastIsSMB1 bool
	supportedCount := 0

	for _, d := range enumDialectOrder {
		ok := false
		if d.smb1 {
			ok = probeSMB1Dialect(host, port)
		} else {
			res, err := negotiateSMB2(host, port, buildSMB2NegotiateSingle(d.dialect))
			ok = err == nil && res != nil
			if ok && lastSupported == 0 {
				lastSupported = d.dialect
				lastIsSMB1 = false
			}
		}
		report.Supported[d.label] = ok
		if ok {
			supportedCount++
			if d.smb1 {
				lastSupported = 0xffff
				lastIsSMB1 = true
			} else {
				lastSupported = d.dialect
				lastIsSMB1 = false
			}
		}
	}

	if supportedCount == 0 {
		return nil, fmt.Errorf("no supported dialects")
	}
	if supportedCount == 1 {
		if lastIsSMB1 {
			report.Preferred = "SMB 1.0"
			report.SMB1Only = true
		} else {
			report.Preferred = dialectLabel(lastSupported)
		}
	} else {
		// default negotiate (no forced dialect) → often SMB 3.0.
		preferred, err := negotiateSMB2(host, port, buildSMB2NegotiatePreferred)
		if err != nil || preferred == nil {
			report.Preferred = dialectLabel(lastSupported)
		} else {
			report.Preferred = preferred.DialectName
			report.PreferredSigning = preferred.SigningEnabled
			report.SigningRequired = preferred.SigningRequired
		}
	}
	if report.Preferred == "" {
		report.Preferred = dialectLabel(lastSupported)
	}
	if report.SigningRequired == false && !report.PreferredSigning {
		if res, err := negotiateSMB2(host, port, buildSMB2NegotiatePreferred); err == nil && res != nil {
			report.SigningRequired = res.SigningRequired
			report.PreferredSigning = res.SigningEnabled
		}
	}
	return report, nil
}

func buildSMB2NegotiatePreferred() []byte {
	dialects := []uint16{0x0202, 0x0210, 0x0300}
	return buildSMB2NegotiateWithDialects(dialects, false)
}
