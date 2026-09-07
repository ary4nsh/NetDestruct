package smbvers

import (
	"crypto/rand"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

const enumTimeoutSecs = 10

var svTypeAbbrev = []struct {
	mask uint32
	abbr string
}{
	{0x00000001, "Wk"},
	{0x00000002, "Sv"},
	{0x00000004, "SQL"},
	{0x00000008, "DC"},
	{0x00000010, "BDC"},
	{0x00000020, "TS"},
	{0x00000040, "AFP"},
	{0x00000080, "Novell"},
	{0x00000100, "DMB"},
	{0x00000200, "PQS"},
	{0x00000400, "Dialin"},
	{0x00000800, "Xenix"},
	{0x00001000, "NT"},
	{0x00002000, "WFW"},
	{0x00004000, "MFPN"},
	{0x00008000, "SNT"},
	{0x00010000, "PtB"},
	{0x00020000, "BMB"},
	{0x00040000, "LMB"},
	{0x00080000, "DMB2"},
	{0x00400000, "Win95"},
	{0x02000000, "TS"},
	{0x04000000, "CLVS"},
	{0x40000000, "LLO"},
	{0x80000000, "ENUM"},
}

var osBuildRe = regexp.MustCompile(`(\d{4,5})\s*$`)

func printEnumSectionHeader(w io.Writer, title string, width int) {
	if width < len(title)+4 {
		width = len(title) + 4
	}
	line := strings.Repeat("=", width)
	pad := width - len(title) - 2
	left := pad / 2
	right := pad - left
	fmt.Fprintf(w, "\n %s\n", line)
	fmt.Fprintf(w, "|%s%s%s|\n", strings.Repeat(" ", left), title, strings.Repeat(" ", right))
	fmt.Fprintf(w, " %s\n", line)
}

func printEnumFail(w io.Writer, msg string) {
	fmt.Fprintf(w, "\x1b[31m[-]\x1b[0m %s\n", msg)
}

func randomEnumUsername() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func ntStatusString(code uint32) string {
	switch code {
	case stSuccess:
		return "STATUS_SUCCESS"
	case ntStatusLogonFailure:
		return "STATUS_LOGON_FAILURE"
	case 0xC0000022:
		return "STATUS_ACCESS_DENIED"
	case ntStatusAccountLockedOut:
		return "STATUS_ACCOUNT_LOCKED_OUT"
	default:
		return fmt.Sprintf("0x%08X", code)
	}
}

func decodeServerTypeString(flags uint32) string {
	var parts []string
	hasSv := flags&0x00000002 != 0
	for _, f := range svTypeAbbrev {
		if flags&f.mask == 0 {
			continue
		}
		if f.abbr == "Wk" && hasSv {
			continue
		}
		parts = append(parts, f.abbr)
	}
	return strings.Join(parts, " ")
}

func extractOSBuild(os string) string {
	if m := osBuildRe.FindStringSubmatch(strings.TrimSpace(os)); len(m) == 2 {
		return m[1]
	}
	return ""
}

type domainSMBView struct {
	NetBIOSComputer string
	NetBIOSDomain   string
	DNSDomain       string
	FQDN            string
	Membership      string
	DerivedDomain   string
}

func deriveDomainSMBView(os *smbOSDiscovery) domainSMBView {
	if os == nil {
		return domainSMBView{}
	}
	view := domainSMBView{
		NetBIOSComputer: os.NetBIOSComputer,
		NetBIOSDomain:   os.NetBIOSDomain,
		DNSDomain:       os.DomainName,
		FQDN:            os.FQDN,
	}
	if view.DNSDomain == "" {
		view.DNSDomain = firstNonEmpty(os.FQDN, os.NetBIOSComputer)
	}
	if view.FQDN == "" {
		view.FQDN = firstNonEmpty(os.DomainName, os.NetBIOSComputer)
	}

	if view.NetBIOSComputer != "" &&
		view.NetBIOSDomain != "" &&
		view.DNSDomain != "" &&
		view.FQDN != "" &&
		strings.Contains(view.FQDN, view.DNSDomain) &&
		strings.Contains(view.FQDN, ".") {
		view.Membership = "domain member"
		view.DerivedDomain = view.NetBIOSDomain
		return view
	}

	if view.NetBIOSDomain != "" &&
		view.NetBIOSComputer == "" &&
		view.FQDN == "" &&
		view.DNSDomain == "" {
		view.Membership = "workgroup member"
		view.DerivedDomain = view.NetBIOSDomain
		return view
	}

	if view.NetBIOSComputer != "" {
		view.Membership = "workgroup member"
		view.DerivedDomain = "unknown"
		if strings.EqualFold(view.NetBIOSDomain, view.NetBIOSComputer) ||
			strings.EqualFold(view.NetBIOSDomain, "WORKGROUP") {
			view.NetBIOSDomain = ""
		}
		if view.DNSDomain == "" {
			view.DNSDomain = view.NetBIOSComputer
		}
		if view.FQDN == "" {
			view.FQDN = view.NetBIOSComputer
		}
	}
	return view
}

func formatSessionProbeLine(p SessionProbe, pass string) string {
	switch p.Label {
	case "null":
		if p.Outcome == LoginSuccess || p.RPCOK {
			return "Could not establish null session: STATUS_SUCCESS"
		}
		return fmt.Sprintf("Could not establish null session: %s", ntStatusString(p.Status))
	case "guest":
		if p.Outcome == LoginSuccess || p.Outcome == LoginGuest {
			return "Could not establish guest session: STATUS_SUCCESS"
		}
		return fmt.Sprintf("Could not establish guest session: %s", ntStatusString(p.Status))
	case "password":
		if p.Outcome == LoginSuccess || p.Outcome == LoginGuest {
			return fmt.Sprintf("Server allows authentication via username '%s' and password '%s'", p.User, pass)
		}
		return fmt.Sprintf("Could not establish password session: %s", ntStatusString(p.Status))
	default:
		return p.Outcome.Message()
	}
}

func enumNullString(v string) string {
	if v == "" {
		return "(null)"
	}
	return v
}

func sortEnumGroups(groups []EnumGroup) {
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].RID < groups[j].RID
	})
}

func formatPrinterDescription(host, name, desc string) string {
	unc := formatPrinterName(host, name)
	if strings.HasPrefix(desc, `\\`) {
		return desc
	}
	if desc == "" {
		return unc + ","
	}
	if idx := strings.Index(desc, ","); idx >= 0 {
		return unc + "," + desc[idx+1:]
	}
	return unc + "," + desc + ","
}

func mergeOSInfo(smbOS *smbOSDiscovery, smb2 *smb2NegotiateResult, srv *ServerInfo) map[string]string {
	out := map[string]string{}
	if smbOS != nil {
		out["OS"] = firstNonEmpty(smbOS.OS, "")
		out["Native OS"] = smbOS.OS
		out["Native LAN manager"] = smbOS.LanManager
		if build := extractOSBuild(smbOS.OS); build != "" {
			out["OS build"] = build
		}
	}
	if smb2 != nil {
		if out["OS"] == "" {
			out["OS"] = smb2.OSVersion
		}
	}
	if srv != nil {
		out["OS version"] = fmt.Sprintf("%d.%d", srv.Major, srv.Minor)
		out["Platform id"] = fmt.Sprintf("%d", srv.PlatformID)
		out["Server type"] = fmt.Sprintf("0x%x", srv.Type)
		if srv.TypeString != "" {
			out["Server type string"] = srv.TypeString
		}
	}
	if out["OS release"] == "" {
		out["OS release"] = ""
	}
	return out
}
