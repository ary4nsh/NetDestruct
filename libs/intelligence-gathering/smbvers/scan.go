package smbvers

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const smbTag = "\x1b[33m[SMB]\x1b[0m"

// Scanner fingerprints SMB protocol versions on remote hosts.
type Scanner struct {
	Target string
	Port   int // TCP port (default 445 when zero)
}

func (s *Scanner) Run() error {
	if strings.TrimSpace(s.Target) == "" {
		return fmt.Errorf("--smb --version requires --target <ip|range>")
	}
	targets, err := expandTargets(s.Target)
	if err != nil {
		return err
	}

	fmt.Printf("%s Scanning %d target(s) for SMB version...\n", smbTag, len(targets))
	port := s.Port
	if port <= 0 {
		port = portDirect
	}
	for _, ip := range targets {
		if ip.To4() == nil {
			fmt.Printf("%s %s SMB scan skipped (IPv6 not supported yet)\n", smbTag, ip)
			continue
		}
		res, ok := probeHost(ip, port)
		if !ok {
			fmt.Printf("%s %s no SMB service (port %d closed or filtered)\n", smbTag, ip, port)
			continue
		}
		printResult(ip, res)
	}
	return nil
}

func signingMode(required, enabled bool) string {
	if required {
		return "Required"
	}
	if enabled {
		return "Enabled"
	}
	return "Disabled"
}

func printResult(ip net.IP, res *hostScanResult) {
	host := ip.String()
	s2, s1 := res.SMB2, res.SMB1
	port := res.Port

	versions := []int{}
	if s1 != nil && (s1.NativeOS != "" || s1.NativeLM != "") {
		versions = append(versions, 1)
	}
	if res.OS != nil && (res.OS.OS != "" || res.OS.LanManager != "") {
		versions = mergeVersions(versions, []int{1})
	}
	if len(res.Probe.Dialects) > 0 {
		for _, d := range res.Probe.Dialects {
			if strings.Contains(d, "SMBv1") {
				versions = mergeVersions(versions, []int{1})
			}
		}
	}
	if s2 != nil {
		versions = mergeVersions(versions, s2.Versions)
	}
	if len(versions) == 0 && s2 != nil {
		versions = s2.Versions
	}

	fmt.Printf("%s SMB Detected on %s:%d:\n", smbTag, host, port)
	printDetail("Versions", formatVersionList(versions))

	if s2 != nil && s2.DialectName != "" {
		printDetail("Preferred dialect", s2.DialectName)
	}
	if s2 != nil {
		mode := signingMode(s2.SigningRequired, s2.SigningEnabled)
		printDetail("Signatures", mode)
	}

	printOSDiscoverySummary(s1, res.OS)

	if res.OS != nil && res.OS.SystemTime != "" {
		printDetail("System time", res.OS.SystemTime)
	} else if s2 != nil && s2.SystemTime != "" {
		printDetail("System time", s2.SystemTime)
	}
	if res.OS != nil && res.OS.AuthDomain != "" {
		printDetail("Authentication domain", res.OS.AuthDomain)
	} else if s2 != nil && s2.AuthDomain != "" {
		printDetail("Authentication domain", s2.AuthDomain)
	}

	if s2 != nil && s2.ServerGUID != "" {
		printDetail("Server GUID", s2.ServerGUID)
	}
	if s2 != nil {
		printDetail("SMB Signing", signingMode(s2.SigningRequired, s2.SigningEnabled))
	}

	fmt.Println()
	printSMBProtocols(res.Probe)
	fmt.Println()
	printSMBCapabilities(res.Probe)
	fmt.Println()
	printSMB2PreauthCapabilities(res.SMB2)
	fmt.Println()
	printSMB2EncryptionCapabilities(res.SMB2)
	fmt.Println()
	printSMB2SigningCapabilities(res.SMB2)
	fmt.Println()
	printSMB2CompressionCapabilities(res.SMB2)
	fmt.Println()
	printOSDiscoveryDetails(s1, res.OS)
}

func printOSDiscoverySummary(s1 *smb1NegotiateResult, os *smbOSDiscovery) {
	if os != nil && looksLikeOSString(os.OS) {
		printDetail("Host is running", formatOSDiscoveryLine(os))
		return
	}
	if os != nil && looksLikeOSString(os.LanManager) {
		printDetail("Host is running", os.LanManager)
		return
	}
	if s1 != nil && (looksLikeOSString(s1.NativeOS) || looksLikeOSString(s1.NativeLM)) {
		osLine := formatOSDiscoveryLine(&smbOSDiscovery{OS: s1.NativeOS, LanManager: s1.NativeLM})
		if osLine != "" && osLine != "Unknown" {
			printDetail("Host is running", osLine)
			return
		}
	}
	printDetail("Host OS", "could not be identified via SMB1")
}

func printSMBProtocols(n dialectProbe) {
	fmt.Println("SMB Protocols:")
	if len(n.Dialects) == 0 {
		fmt.Println("- (no dialects accepted)")
		return
	}
	for _, d := range n.Dialects {
		fmt.Printf("- %s\n", d)
	}
}

func printSMBCapabilities(n dialectProbe) {
	fmt.Println("SMB2 Capabilities:")
	if len(n.Capabilities) == 0 {
		fmt.Println("- (SMB 2+ not probed)")
		return
	}
	for _, d := range knownSMB2Dialects {
		label := smbDialectLabel(d)
		capFlags, ok := n.Capabilities[label]
		if !ok {
			continue
		}
		fmt.Printf("- %s:\n", label)
		for _, name := range supportedCapabilityNames(capFlags) {
			fmt.Printf("  - %s\n", name)
		}
	}
}

func printSMB2PreauthCapabilities(s2 *smb2NegotiateResult) {
	fmt.Println("SMB2 PREAUTH Capabilities:")
	if s2 == nil || (len(s2.PreauthHashAlgs) == 0 && s2.PreauthSaltHex == "") {
		fmt.Println("- (not returned)")
		return
	}
	for _, h := range s2.PreauthHashAlgs {
		printSubDetail("Hash Algorithm", h)
	}
	if s2.PreauthSaltHex != "" {
		printSubDetail("Salt", s2.PreauthSaltHex)
	}
}

func printSMB2EncryptionCapabilities(s2 *smb2NegotiateResult) {
	fmt.Println("SMB2 Encryption Capabilities:")
	if s2 == nil || len(s2.EncryptionAlgos) == 0 {
		fmt.Println("- (not returned)")
		return
	}
	for _, c := range s2.EncryptionAlgos {
		fmt.Printf("- %s\n", c)
	}
}

func printSMB2SigningCapabilities(s2 *smb2NegotiateResult) {
	fmt.Println("SMB2 Signing Capabilities:")
	if s2 == nil || len(s2.SigningAlgos) == 0 {
		fmt.Println("- (not returned)")
		return
	}
	for _, c := range s2.SigningAlgos {
		fmt.Printf("- %s\n", c)
	}
}

func printSMB2CompressionCapabilities(s2 *smb2NegotiateResult) {
	fmt.Println("SMB2 Compression Capabilities:")
	if s2 == nil || len(s2.CompressionAlgos) == 0 {
		fmt.Println("- (not returned)")
		return
	}
	for _, c := range s2.CompressionAlgos {
		fmt.Printf("- %s\n", c)
	}
}

func printOSDiscoveryDetails(s1 *smb1NegotiateResult, os *smbOSDiscovery) {
	fmt.Println("SMB OS Discovery:")
	if os == nil && (s1 == nil || (s1.NativeOS == "" && s1.NativeLM == "")) {
		fmt.Println("- (no OS details returned)")
		return
	}
	if os == nil {
		os = &smbOSDiscovery{OS: s1.NativeOS, LanManager: s1.NativeLM}
		os.CPE = makeOSCPE(os.OS)
	}
	printSubDetail("OS", formatOSDiscoveryLine(os))
	if os.CPE != "" {
		printSubDetail("OS CPE", os.CPE)
	}
	if os.ComputerName != "" {
		printSubDetail("Computer name", os.ComputerName)
	}
	if os.NetBIOSComputer != "" {
		printSubDetail("NetBIOS computer name", os.NetBIOSComputer)
	}
	if os.AuthDomain != "" {
		printSubDetail("Authentication domain", os.AuthDomain)
	}
	if os.DomainName != "" {
		printSubDetail("Domain name", os.DomainName)
	}
	if os.ForestName != "" {
		printSubDetail("Forest name", os.ForestName)
	}
	if os.FQDN != "" {
		printSubDetail("FQDN", os.FQDN)
	}
	if os.NetBIOSDomain != "" && os.DomainName != "" {
		printSubDetail("NetBIOS domain name", os.NetBIOSDomain)
	}
	if os.Workgroup != "" {
		printSubDetail("Workgroup", os.Workgroup)
	}
	if os.SystemTime != "" {
		printSubDetail("System time", formatDiscoveryTime(os.SystemTime))
	} else {
		printSubDetail("System time", "Unknown")
	}
}

func formatDiscoveryTime(s string) string {
	if i := strings.IndexByte(s, 'T'); i > 0 {
		return s[:i] + " " + s[i+1:]
	}
	return s
}

func printSubDetail(label, value string) {
	fmt.Printf("- %s: %s\n", label, value)
}

func printDetail(label, value string) {
	fmt.Printf("- %s: %s\n", label, value)
}

func mergeVersions(base, extra []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, v := range append(base, extra...) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func formatVersionList(v []int) string {
	if len(v) == 0 {
		return "unknown"
	}
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}
