package smbvers

import (
	"fmt"
	"io"
	"net"
	"time"
)

// RunSMBEnum performs SMB/RPC enumeration against one host.
// When user is non-empty, authenticated enumeration is used (optional pass may be empty for hash-less blank password tries).
func RunSMBEnum(host string, port int, user, pass, domain string, w io.Writer) error {
	if port <= 0 {
		port = portDirect
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid target IP %q", host)
	}

	timeout := time.Duration(enumTimeoutSecs) * time.Second

	printEnumSectionHeader(w, "Target Information", 26)
	printEnumInfo(w, fmt.Sprintf("Target ........... %s", host))
	if user != "" {
		printEnumInfo(w, fmt.Sprintf("Username ......... '%s'", user))
	} else {
		printEnumInfo(w, "Username ......... ''")
		// random name is only for unauthenticated/guest probing.
		printEnumInfo(w, fmt.Sprintf("Random Username .. '%s'", randomEnumUsername()))
	}
	if user != "" {
		printEnumInfo(w, fmt.Sprintf("Password ......... '%s'", pass))
	} else {
		printEnumInfo(w, "Password ......... ''")
	}
	printEnumInfo(w, fmt.Sprintf("Timeout .......... %d second(s)", enumTimeoutSecs))

	printEnumSectionHeader(w, fmt.Sprintf("Listener Scan on %s", host), 40)
	for _, lr := range scanListeners(host, timeout) {
		printEnumInfo(w, fmt.Sprintf("Checking %s", lr.Name))
		switch {
		case lr.Open:
			printEnumSuccess(w, fmt.Sprintf("%s is accessible on %d/tcp", lr.Name, lr.Port))
		case lr.Timeout:
			printEnumFail(w, fmt.Sprintf("Could not connect to %s on %d/tcp: timed out", lr.Name, lr.Port))
		default:
			printEnumFail(w, fmt.Sprintf("Could not connect to %s on %d/tcp", lr.Name, lr.Port))
		}
	}

	if err := CheckSMBPort(host, port); err != nil {
		return err
	}

	var nbns *nbnsResult
	printEnumSectionHeader(w, fmt.Sprintf("NetBIOS Names and Workgroup/Domain for %s", host), 62)
	if res, err := queryNBSTAT(host, timeout); err != nil {
		printEnumFail(w, fmt.Sprintf("Could not get NetBIOS names information: %v", err))
	} else {
		nbns = res
		if res.Workgroup != "" {
			printEnumSuccess(w, fmt.Sprintf("Got domain/workgroup name: %s", res.Workgroup))
		}
		printEnumSuccess(w, "Full NetBIOS names information:")
		for _, e := range res.Entries {
			fmt.Fprintf(w, "%s\n", formatNBNSEntryLine(e))
		}
		if res.MAC != "" {
			fmt.Fprintf(w, "- MAC Address = %s\n", res.MAC)
		}
	}

	printEnumSectionHeader(w, fmt.Sprintf("SMB Dialect Check on %s", host), 42)
	printEnumInfo(w, fmt.Sprintf("Trying on %d/tcp", port))
	dialects, err := probeEnumDialects(host, port)
	if err != nil {
		printEnumFail(w, err.Error())
	} else {
		printEnumSuccess(w, "Supported dialects and settings:")
		fmt.Fprintf(w, "Supported dialects:\n")
		for _, d := range enumDialectOrder {
			fmt.Fprintf(w, "  %s: %t\n", d.label, dialects.Supported[d.label])
		}
		fmt.Fprintf(w, "Preferred dialect: %s\n", dialects.Preferred)
		fmt.Fprintf(w, "SMB1 only: %t\n", dialects.SMB1Only)
		fmt.Fprintf(w, "SMB signing required: %t\n", dialects.SigningRequired)
	}

	res, _ := probeHost(ip, port)

	printEnumSectionHeader(w, fmt.Sprintf("Domain Information via SMB session for %s", host), 62)
	printEnumInfo(w, fmt.Sprintf("Enumerating via unauthenticated SMB session on %d/tcp", port))
	if res != nil && res.OS != nil {
		view := deriveDomainSMBView(res.OS)
		printEnumSuccess(w, "Found domain information via SMB")
		printEnumKV(w, "NetBIOS computer name", view.NetBIOSComputer)
		printEnumKV(w, "NetBIOS domain name", quoteEmpty(view.NetBIOSDomain))
		printEnumKV(w, "DNS domain", view.DNSDomain)
		printEnumKV(w, "FQDN", view.FQDN)
		if view.Membership != "" {
			printEnumKV(w, "Derived membership", view.Membership)
		}
		if view.DerivedDomain != "" {
			printEnumKV(w, "Derived domain", view.DerivedDomain)
		}
	} else {
		printEnumFail(w, "Could not enumerate domain information via unauthenticated SMB")
	}

	printEnumSectionHeader(w, fmt.Sprintf("RPC Session Check on %s", host), 42)
	probes := ProbeSessions(host, port, user, pass, domain)
	for _, p := range probes {
		switch p.Label {
		case "null":
			printEnumInfo(w, "Check for anonymous access (null session)")
			if p.Outcome == LoginSuccess {
				printEnumSuccess(w, "Server allows anonymous access")
			} else {
				printEnumFail(w, formatSessionProbeLine(p, pass))
			}
		case "password":
			printEnumInfo(w, "Check for password authentication")
			if p.Outcome == LoginSuccess || p.Outcome == LoginGuest {
				printEnumSuccess(w, formatSessionProbeLine(p, pass))
			} else {
				printEnumFail(w, formatSessionProbeLine(p, pass))
			}
		case "guest":
			printEnumInfo(w, "Check for guest access")
			if p.Outcome == LoginSuccess || p.Outcome == LoginGuest {
				printEnumSuccess(w, "Server allows guest access")
			} else {
				printEnumFail(w, formatSessionProbeLine(p, pass))
			}
		}
	}

	session, _, err := BestEnumSession(host, port, user, pass, domain)
	if err != nil {
		printEnumFail(w, fmt.Sprintf("Skipping RPC enumeration: %v", err))
		return nil
	}
	defer session.Close()

	rpcDomain := "WORKGROUP"
	rpcSID := "NULL SID"
	rpcMembership := "workgroup member"
	if nbns != nil && nbns.Workgroup != "" {
		rpcDomain = nbns.Workgroup
	} else if res != nil && res.OS != nil && res.OS.Workgroup != "" {
		rpcDomain = res.OS.Workgroup
	}
	if res != nil && res.OS != nil {
		view := deriveDomainSMBView(res.OS)
		if view.Membership == "domain member" && view.NetBIOSDomain != "" {
			rpcDomain = view.NetBIOSDomain
			rpcSID = "unknown"
			rpcMembership = "domain member"
		}
	}

	printEnumSectionHeader(w, fmt.Sprintf("Domain Information via RPC for %s", host), 54)
	printEnumSuccess(w, fmt.Sprintf("Domain: %s", rpcDomain))
	printEnumSuccess(w, fmt.Sprintf("Domain SID: %s", rpcSID))
	printEnumSuccess(w, fmt.Sprintf("Membership: %s", rpcMembership))

	var srvInfo *ServerInfo
	if info, err := QueryServerInfo(session); err == nil {
		srvInfo = info
	}

	printEnumSectionHeader(w, fmt.Sprintf("OS Information via RPC for %s", host), 50)
	printEnumInfo(w, fmt.Sprintf("Enumerating via unauthenticated SMB session on %d/tcp", port))
	if res != nil && res.OS != nil {
		printEnumSuccess(w, "Found OS information via SMB")
	}
	printEnumInfo(w, "Enumerating via 'srvinfo'")
	if srvInfo != nil {
		printEnumSuccess(w, "Found OS information via 'srvinfo'")
	}
	printEnumSuccess(w, "After merging OS information we have the following result:")
	merged := mergeOSInfo(nil, nil, srvInfo)
	if res != nil {
		merged = mergeOSInfo(res.OS, res.SMB2, srvInfo)
	}
	printEnumKV(w, "OS", merged["OS"])
	printEnumKV(w, "OS version", quoteSingle(merged["OS version"]))
	printEnumKV(w, "OS release", quoteEmpty(merged["OS release"]))
	printEnumKV(w, "OS build", quoteSingle(merged["OS build"]))
	printEnumKV(w, "Native OS", merged["Native OS"])
	printEnumKV(w, "Native LAN manager", merged["Native LAN manager"])
	printEnumKV(w, "Platform id", quoteSingle(merged["Platform id"]))
	if merged["Server type"] != "" {
		printEnumKV(w, "Server type", "'"+merged["Server type"]+"'")
	}
	if merged["Server type string"] != "" {
		printEnumKV(w, "Server type string", merged["Server type string"])
	}

	printEnumBanner(w, "Users via RPC on", host)
	printEnumInfo(w, "Enumerating users via 'querydispinfo'")
	users, err := EnumerateSAMUsers(session)
	if err != nil {
		printEnumFail(w, fmt.Sprintf("User enum failed: %v", err))
	} else {
		printEnumSuccess(w, fmt.Sprintf("Found %d user(s) via 'querydispinfo'", len(users)))
		printEnumInfo(w, "Enumerating users via 'enumdomusers'")
		printEnumSuccess(w, fmt.Sprintf("Found %d user(s) via 'enumdomusers'", len(users)))
		printEnumSuccess(w, fmt.Sprintf("After merging user results we have %d user(s) total:", len(users)))
		for _, u := range users {
			fmt.Fprintf(w, "'%d':\n", u.RID)
			fmt.Fprintf(w, "  username: %s\n", u.Name)
			fmt.Fprintf(w, "  name: %s\n", enumNullString(u.FullName))
			fmt.Fprintf(w, "  acb: '0x%08x'\n", u.ACB)
			fmt.Fprintf(w, "  description: %s\n", enumNullString(u.Description))
		}
	}

	printEnumBanner(w, "Groups via RPC on", host)
	printEnumInfo(w, "Enumerating local groups")
	printEnumInfo(w, "Enumerating builtin groups")
	printEnumInfo(w, "Enumerating domain groups")
	groups, err := EnumerateSAMGroups(session)
	if err != nil {
		printEnumFail(w, fmt.Sprintf("Group enum failed: %v", err))
	} else {
		builtinCount := 0
		domainCount := 0
		for _, g := range groups {
			if g.Type == "builtin" {
				builtinCount++
			} else {
				domainCount++
			}
		}
		printEnumSuccess(w, fmt.Sprintf("Found %d group(s) via 'enumalsgroups domain'", domainCount))
		printEnumSuccess(w, fmt.Sprintf("Found %d group(s) via 'enumalsgroups builtin'", builtinCount))
		printEnumSuccess(w, fmt.Sprintf("Found %d group(s) via 'enumdomgroups'", domainCount))
		printEnumSuccess(w, fmt.Sprintf("After merging groups results we have %d group(s) total:", len(groups)))
		for _, g := range groups {
			fmt.Fprintf(w, "'%d':\n", g.RID)
			fmt.Fprintf(w, "  groupname: %s\n", g.Name)
			fmt.Fprintf(w, "  type: %s\n", g.Type)
		}
	}

	userRPC, passRPC, domainRPC := session.Credentials()
	hostRPC, portRPC := session.HostPort()

	printEnumBanner(w, "Shares via RPC on", host)
	printEnumInfo(w, "Enumerating shares")
	shares, err := EnumerateShares(session)
	if err != nil {
		printEnumFail(w, fmt.Sprintf("Share enum failed: %v", err))
	} else if len(shares) == 0 {
		printEnumSuccess(w, "Found 0 share(s)")
	} else {
		printEnumSuccess(w, fmt.Sprintf("Found %d share(s):", len(shares)))
		for _, sh := range shares {
			fmt.Fprintf(w, "%s:\n", sh.Name)
			fmt.Fprintf(w, "  comment: %s\n", sh.Comment)
			fmt.Fprintf(w, "  type: %s\n", sh.Type)
		}
		for _, sh := range shares {
			printEnumInfo(w, fmt.Sprintf("Testing share %s", sh.Name))
			access := TestShareAccess(hostRPC, portRPC, userRPC, passRPC, domainRPC, sh.Name, sh.Type)
			printEnumSuccess(w, formatShareAccessResult(access))
		}
	}

	printEnumBanner(w, "Policies via RPC for", host)
	printEnumInfo(w, fmt.Sprintf("Trying port %d/tcp", port))
	if pol, err := QueryPasswordPolicy(session); err != nil {
		printEnumFail(w, fmt.Sprintf("Password policy: %v", err))
	} else {
		printEnumSuccess(w, "Found policy:")
		printPasswordPolicy(w, pol)
	}

	printEnumBanner(w, "Printers via RPC for", host)
	if printers, err := EnumeratePrinters(session); err != nil {
		printEnumFail(w, fmt.Sprintf("Printer enum failed: %v", err))
	} else if len(printers) == 0 {
		printEnumSuccess(w, "No printers returned")
	} else {
		printEnumSuccess(w, fmt.Sprintf("Found %d printer(s):", len(printers)))
		for _, p := range printers {
			displayName := formatPrinterName(host, p.Name)
			fmt.Fprintf(w, "%s:\n", displayName)
			fmt.Fprintf(w, "  description: %s\n", formatPrinterDescription(host, p.Name, p.Description))
			fmt.Fprintf(w, "  comment: %s\n", quoteEnumValue(p.Comment))
			fmt.Fprintf(w, "  flags: '%s'\n", fmt.Sprintf("0x%x", p.Flags))
		}
	}

	return nil
}

func printEnumKV(w io.Writer, key, val string) {
	fmt.Fprintf(w, "%-30s%s\n", key+":", val)
}

func printKV(w io.Writer, key, val string) {
	if val == "" {
		return
	}
	fmt.Fprintf(w, "  %-28s %s\n", key+":", val)
}

func quoteEmpty(v string) string {
	if v == "" {
		return "''"
	}
	return v
}

func quoteSingle(v string) string {
	if v == "" {
		return "''"
	}
	return "'" + v + "'"
}

func quoteEnumValue(v string) string {
	if v == "" {
		return "''"
	}
	return v
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
