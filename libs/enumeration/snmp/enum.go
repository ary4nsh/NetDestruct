package snmp

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Enumerator performs host enumeration.
type Enumerator struct {
	Target    string
	Port      int
	Community string
	Timeout   time.Duration
	Out       io.Writer
}

var (
	oidSysName     = []int{1, 3, 6, 1, 2, 1, 1, 5, 0}
	oidSysDescr    = []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidSysContact  = []int{1, 3, 6, 1, 2, 1, 1, 4, 0}
	oidSysLocation = []int{1, 3, 6, 1, 2, 1, 1, 6, 0}
	oidSysUpTime   = []int{1, 3, 6, 1, 2, 1, 1, 3, 0}
	oidHRUpTime    = []int{1, 3, 6, 1, 2, 1, 25, 1, 1, 0}
	oidHRDate      = []int{1, 3, 6, 1, 2, 1, 25, 1, 2, 0}
	oidWinDomain  = []int{1, 3, 6, 1, 4, 1, 77, 1, 4, 1, 0}
	oidWinUserTbl = []int{1, 3, 6, 1, 4, 1, 77, 1, 2, 25}
	oidIPForward   = []int{1, 3, 6, 1, 2, 1, 4, 1, 0}
	oidIPDefTTL    = []int{1, 3, 6, 1, 2, 1, 4, 2, 0}
	oidTCPInSegs   = []int{1, 3, 6, 1, 2, 1, 6, 10, 0}
	oidTCPOutSegs  = []int{1, 3, 6, 1, 2, 1, 6, 11, 0}
	oidTCPRetrans  = []int{1, 3, 6, 1, 2, 1, 6, 12, 0}
	oidIPInRecv    = []int{1, 3, 6, 1, 2, 1, 4, 3, 0}
	oidIPInDeliv   = []int{1, 3, 6, 1, 2, 1, 4, 9, 0}
	oidIPOutReq    = []int{1, 3, 6, 1, 2, 1, 4, 10, 0}
)

// Run collects system, network, and host-resource information via SNMPv2c.
func (e *Enumerator) Run() error {
	host := strings.TrimSpace(e.Target)
	community := strings.TrimSpace(e.Community)
	if host == "" {
		return fmt.Errorf("--snmp --enum requires --target <ip>")
	}
	if community == "" {
		return fmt.Errorf("--snmp --enum requires --community <string>")
	}

	port := e.Port
	if port <= 0 {
		port = defaultPort
	}
	out := e.Out
	if out == nil {
		out = os.Stdout
	}

	sess, ip, err := dialSession(host, port, community, e.Timeout)
	if err != nil {
		return err
	}
	defer sess.Close()

	if _, err := sess.Get(oidSysName); err != nil {
		return fmt.Errorf("snmp request failed: %w", err)
	}

	fmt.Fprintf(out, "%s %s, Connected.\n", snmpTag, ip)

	fmt.Fprintf(out, "\n%s === System information ===\n", snmpTag)
	printField(out, "Host IP", ip.String())
	printField(out, "Hostname", dashIfEmpty(sess.getString(oidSysName)))

	sysDescr := strings.Join(strings.Fields(strings.ReplaceAll(sess.getString(oidSysDescr), "\r\n", " ")), " ")
	printField(out, "Description", dashIfEmpty(sysDescr))
	printField(out, "Contact", dashIfEmpty(sess.getString(oidSysContact)))
	printField(out, "Location", dashIfEmpty(sess.getString(oidSysLocation)))
	printField(out, "Uptime system", dashIfEmpty(sess.getString(oidSysUpTime)))

	hrUp := sess.getString(oidHRUpTime)
	if isNullish(hrUp) {
		hrUp = "-"
	}
	printField(out, "Uptime snmp", hrUp)

	if vb := sess.getValue(oidHRDate); vb != nil && vb.Tag == 0x04 && len(vb.Data) >= 8 {
		printField(out, "System date", formatDateAndTime(vb.Data))
	} else {
		printField(out, "System date", "-")
	}

	isWindows := strings.Contains(sysDescr, "Windows")

	if isWindows {
		printField(out, "Domain", dashIfEmpty(sess.getString(oidWinDomain)))
		e.printWindowsUsers(sess, out)
	}

	e.printNetworkInfo(sess, out)
	e.printInterfaces(sess, out)
	e.printNetworkIP(sess, out)
	e.printRouting(sess, out)
	e.printTCP(sess, out)
	e.printUDP(sess, out)

	if isWindows {
		e.printWindowsServices(sess, out)
		e.printWindowsShares(sess, out)
		e.printIIS(sess, out)
	}

	e.printStorage(sess, out)
	e.printFileSystem(sess, out)
	e.printDevices(sess, out)
	e.printSoftware(sess, out)
	e.printProcesses(sess, out)

	fmt.Fprintln(out)
	return nil
}

func printField(out io.Writer, name, value string) {
	fmt.Fprintf(out, "%s   %-28s : %s\n", snmpTag, name, value)
}

func printSection(out io.Writer, title string) {
	fmt.Fprintf(out, "\n%s === %s ===\n", snmpTag, title)
}

func (e *Enumerator) printWindowsUsers(sess *Session, out io.Writer) {
	users, err := collectWindowsUsers(sess)
	if err != nil || len(users) == 0 {
		return
	}
	printSection(out, "User accounts")
	fmt.Fprintf(out, "%s   Found %d user(s):\n", snmpTag, len(users))
	for _, u := range users {
		fmt.Fprintf(out, "%s   - %s\n", snmpTag, u)
	}
}

// collectWindowsUsers walks lmUserTable (1.3.6.1.4.1.77.1.2.25) and collects non-empty string varbinds from the subtree.
func collectWindowsUsers(sess *Session) ([]string, error) {
	vbs, err := sess.Walk(oidWinUserTbl)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var users []string
	for _, vb := range vbs {
		if !oidHasPrefix(vb.OID, oidWinUserTbl) {
			continue
		}
		if vb.Tag != 0x04 {
			continue
		}
		name := strings.TrimSpace(string(vb.Data))
		if name == "" || isNullish(name) || seen[name] {
			continue
		}
		seen[name] = true
		users = append(users, name)
	}
	sort.Strings(users)
	return users, nil
}

func (e *Enumerator) printNetworkInfo(sess *Session, out io.Writer) {
	info := map[string]string{}
	if v := ipForwardingText(sess.getValue(oidIPForward)); v != "" {
		info["IP forwarding enabled"] = v
	}
	if v := sess.getString(oidIPDefTTL); !isNullish(v) {
		info["Default TTL"] = v
	}
	if v := sess.getString(oidTCPInSegs); !isNullish(v) {
		info["TCP segments received"] = v
	}
	if v := sess.getString(oidTCPOutSegs); !isNullish(v) {
		info["TCP segments sent"] = v
	}
	if v := sess.getString(oidTCPRetrans); !isNullish(v) {
		info["TCP segments retrans"] = v
	}
	if v := sess.getString(oidIPInRecv); !isNullish(v) {
		info["Input datagrams"] = v
	}
	if v := sess.getString(oidIPInDeliv); !isNullish(v) {
		info["Delivered datagrams"] = v
	}
	if v := sess.getString(oidIPOutReq); !isNullish(v) {
		info["Output datagrams"] = v
	}
	if len(info) == 0 {
		return
	}
	printSection(out, "Network information")
	keys := make([]string, 0, len(info))
	for k := range info {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		printField(out, k, info[k])
	}
}

func (e *Enumerator) printInterfaces(sess *Session, out io.Writer) {
	roots := [][]int{
		{1, 3, 6, 1, 2, 1, 2, 2, 1, 1},
		{1, 3, 6, 1, 2, 1, 2, 2, 1, 2},
		{1, 3, 6, 1, 2, 1, 2, 2, 1, 6},
		{1, 3, 6, 1, 2, 1, 2, 2, 1, 3},
		{1, 3, 6, 1, 2, 1, 2, 2, 1, 4},
		{1, 3, 6, 1, 2, 1, 2, 2, 1, 5},
		{1, 3, 6, 1, 2, 1, 2, 2, 1, 10},
		{1, 3, 6, 1, 2, 1, 2, 2, 1, 16},
		{1, 3, 6, 1, 2, 1, 2, 2, 1, 7},
	}
	table, err := walkTable(sess, roots)
	if err != nil || len(table) == 0 {
		return
	}

	macRaw := map[int]string{}
	if vbs, err := sess.Walk(roots[2]); err == nil {
		for _, vb := range vbs {
			if oidHasPrefix(vb.OID, roots[2]) {
				macRaw[oidIndex(vb.OID)] = formatMAC(vb.Data)
			}
		}
	}

	printSection(out, "Network interfaces")
	for _, idx := range sortedIndexes(table) {
		row := table[idx]
		for len(row) < 9 {
			row = append(row, "")
		}
		iface := fmt.Sprintf("[ %s ] %s", mapIfStatus(row[8]), row[1])
		fmt.Fprintf(out, "%s   Interface                  : %s\n", snmpTag, iface)
		fmt.Fprintf(out, "%s   Id                         : %s\n", snmpTag, dashIfEmpty(row[0]))
		mac := macRaw[idx]
		if mac == "" {
			mac = "unknown"
		}
		fmt.Fprintf(out, "%s   Mac Address                : %s\n", snmpTag, mac)
		fmt.Fprintf(out, "%s   Type                       : %s\n", snmpTag, mapIfType(row[3]))
		fmt.Fprintf(out, "%s   Speed                      : %s\n", snmpTag, ifaceSpeedMbps(row[5]))
		fmt.Fprintf(out, "%s   MTU                        : %s\n", snmpTag, dashIfEmpty(row[4]))
		fmt.Fprintf(out, "%s   In octets                  : %s\n", snmpTag, dashIfEmpty(row[6]))
		fmt.Fprintf(out, "%s   Out octets                 : %s\n", snmpTag, dashIfEmpty(row[7]))
		fmt.Fprintln(out)
	}
}

func (e *Enumerator) printNetworkIP(sess *Session, out io.Writer) {
	roots := [][]int{
		{1, 3, 6, 1, 2, 1, 4, 20, 1, 2},
		{1, 3, 6, 1, 2, 1, 4, 20, 1, 1},
		{1, 3, 6, 1, 2, 1, 4, 20, 1, 3},
		{1, 3, 6, 1, 2, 1, 4, 20, 1, 4},
	}
	table, err := walkTable(sess, roots)
	if err != nil || len(table) == 0 {
		return
	}
	printSection(out, "Network IP")
	fmt.Fprintf(out, "%s   %-6s %-16s %-16s %-16s\n", snmpTag, "Id", "IP Address", "Netmask", "Broadcast")
	for _, idx := range sortedIndexes(table) {
		row := table[idx]
		for len(row) < 4 {
			row = append(row, "-")
		}
		fmt.Fprintf(out, "%s   %-6s %-16s %-16s %-16s\n", snmpTag, row[0], row[1], row[2], row[3])
	}
}

func (e *Enumerator) printRouting(sess *Session, out io.Writer) {
	roots := [][]int{
		{1, 3, 6, 1, 2, 1, 4, 21, 1, 1},
		{1, 3, 6, 1, 2, 1, 4, 21, 1, 7},
		{1, 3, 6, 1, 2, 1, 4, 21, 1, 11},
		{1, 3, 6, 1, 2, 1, 4, 21, 1, 3},
	}
	table, err := walkTable(sess, roots)
	if err != nil || len(table) == 0 {
		return
	}
	printSection(out, "Routing information")
	fmt.Fprintf(out, "%s   %-16s %-16s %-16s %-8s\n", snmpTag, "Destination", "Next Hop", "Mask", "Metric")
	for _, idx := range sortedIndexes(table) {
		row := table[idx]
		for len(row) < 4 {
			row = append(row, "-")
		}
		metric := row[3]
		if isNullish(metric) {
			metric = "-"
		}
		fmt.Fprintf(out, "%s   %-16s %-16s %-16s %-8s\n", snmpTag, row[0], row[1], row[2], metric)
	}
}

func (e *Enumerator) printTCP(sess *Session, out io.Writer) {
	roots := [][]int{
		{1, 3, 6, 1, 2, 1, 6, 13, 1, 2},
		{1, 3, 6, 1, 2, 1, 6, 13, 1, 3},
		{1, 3, 6, 1, 2, 1, 6, 13, 1, 4},
		{1, 3, 6, 1, 2, 1, 6, 13, 1, 5},
		{1, 3, 6, 1, 2, 1, 6, 13, 1, 1},
	}
	table, err := walkTable(sess, roots)
	if err != nil || len(table) == 0 {
		return
	}
	printSection(out, "TCP connections and listening ports")
	fmt.Fprintf(out, "%s   %-16s %-8s %-16s %-8s %-12s\n", snmpTag, "Local address", "Local port", "Remote address", "Remote port", "State")
	for _, idx := range sortedIndexes(table) {
		row := table[idx]
		for len(row) < 5 {
			row = append(row, "-")
		}
		laddr, lport, raddr, rport := row[0], row[1], row[2], row[3]
		if isNullish(laddr) {
			laddr = "-"
		}
		if isNullish(lport) {
			lport = "-"
		}
		if isNullish(raddr) {
			raddr = "-"
		}
		if isNullish(rport) {
			rport = "-"
		}
		fmt.Fprintf(out, "%s   %-16s %-8s %-16s %-8s %-12s\n", snmpTag, laddr, lport, raddr, rport, mapTCPState(row[4]))
	}
}

func (e *Enumerator) printUDP(sess *Session, out io.Writer) {
	roots := [][]int{
		{1, 3, 6, 1, 2, 1, 7, 5, 1, 1},
		{1, 3, 6, 1, 2, 1, 7, 5, 1, 2},
	}
	table, err := walkTable(sess, roots)
	if err != nil || len(table) == 0 {
		return
	}
	printSection(out, "Listening UDP ports")
	fmt.Fprintf(out, "%s   %-16s %-8s\n", snmpTag, "Local address", "Local port")
	for _, idx := range sortedIndexes(table) {
		row := table[idx]
		for len(row) < 2 {
			row = append(row, "-")
		}
		fmt.Fprintf(out, "%s   %-16s %-8s\n", snmpTag, dashIfEmpty(row[0]), dashIfEmpty(row[1]))
	}
}

func (e *Enumerator) printWindowsServices(sess *Session, out io.Writer) {
	roots := [][]int{
		{1, 3, 6, 1, 4, 1, 77, 1, 2, 3, 1, 1},
		{1, 3, 6, 1, 4, 1, 77, 1, 2, 3, 1, 2},
	}
	table, err := walkTable(sess, roots)
	if err != nil || len(table) == 0 {
		return
	}
	printSection(out, "Network services")
	fmt.Fprintf(out, "%s   %-8s %s\n", snmpTag, "Index", "Name")
	n := 0
	for _, idx := range sortedIndexes(table) {
		row := table[idx]
		if len(row) == 0 || isNullish(row[0]) {
			continue
		}
		fmt.Fprintf(out, "%s   %-8d %s\n", snmpTag, n, row[0])
		n++
	}
}

func (e *Enumerator) printWindowsShares(sess *Session, out io.Writer) {
	roots := [][]int{
		{1, 3, 6, 1, 4, 1, 77, 1, 2, 27, 1, 1},
		{1, 3, 6, 1, 4, 1, 77, 1, 2, 27, 1, 2},
		{1, 3, 6, 1, 4, 1, 77, 1, 2, 27, 1, 3},
	}
	table, err := walkTable(sess, roots)
	if err != nil || len(table) == 0 {
		return
	}
	printSection(out, "Share")
	for _, idx := range sortedIndexes(table) {
		row := table[idx]
		for len(row) < 3 {
			row = append(row, "")
		}
		fmt.Fprintf(out, "%s    Name                       : %s\n", snmpTag, row[0])
		fmt.Fprintf(out, "%s     Path                      : %s\n", snmpTag, row[1])
		fmt.Fprintf(out, "%s     Comment                   : %s\n", snmpTag, row[2])
		fmt.Fprintln(out)
	}
}

func (e *Enumerator) printIIS(sess *Session, out io.Writer) {
	oids := map[string][]int{
		"TotalBytesSentLowWord":        {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 2, 0},
		"TotalBytesReceivedLowWord":    {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 4, 0},
		"TotalFilesSent":               {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 5, 0},
		"CurrentAnonymousUsers":        {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 6, 0},
		"CurrentNonAnonymousUsers":     {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 7, 0},
		"TotalAnonymousUsers":          {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 8, 0},
		"TotalNonAnonymousUsers":       {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 9, 0},
		"MaxAnonymousUsers":            {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 10, 0},
		"MaxNonAnonymousUsers":         {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 11, 0},
		"CurrentConnections":         {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 12, 0},
		"MaxConnections":               {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 13, 0},
		"ConnectionAttempts":           {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 14, 0},
		"LogonAttempts":                {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 15, 0},
		"Gets":                         {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 16, 0},
		"Posts":                        {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 17, 0},
		"Heads":                        {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 18, 0},
		"Others":                       {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 19, 0},
		"CGIRequests":                  {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 20, 0},
		"BGIRequests":                  {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 21, 0},
		"NotFoundErrors":               {1, 3, 6, 1, 4, 1, 311, 1, 7, 3, 1, 22, 0},
	}
	info := map[string]string{}
	for name, oid := range oids {
		if v := sess.getString(oid); !isNullish(v) {
			info[name] = v
		}
	}
	if len(info) == 0 {
		return
	}
	printSection(out, "IIS server information")
	keys := make([]string, 0, len(info))
	for k := range info {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		printField(out, k, info[k])
	}
}

func (e *Enumerator) printStorage(sess *Session, out io.Writer) {
	roots := [][]int{
		{1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 1},
		{1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 2},
		{1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 3},
		{1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 4},
		{1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 5},
		{1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 6},
	}
	table, err := walkTable(sess, roots)
	if err != nil || len(table) == 0 {
		return
	}
	printSection(out, "Storage information")
	for _, idx := range sortedIndexes(table) {
		row := table[idx]
		for len(row) < 6 {
			row = append(row, "")
		}
		descr, id, typ, alloc, size, used := row[2], row[0], mapStorageType(row[1]), row[3], row[4], row[5]
		if isNullish(alloc) {
			alloc = "unknown"
		}
		if isNullish(size) {
			size = "unknown"
		}
		if isNullish(used) {
			used = "unknown"
		}
		memSize := size
		memUsed := used
		if size != "unknown" && alloc != "unknown" {
			memSize = numberToHumanSize(size, alloc)
		}
		if used != "unknown" && alloc != "unknown" {
			memUsed = numberToHumanSize(used, alloc)
		}
		printField(out, "Description", dashIfEmpty(descr))
		printField(out, "Device id", dashIfEmpty(id))
		printField(out, "Filesystem type", typ)
		printField(out, "Device unit", alloc)
		printField(out, "Memory size", memSize)
		printField(out, "Memory used", memUsed)
		fmt.Fprintln(out)
	}
}

func (e *Enumerator) printFileSystem(sess *Session, out io.Writer) {
	fields := []struct {
		name string
		oid  []int
	}{
		{"Index", []int{1, 3, 6, 1, 2, 1, 25, 3, 8, 1, 1, 1}},
		{"Mount point", []int{1, 3, 6, 1, 2, 1, 25, 3, 8, 1, 2, 1}},
		{"Remote mount point", []int{1, 3, 6, 1, 2, 1, 25, 3, 8, 1, 3, 1}},
		{"Access", []int{1, 3, 6, 1, 2, 1, 25, 3, 8, 1, 5, 1}},
		{"Bootable", []int{1, 3, 6, 1, 2, 1, 25, 3, 8, 1, 6, 1}},
	}
	info := map[string]string{}
	for _, f := range fields {
		if v := sess.getString(f.oid); !isNullish(v) {
			info[f.name] = v
		}
	}
	if v := sess.getString([]int{1, 3, 6, 1, 2, 1, 25, 3, 8, 1, 4, 1}); !isNullish(v) {
		info["Type"] = mapFSType(v)
	}
	if len(info) == 0 {
		return
	}
	printSection(out, "File system information")
	keys := make([]string, 0, len(info))
	for k := range info {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		printField(out, k, info[k])
	}
}

func (e *Enumerator) printDevices(sess *Session, out io.Writer) {
	roots := [][]int{
		{1, 3, 6, 1, 2, 1, 25, 3, 2, 1, 1},
		{1, 3, 6, 1, 2, 1, 25, 3, 2, 1, 2},
		{1, 3, 6, 1, 2, 1, 25, 3, 2, 1, 5},
		{1, 3, 6, 1, 2, 1, 25, 3, 2, 1, 3},
	}
	table, err := walkTable(sess, roots)
	if err != nil || len(table) == 0 {
		return
	}
	printSection(out, "Device information")
	fmt.Fprintf(out, "%s   %-6s %-18s %-10s %s\n", snmpTag, "Id", "Type", "Status", "Descr")
	for _, idx := range sortedIndexes(table) {
		row := table[idx]
		for len(row) < 4 {
			row = append(row, "")
		}
		descr := row[3]
		if isNullish(descr) {
			descr = "unknown"
		}
		fmt.Fprintf(out, "%s   %-6s %-18s %-10s %s\n", snmpTag, row[0], mapDeviceType(row[1]), mapDeviceStatus(row[2]), descr)
	}
}

func (e *Enumerator) printSoftware(sess *Session, out io.Writer) {
	roots := [][]int{
		{1, 3, 6, 1, 2, 1, 25, 6, 3, 1, 1},
		{1, 3, 6, 1, 2, 1, 25, 6, 3, 1, 2},
	}
	table, err := walkTable(sess, roots)
	if err != nil || len(table) == 0 {
		return
	}
	printSection(out, "Software components")
	fmt.Fprintf(out, "%s   %-8s %s\n", snmpTag, "Index", "Name")
	for _, idx := range sortedIndexes(table) {
		row := table[idx]
		if len(row) < 2 {
			continue
		}
		fmt.Fprintf(out, "%s   %-8s %s\n", snmpTag, row[0], row[1])
	}
}

func (e *Enumerator) printProcesses(sess *Session, out io.Writer) {
	roots := [][]int{
		{1, 3, 6, 1, 2, 1, 25, 4, 2, 1, 1},
		{1, 3, 6, 1, 2, 1, 25, 4, 2, 1, 2},
		{1, 3, 6, 1, 2, 1, 25, 4, 2, 1, 4},
		{1, 3, 6, 1, 2, 1, 25, 4, 2, 1, 5},
		{1, 3, 6, 1, 2, 1, 25, 4, 2, 1, 7},
	}
	table, err := walkTable(sess, roots)
	if err != nil || len(table) == 0 {
		return
	}
	printSection(out, "Processes")
	fmt.Fprintf(out, "%s   %-6s %-10s %-16s %s %s\n", snmpTag, "Id", "Status", "Name", "Path", "Parameters")
	for _, idx := range sortedIndexes(table) {
		row := table[idx]
		for len(row) < 5 {
			row = append(row, "")
		}
		fmt.Fprintf(out, "%s   %-6s %-10s %-16s %s %s\n", snmpTag, row[0], mapProcessStatus(row[4]), row[1], row[2], row[3])
	}
}
