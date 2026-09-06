package snmp

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// TriggerCiscoConfigCopy uses SNMPv3 SET against CISCO-CONFIG-COPY-MIB
// to push the running-config to a TFTP server.
// Auth/priv are optional: noAuthNoPriv, authNoPriv, or authPriv depending on what is set.
// Returns the destination filename on the TFTP server (typically "<target>-config.txt").
func TriggerCiscoConfigCopy(host string, port int, user, authName, authPass, privName, privPass, tftpHost string) (string, error) {
	host = strings.TrimSpace(host)
	user = strings.TrimSpace(user)
	authName = strings.TrimSpace(authName)
	authPass = strings.TrimSpace(authPass)
	privName = strings.TrimSpace(privName)
	privPass = strings.TrimSpace(privPass)
	tftpHost = strings.TrimSpace(tftpHost)
	if host == "" {
		return "", fmt.Errorf("empty target")
	}
	if user == "" {
		return "", fmt.Errorf("empty username")
	}

	authProto := v3AuthNone
	privProto := v3PrivNone
	var flags byte = v3FlagNoAuthNoPriv

	if authName != "" {
		authProto = v3AuthByName(authName)
		if authProto == v3AuthNone {
			return "", fmt.Errorf("unsupported --auth %q (use MD5|SHA|SHA-224|SHA-256|SHA-384|SHA-512)", authName)
		}
		if authPass == "" {
			return "", fmt.Errorf("--auth requires --auth-pass")
		}
		flags = v3FlagAuthNoPriv
	} else if authPass != "" {
		return "", fmt.Errorf("--auth-pass requires --auth")
	}

	if privName != "" {
		if authProto == v3AuthNone {
			return "", fmt.Errorf("--priv requires --auth (privacy cannot be used without authentication)")
		}
		privProto = v3PrivByName(privName)
		if privProto == v3PrivNone {
			return "", fmt.Errorf("unsupported --priv %q (use DES|AES|AES-192|AES-256)", privName)
		}
		if privPass == "" {
			return "", fmt.Errorf("--priv requires --priv-pass")
		}
		flags = v3FlagAuthPriv
	} else if privPass != "" {
		return "", fmt.Errorf("--priv-pass requires --priv")
	}

	targetIP := net.ParseIP(host)
	if targetIP == nil {
		addrs, err := net.LookupIP(host)
		if err != nil || len(addrs) == 0 {
			return "", fmt.Errorf("resolve target %q: %w", host, err)
		}
		targetIP = addrs[0]
	}
	tftpIP := net.ParseIP(tftpHost)
	if tftpIP == nil {
		addrs, err := net.LookupIP(tftpHost)
		if err != nil || len(addrs) == 0 {
			return "", fmt.Errorf("resolve tftp server %q: %w", tftpHost, err)
		}
		tftpIP = addrs[0]
	}
	tftp4 := tftpIP.To4()
	if tftp4 == nil {
		return "", fmt.Errorf("TFTP server must be IPv4 (CISCO-CONFIG-COPY ccCopyServerAddress): %s", tftpHost)
	}

	client, err := newV3Client(targetIP.String(), port, 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	client.discoverEngine()
	if !client.hasEngine() {
		return "", fmt.Errorf("SNMP engine discovery failed (check reachability / SNMPv3)")
	}

	idx := 100 + rand.Intn(900) //nolint:gosec // random CISCO-CONFIG-COPY row index
	fileName := fmt.Sprintf("%s-config.txt", targetIP.String())

	// CISCO-CONFIG-COPY-MIB::ccCopyEntry columns (enterprises.9.9.96.1.1.1.1.*)
	base := []int{1, 3, 6, 1, 4, 1, 9, 9, 96, 1, 1, 1, 1}
	oid := func(col int) []int {
		return append(append([]int{}, base...), col, idx)
	}

	binds := []v3VarBind{
		{OID: oid(2), Value: asn1Int(1)},                        // ccCopyProtocol = tftp(1)
		{OID: oid(3), Value: asn1Int(4)},                        // ccCopySourceFileType = runningConfig(4)
		{OID: oid(4), Value: asn1Int(1)},                        // ccCopyDestFileType = networkFile(1)
		{OID: oid(5), Value: asn1IPAddress(tftp4)},              // ccCopyServerAddress
		{OID: oid(6), Value: asn1OctetString([]byte(fileName))}, // ccCopyFileName
		{OID: oid(14), Value: asn1Int(4)},                       // ccCopyEntryRowStatus = createAndGo(4)
	}

	if err := client.setVarbinds(user, flags, authProto, privProto, authPass, privPass, binds); err != nil {
		return "", err
	}
	return fileName, nil
}
