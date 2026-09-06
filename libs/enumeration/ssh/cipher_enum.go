package ssh

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// CipherEnumer runs SSH cipher / hostkey / publickey probes
// (SSH2 Algorithms, SSH Host Keys, SSH Accepted Public Keys) using stdlib only.
type CipherEnumer struct {
	Target  string
	Port    int
	Timeout time.Duration
	Out     io.Writer
}

// knownBadPublicKeys (base64 blob,user,msg).
var knownBadPublicKeys = []struct {
	b64  string
	user string
	msg  string
}{
	{
		b64:  "AAAAB3NzaC1kc3MAAACBAISAE3CAX4hsxTw0dRc0gx8nQ41r3Vkj9OmG6LGeKWRmpy7C6vaExuupjxid76fd4aS56lCUEEoRlJ3zE93qoK9acI6EGqGQFLuDZ0fqMyRSX+ilf+1HDo/TRyuraggxp9Hj9LMpZVbpFATMm0+d9Xs7eLmaJjuMsowNlOf8NFdHAAAAFQCwdvqOAkR6QhuiAapQ/9iVuR0UAQAAAIBpLMo4dhSeWkChfv659WLPftxRrX/HR8YMD/jqa3R4PsVM2g6dQ1191nHugtdV7uaMeOqOJ/QRWeYM+UYwT0Zgx2LqvgVSjNDfdjk+ZRY8x3SmExFi62mKFoTGSOCXfcAfuanjaoF+sepnaiLUd+SoJShGYHoqR2QWiysTRqknlwAAAIBLEgYmr9XCSqjENFDVQPFELYKT7Zs9J87PjPS1AP0qF1OoRGZ5mefK6X/6VivPAUWmmmev/BuAs8M1HtfGeGGzMzDIiU/WZQ3bScLB1Ykrcjk7TOFD6xrnk/inYAp5l29hjidoAONcXoHmUAMYOKqn63Q2AsDpExVcmfj99/BlpQ==",
		user: "root",
		msg:  "Quantum DXi V1000 2.2.1 static root publickey accepted",
	},
	{
		b64:  "AAAAB3NzaC1kc3MAAACBAKwKBw7D4OA1H/uD4htdh04TBIHdbSjeXUSnWJsce8C0tvoB01Yarjv9TFj+tfeDYVWtUK1DA1JkyqSuoAtDANJzF4I6Isyd0KPrW3dHFTcg6Xlz8d3KEaHokY93NOmB/xWEkhme8b7Q0U2iZie2pgWbTLXV0FA+lhskTtPHW3+VAAAAFQDRyayUlVZKXEweF3bUe03zt9e8VQAAAIAEPK1k3Y6ErAbIl96dnUCnZjuWQ7xXy062pf63QuRWI6LYSscm3f1pEknWUNFr/erQ02pkfi2eP9uHl1TI1ql+UmJX3g3frfssLNZwWXAW0m8PbY3HZSs+f5hevM3ua32pnKDmbQ2WpvKNyycKHi81hSI14xMcdblJolhN5iY8/wAAAIAjEe5+0m/TlBtVkqQbUit+s/g+eB+PFQ+raaQdL1uztW3etntXAPH1MjxsAC/vthWYSTYXORkDFMhrO5ssE2rfg9io0NDyTIZt+VRQMGdi++dH8ptU+ldl2ZejLFdTJFwFgcfXz+iQ1mx6h9TPX1crE1KoMAVOj3yKVfKpLB1EkA==",
		user: "root",
		msg:  "Loadbalancer.org Enterprise VA 7.5.2 static root publickey accepted",
	},
	{
		b64:  "AAAAB3NzaC1yc2EAAAABIwAAAIEAvIhC5skTzxyHif/7iy3yhxuK6/OB13hjPqrskogkYFrcW8OK4VJT+5+Fx7wd4sQCnVn8rNqahw/x6sfcOMDI/Xvn4yKU4t8TnYf2MpUVr4ndz39L5Ds1n7Si1m2suUNxWbKv58I8+NMhlt2ITraSuTU0NGymWOc8+LNi+MHXdLk=",
		user: "root",
		msg:  "f5 BigIP static root publickey accepted",
	},
}

// Host key probes match OpenSSH ssh-keyscan.c (KT_* families / keygrab_ssh2).
// Each entry offers one or more host-key algorithms in preference order;
// one KEX retrieves that family's host key when the server supports any of them.
var hostKeyProbes = []struct {
	family string
	algs   string // comma-separated, ssh-keyscan proposal order
}{
	{"RSA", "rsa-sha2-512,rsa-sha2-256,ssh-rsa"},
	{"ECDSA", "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521"},
	{"ED25519", "ssh-ed25519"},
	{"ECDSA_SK", "sk-ecdsa-sha2-nistp256@openssh.com"},
	{"ED25519_SK", "sk-ssh-ed25519@openssh.com"},
	{"MLDSA44_ED25519", "ssh-mldsa44-ed25519"},
	// Legacy DSA still useful on older SSH; not in modern ssh-keyscan defaults.
	{"DSA", "ssh-dss"},
}

// HostKeyInfo is one SSH host public key.
type HostKeyInfo struct {
	KeyType           string
	Algorithm         string
	Bits              int
	Blob              []byte
	FullKey           string
	MD5Fingerprint    string
	SHA256Fingerprint string
}

// Run performs banner grab + SSH2 Algorithms + SSH Host Keys + SSH Accepted Public Keys.
func (c *CipherEnumer) Run() error {
	host := strings.TrimSpace(c.Target)
	if host == "" {
		return fmt.Errorf("--ssh --cipher-enum requires --target <ip>")
	}
	port := c.Port
	if port <= 0 {
		port = defaultPort
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	out := c.Out
	if out == nil {
		out = os.Stdout
	}

	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupIP(host)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("resolve %q: %w", host, err)
		}
		ip = addrs[0]
	}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	fmt.Fprintf(out, "%s Target: %s\n", sshTag, addr)

	if banner, err := GrabBanner(ip.String(), port, timeout); err == nil && banner != "" {
		fmt.Fprintf(out, "%s Banner: %s\n", sshTag, banner)
	}

	if err := c.runEnumAlgos(addr, timeout, out); err != nil {
		fmt.Fprintf(out, "%s SSH2 Algorithms: %v\n", sshTag, err)
	}
	if err := c.runHostKeys(addr, timeout, out); err != nil {
		fmt.Fprintf(out, "%s SSH Host Keys: %v\n", sshTag, err)
	}
	if err := c.runPublickeyAcceptance(addr, timeout, out); err != nil {
		fmt.Fprintf(out, "%s SSH Accepted Public Keys: %v\n", sshTag, err)
	}
	return nil
}

func (c *CipherEnumer) runEnumAlgos(addr string, timeout time.Duration, out io.Writer) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout * 3))

	tr := newTransport(conn)
	if err := tr.exchangeVersions(); err != nil {
		return fmt.Errorf("version exchange: %w", err)
	}
	lists, err := tr.readServerKexInit()
	if err != nil {
		return err
	}

	const indent = "      "
	fmt.Fprintf(out, "\n%s SSH2 Algorithms:\n", sshTag)

	printAlgoList(out, indent, "kex_algorithms", lists[0])
	printAlgoList(out, indent, "server_host_key_algorithms", lists[1])
	printCombinedAlgos(out, indent, "encryption_algorithms", lists[2], lists[3])
	printCombinedAlgos(out, indent, "mac_algorithms", lists[4], lists[5])
	printCombinedAlgos(out, indent, "compression_algorithms", lists[6], lists[7])
	return nil
}

func printCombinedAlgos(out io.Writer, indent, name string, c2s, s2c []string) {
	if equalStringSlices(c2s, s2c) {
		printAlgoList(out, indent, name, c2s)
		return
	}
	printAlgoList(out, indent, name+"_client_to_server", c2s)
	printAlgoList(out, indent, name+"_server_to_client", s2c)
}

func printAlgoList(out io.Writer, indent, name string, algs []string) {
	clean := make([]string, 0, len(algs))
	for _, a := range algs {
		a = strings.TrimSpace(a)
		if a != "" {
			clean = append(clean, a)
		}
	}
	fmt.Fprintf(out, "%s%s (%d)\n", indent, name, len(clean))
	for _, a := range clean {
		fmt.Fprintf(out, "%s    %s\n", indent, a)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (c *CipherEnumer) runHostKeys(addr string, timeout time.Duration, out io.Writer) error {
	fmt.Fprintf(out, "\n%s SSH Host Keys:\n", sshTag)
	const indent = "      "
	found := 0
	seenFP := map[string]bool{}
	for _, probe := range hostKeyProbes {
		hk, err := fetchHostKey(addr, timeout, probe.algs)
		if err != nil || hk == nil {
			continue
		}
		// Same RSA blob can be negotiated
		if seenFP[hk.MD5Fingerprint] {
			continue
		}
		seenFP[hk.MD5Fingerprint] = true
		found++
		fmt.Fprintf(out, "%s%d %s (%s)\n", indent, hk.Bits, hk.MD5Fingerprint, hk.Algorithm)
		fmt.Fprintf(out, "%s%d %s (%s)\n", indent, hk.Bits, hk.SHA256Fingerprint, hk.Algorithm)
		fmt.Fprintf(out, "%s%s\n", indent, hk.FullKey)
	}
	if found == 0 {
		fmt.Fprintf(out, "%s(no host keys retrieved)\n", indent)
	}
	return nil
}

// fetchHostKey completes KEX offering hostKeyAlgs (comma-separated).
func fetchHostKey(addr string, timeout time.Duration, hostKeyAlgs string) (*HostKeyInfo, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout * 3))

	tr := newTransport(conn)
	if err := tr.exchangeVersions(); err != nil {
		return nil, err
	}

	cookie := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, cookie); err != nil {
		return nil, err
	}
	opts := defaultKexInitOpts()
	opts.hostKeyAlgs = hostKeyAlgs
	opts.kexAlgs = "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,curve25519-sha256,curve25519-sha256@libssh.org"
	clientInit := buildKexInitWith(cookie, opts)
	if err := tr.writePacket(clientInit); err != nil {
		return nil, err
	}
	serverPayload, err := tr.readPayload()
	if err != nil {
		return nil, err
	}
	if serverPayload[0] != msgKexInit {
		return nil, fmt.Errorf("expected KEXINIT")
	}
	sLists, err := parseKexInitLists(serverPayload)
	if err != nil {
		return nil, err
	}
	want := strings.Split(hostKeyAlgs, ",")
	if !containsAnyAlg(sLists[1], want) {
		return nil, nil
	}
	if _, err := tr.doKexAfterInits(clientInit, serverPayload); err != nil {
		return nil, err
	}
	if len(tr.hostKey) == 0 {
		return nil, nil
	}
	// Record negotiated host-key algorithm name when possible.
	negotiated := firstMatch(want, sLists[1])
	if negotiated == "" {
		negotiated = want[0]
	}
	return parseHostKeyBlob(negotiated, tr.hostKey)
}

func containsAlg(list []string, want string) bool {
	for _, a := range list {
		if a == want {
			return true
		}
	}
	return false
}

func containsAnyAlg(list, want []string) bool {
	set := make(map[string]bool, len(list))
	for _, a := range list {
		set[a] = true
	}
	for _, w := range want {
		w = strings.TrimSpace(w)
		if w != "" && set[w] {
			return true
		}
	}
	return false
}

func parseHostKeyBlob(keyType string, blob []byte) (*HostKeyInfo, error) {
	algName, _, ok := readString(blob)
	if !ok {
		return nil, fmt.Errorf("bad host key blob")
	}
	algo, bits := hostKeyAlgoBits(string(algName), blob)
	md5sum := md5.Sum(blob)
	sha := sha256.Sum256(blob)
	return &HostKeyInfo{
		KeyType:           keyType,
		Algorithm:         algo,
		Bits:              bits,
		Blob:              append([]byte(nil), blob...),
		FullKey:           string(algName) + " " + base64.StdEncoding.EncodeToString(blob),
		MD5Fingerprint:    formatMD5Fingerprint(md5sum[:]),
		SHA256Fingerprint: "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sha[:]), "="),
	}, nil
}

func hostKeyAlgoBits(alg string, blob []byte) (string, int) {
	switch alg {
	case "ssh-rsa", "rsa-sha2-256", "rsa-sha2-512":
		return "RSA", rsaBits(blob)
	case "ssh-dss":
		return "DSA", dsaBits(blob)
	case "ecdsa-sha2-nistp256":
		return "ECDSA", 256
	case "ecdsa-sha2-nistp384":
		return "ECDSA", 384
	case "ecdsa-sha2-nistp521":
		return "ECDSA", 521
	case "ssh-ed25519":
		return "ED25519", 256
	case "sk-ecdsa-sha2-nistp256@openssh.com":
		return "ECDSA-SK", 256
	case "sk-ssh-ed25519@openssh.com":
		return "ED25519-SK", 256
	case "ssh-mldsa44-ed25519":
		return "MLDSA44-ED25519", 256
	default:
		if strings.HasPrefix(alg, "ecdsa-sha2-") {
			return "ECDSA", 0
		}
		if strings.HasPrefix(alg, "sk-ecdsa-") {
			return "ECDSA-SK", 0
		}
		if strings.HasPrefix(alg, "sk-ssh-ed25519") {
			return "ED25519-SK", 256
		}
		return strings.ToUpper(alg), 0
	}
}

func rsaBits(blob []byte) int {
	_, rest, ok := readString(blob)
	if !ok {
		return 0
	}
	_, rest, ok = readString(rest) // e
	if !ok {
		return 0
	}
	nBytes, _, ok := readString(rest)
	if !ok {
		return 0
	}
	return new(big.Int).SetBytes(nBytes).BitLen()
}

func dsaBits(blob []byte) int {
	_, rest, ok := readString(blob)
	if !ok {
		return 0
	}
	pBytes, _, ok := readString(rest)
	if !ok {
		return 0
	}
	return new(big.Int).SetBytes(pBytes).BitLen()
}

func formatMD5Fingerprint(sum []byte) string {
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

func (c *CipherEnumer) runPublickeyAcceptance(addr string, timeout time.Duration, out io.Writer) error {
	fmt.Fprintf(out, "\n%s SSH Accepted Public Keys:\n", sshTag)
	const indent = "      "
	fmt.Fprintf(out, "%sAccepted Public Keys:\n", indent)

	var accepted []string
	failures := 0
	successes := 0
	for _, entry := range knownBadPublicKeys {
		blob, err := base64.StdEncoding.DecodeString(entry.b64)
		if err != nil {
			continue
		}
		tr, err := dialKex(addr, timeout)
		if err != nil {
			failures++
			if failures > 2 && successes == 0 {
				fmt.Fprintf(out, "%s- (connect failed; giving up)\n", indent)
				return nil
			}
			continue
		}
		successes++
		ok, err := tr.publickeyCanAuth(entry.user, blob)
		_ = tr.conn.Close()
		if err != nil {
			continue
		}
		if ok {
			accepted = append(accepted, entry.msg)
		}
	}

	if len(accepted) == 0 {
		fmt.Fprintf(out, "%s- No public keys accepted\n", indent)
		return nil
	}
	for _, msg := range accepted {
		fmt.Fprintf(out, "%s- %s\n", indent, msg)
	}
	return nil
}
