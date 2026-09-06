package ssh

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const (
	defaultPort    = 22
	defaultTimeout = 10 * time.Second
	sshTag         = "\x1b[33m[SSH]\x1b[0m"
)

// AuthMethodsProbe lists authentication methods a SSH server supports for a username.
// Stdlib only — no third-party SSH libraries.
type AuthMethodsProbe struct {
	Target   string
	Port     int
	Username string
	Timeout  time.Duration
	Out      io.Writer
}

// Run connects, completes SSH KEX, sends USERAUTH "none", and prints supported methods.
func (p *AuthMethodsProbe) Run() error {
	host := strings.TrimSpace(p.Target)
	user := strings.TrimSpace(p.Username)
	if host == "" {
		return fmt.Errorf("--ssh --auth-methods requires --target <ip>")
	}
	if user == "" {
		return fmt.Errorf("--ssh --auth-methods requires --username <user>")
	}

	port := p.Port
	if port <= 0 {
		port = defaultPort
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	out := p.Out
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
	fmt.Fprintf(out, "%s Target: %s  User: %s\n", sshTag, addr, user)

	// Identification grab before full handshake.
	if banner, err := GrabBanner(ip.String(), port, timeout); err == nil && banner != "" {
		fmt.Fprintf(out, "%s Banner: %s\n", sshTag, banner)
	}

	tr, err := dialKex(addr, timeout)
	if err != nil {
		return err
	}
	defer tr.conn.Close()

	methods, err := tr.listAuthMethods(user)
	if err != nil {
		return fmt.Errorf("userauth: %w", err)
	}

	const indent = "      "
	fmt.Fprintf(out, "%sSupported authentication methods:\n", indent)
	trimmed := trimMethods(methods)
	if len(trimmed) == 0 {
		fmt.Fprintf(out, "%s- (none reported)\n", indent)
	} else {
		for _, m := range trimmed {
			fmt.Fprintf(out, "%s- %s\n", indent, m)
		}
	}
	if strings.TrimSpace(tr.banner) != "" {
		fmt.Fprintf(out, "%sAuth banner: %s\n", indent, strings.TrimRight(tr.banner, "\r\n"))
	}
	return nil
}

func dialKex(addr string, timeout time.Duration) (*transport, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout * 3))

	tr := newTransport(conn)
	if err := tr.exchangeVersions(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("version exchange: %w", err)
	}
	if _, err := tr.doKex(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("key exchange: %w", err)
	}
	return tr, nil
}

func trimMethods(methods []string) []string {
	var out []string
	for _, m := range methods {
		m = strings.TrimSpace(m)
		if m != "" {
			out = append(out, m)
		}
	}
	return out
}
