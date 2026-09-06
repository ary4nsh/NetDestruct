package ssh

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// GrabBanner performs an SSH identification grab:
// TCP connect to host:port and read the server's version line
// (e.g. "SSH-2.0-OpenSSH_8.9p1 ...") without key exchange or auth.
// Stdlib only.
func GrabBanner(host string, port int, timeout time.Duration) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("empty host")
	}
	if port <= 0 {
		port = defaultPort
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupIP(host)
		if err != nil || len(addrs) == 0 {
			return "", fmt.Errorf("resolve %q: %w", host, err)
		}
		ip = addrs[0]
	}
	addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", fmt.Errorf("connect %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Do not speak first; read what the server sends.
	line, err := readSSHIdentification(conn)
	if err != nil {
		return "", fmt.Errorf("banner: %w", err)
	}
	return line, nil
}

// readSSHIdentification reads lines until the SSH version string (RFC 4253 §4.2).
// Lines before the identification string are ignored.
func readSSHIdentification(r io.Reader) (string, error) {
	for {
		line, err := readVersionLine(r)
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(line, "SSH-") {
			return line, nil
		}
	}
}
