package memcached

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	memcachedTag   = "\x1b[90m[MEMCACHED]\x1b[0m"
	defaultPort    = 11211
	defaultTimeout = 5 * time.Second
)

// Setter stores a key/value with the Memcached text-protocol set command.
type Setter struct {
	Target  string
	Port    int
	Key     string
	Value   string
	Flags   uint32
	Exptime int // seconds; 0 = never expire
	Timeout time.Duration
	Out     io.Writer
}

// Run connects and issues `set <key> <flags> <exptime> <bytes>\r\n<data>\r\n`.
func (s *Setter) Run() error {
	host := strings.TrimSpace(s.Target)
	key := strings.TrimSpace(s.Key)
	if host == "" {
		return fmt.Errorf("--memcached --set requires --target <ip|host>")
	}
	if key == "" {
		return fmt.Errorf("--memcached --set requires a non-empty key")
	}
	if strings.ContainsAny(key, " \r\n") {
		return fmt.Errorf("invalid memcached key %q (no spaces/newlines)", key)
	}

	port := s.Port
	if port <= 0 {
		port = defaultPort
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	out := s.Out
	if out == nil {
		out = os.Stdout
	}

	data := []byte(s.Value)
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	fmt.Fprintf(out, "%s Target: %s  Timeout: %s\n", memcachedTag, addr, timeout)
	fmt.Fprintf(out, "%s Setting key %q (%d bytes)\n", memcachedTag, key, len(data))

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer conn.Close()
	fmt.Fprintf(out, "%s Connected to %s\n", memcachedTag, addr)

	_ = conn.SetDeadline(time.Now().Add(timeout))
	hdr := fmt.Sprintf("set %s %d %d %d\r\n", key, s.Flags, s.Exptime, len(data))
	if _, err := conn.Write([]byte(hdr)); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if _, err := conn.Write([]byte("\r\n")); err != nil {
		return fmt.Errorf("write trailer: %w", err)
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("read: %w", err)
	}
	resp := strings.TrimRight(line, "\r\n")
	switch resp {
	case "STORED":
		fmt.Fprintf(out, "\x1b[32m[+]\x1b[0m STORED key %q (%d bytes)\n", key, len(data))
		return nil
	case "NOT_STORED":
		return fmt.Errorf("NOT_STORED (server rejected set for key %q)", key)
	case "ERROR":
		return fmt.Errorf("server returned ERROR")
	default:
		if strings.HasPrefix(resp, "CLIENT_ERROR") || strings.HasPrefix(resp, "SERVER_ERROR") {
			return fmt.Errorf("%s", resp)
		}
		return fmt.Errorf("unexpected response: %s", resp)
	}
}

// Deleter removes a key via the Memcached text-protocol delete command.
type Deleter struct {
	Target  string
	Port    int
	Key     string
	Timeout time.Duration
	Out     io.Writer
}

// Run connects and issues `delete <key>`.
func (d *Deleter) Run() error {
	host := strings.TrimSpace(d.Target)
	key := strings.TrimSpace(d.Key)
	if host == "" {
		return fmt.Errorf("--memcached --delete requires --target <ip|host>")
	}
	if key == "" {
		return fmt.Errorf("--memcached --delete requires a non-empty key")
	}
	if strings.ContainsAny(key, " \r\n") {
		return fmt.Errorf("invalid memcached key %q (no spaces/newlines)", key)
	}

	port := d.Port
	if port <= 0 {
		port = defaultPort
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	out := d.Out
	if out == nil {
		out = os.Stdout
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	fmt.Fprintf(out, "%s Target: %s  Timeout: %s\n", memcachedTag, addr, timeout)
	fmt.Fprintf(out, "%s Deleting key %q\n", memcachedTag, key)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer conn.Close()
	fmt.Fprintf(out, "%s Connected to %s\n", memcachedTag, addr)

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("delete " + key + "\r\n")); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("read: %w", err)
	}
	resp := strings.TrimRight(line, "\r\n")
	switch resp {
	case "DELETED":
		fmt.Fprintf(out, "\x1b[32m[+]\x1b[0m DELETED key %q\n", key)
		return nil
	case "NOT_FOUND":
		fmt.Fprintf(out, "\x1b[31m[-]\x1b[0m Key not found: %s\n", key)
		return nil
	case "ERROR":
		return fmt.Errorf("server returned ERROR")
	default:
		if strings.HasPrefix(resp, "CLIENT_ERROR") || strings.HasPrefix(resp, "SERVER_ERROR") {
			return fmt.Errorf("%s", resp)
		}
		return fmt.Errorf("unexpected response: %s", resp)
	}
}
