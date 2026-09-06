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

// Flusher wipes all keys on a Memcached server via flush_all.
type Flusher struct {
	Target  string
	Port    int
	Timeout time.Duration
	Out     io.Writer
}

// Run connects and issues `flush_all`, invalidating every cached item.
func (f *Flusher) Run() error {
	host := strings.TrimSpace(f.Target)
	if host == "" {
		return fmt.Errorf("--memcached --flush-all requires --target <ip|host>")
	}
	port := f.Port
	if port <= 0 {
		port = defaultPort
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	out := f.Out
	if out == nil {
		out = os.Stdout
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	fmt.Fprintf(out, "%s Target: %s  Timeout: %s\n", memcachedTag, addr, timeout)
	fmt.Fprintf(out, "%s Sending flush_all\n", memcachedTag)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer conn.Close()
	fmt.Fprintf(out, "%s Connected to %s\n", memcachedTag, addr)

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("flush_all\r\n")); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("read: %w", err)
	}
	resp := strings.TrimRight(line, "\r\n")
	switch {
	case resp == "OK":
		fmt.Fprintf(out, "\x1b[32m[+]\x1b[0m flush_all succeeded — all keys invalidated\n")
		return nil
	case resp == "ERROR":
		return fmt.Errorf("server returned ERROR (flush_all not supported)")
	case strings.HasPrefix(resp, "CLIENT_ERROR"), strings.HasPrefix(resp, "SERVER_ERROR"):
		return fmt.Errorf("%s", resp)
	case resp == "":
		return fmt.Errorf("empty response to flush_all")
	default:
		return fmt.Errorf("unexpected response: %s", resp)
	}
}
