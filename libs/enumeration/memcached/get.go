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

// Getter fetches a single key/value from Memcached via the text protocol get command.
type Getter struct {
	Target  string
	Port    int
	Key     string
	Timeout time.Duration
	Out     io.Writer
}

// Run connects and issues `get <key>`, printing the stored value when present.
func (g *Getter) Run() error {
	host := strings.TrimSpace(g.Target)
	key := strings.TrimSpace(g.Key)
	if host == "" {
		return fmt.Errorf("--memcached --enum <key> requires --target <ip|host>")
	}
	if key == "" {
		return fmt.Errorf("--memcached --enum <key> requires a non-empty key")
	}
	if strings.ContainsAny(key, " \r\n") {
		return fmt.Errorf("invalid memcached key %q (no spaces/newlines)", key)
	}

	port := g.Port
	if port <= 0 {
		port = defaultPort
	}
	timeout := g.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	out := g.Out
	if out == nil {
		out = os.Stdout
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	fmt.Fprintf(out, "%s Target: %s  Key: %s  Timeout: %s\n", memcachedTag, addr, key, timeout)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer conn.Close()
	fmt.Fprintf(out, "%s Connected to %s\n", memcachedTag, addr)

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("get " + key + "\r\n")); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	reader := bufio.NewReader(conn)
	found := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("read: %w", err)
		}
		trimmed := strings.TrimRight(line, "\r\n")

		switch {
		case trimmed == "END":
			if !found {
				fmt.Fprintf(out, "\x1b[31m[-]\x1b[0m Key not found: %s\n", key)
			}
			return nil
		case trimmed == "ERROR":
			return fmt.Errorf("server returned ERROR")
		case strings.HasPrefix(trimmed, "CLIENT_ERROR"), strings.HasPrefix(trimmed, "SERVER_ERROR"):
			return fmt.Errorf("%s", trimmed)
		case strings.HasPrefix(trimmed, "VALUE "):
			// VALUE <key> <flags> <bytes> [<cas>]\r\n
			parts := strings.Fields(trimmed)
			if len(parts) < 4 {
				return fmt.Errorf("malformed VALUE line: %s", trimmed)
			}
			nbytes, err := strconv.Atoi(parts[3])
			if err != nil || nbytes < 0 {
				return fmt.Errorf("invalid VALUE byte count: %s", parts[3])
			}
			flags := parts[2]
			data := make([]byte, nbytes)
			if _, err := io.ReadFull(reader, data); err != nil {
				return fmt.Errorf("read value body: %w", err)
			}
			// Trailing CRLF after the body.
			crlf := make([]byte, 2)
			if _, err := io.ReadFull(reader, crlf); err != nil {
				return fmt.Errorf("read value trailer: %w", err)
			}
			found = true
			fmt.Fprintf(out, "\x1b[32m[+]\x1b[0m Key found\n")
			fmt.Fprintf(out, "- key: %s\n", parts[1])
			fmt.Fprintf(out, "- flags: %s\n", flags)
			fmt.Fprintf(out, "- bytes: %d\n", nbytes)
			fmt.Fprintf(out, "- value: %q\n", string(data))
		default:
			// Ignore unexpected lines; END terminates the exchange.
		}
	}
	if !found {
		fmt.Fprintf(out, "\x1b[31m[-]\x1b[0m Key not found: %s\n", key)
	}
	return nil
}
