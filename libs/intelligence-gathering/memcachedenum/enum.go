package memcachedenum

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

// reconCommands is the ordered set of unauthenticated text-protocol commands
// issued during reconnaissance against an open Memcached instance.
var reconCommands = []struct {
	title   string
	command string
}{
	{"Version", "version"},
	{"Stats", "stats"},
	{"Stats Slabs", "stats slabs"},
	{"Stats Items", "stats items"},
	{"Stats Settings", "stats settings"},
	{"Stats Sizes", "stats sizes"},
}

// Enumerator performs unauthenticated Memcached reconnaissance over TCP.
type Enumerator struct {
	Target  string
	Port    int
	Timeout time.Duration
	Out     io.Writer
}

type session struct {
	conn    net.Conn
	reader  *bufio.Reader
	timeout time.Duration
}

// Run connects to the target and issues each reconnaissance command in order.
func (e *Enumerator) Run() error {
	host := strings.TrimSpace(e.Target)
	if host == "" {
		return fmt.Errorf("--memcached --enum requires --target <ip|host>")
	}
	port := e.Port
	if port <= 0 {
		port = defaultPort
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	out := e.Out
	if out == nil {
		out = os.Stdout
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	fmt.Fprintf(out, "%s Target: %s  Timeout: %s\n", memcachedTag, addr, timeout)
	fmt.Fprintf(out, "%s Running reconnaissance\n", memcachedTag)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer conn.Close()
	fmt.Fprintf(out, "%s Connected to %s\n", memcachedTag, addr)

	s := &session{conn: conn, reader: bufio.NewReader(conn), timeout: timeout}

	for _, rc := range reconCommands {
		printSection(out, fmt.Sprintf("%s @ %s", rc.title, addr))
		lines, err := s.send(rc.command)
		if err != nil {
			printFail(out, fmt.Sprintf("%q failed: %v", rc.command, err))
			// A single failed command should not abort the whole run; the
			// server may simply disable that stat sub-command.
			if isFatal(err) {
				return err
			}
			continue
		}
		if len(lines) == 0 {
			printInfo(out, "no data returned")
			continue
		}
		for _, line := range lines {
			fmt.Fprintf(out, "- %s\n", formatStatLine(line))
		}
		if rc.command == "stats" {
			if summary := serverSummary(lines); summary != "" {
				printSuccess(out, summary)
			}
		}
	}

	// UDP amplification check (CVE-2018-1000115).
	// Runs after TCP recon so a closed UDP port does not skip the stats dump.
	runAmplificationTest(out, host, port, timeout)

	return nil
}

// send writes a text-protocol command and reads the response until a
// terminator line (END / VERSION / ERROR family) or EOF is reached.
func (s *session) send(command string) ([]string, error) {
	if err := s.conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, err
	}
	if _, err := s.conn.Write([]byte(command + "\r\n")); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	var lines []string
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF && len(lines) > 0 {
				return lines, nil
			}
			return lines, fmt.Errorf("read: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")

		switch {
		case line == "END":
			return lines, nil
		case line == "ERROR":
			return lines, fmt.Errorf("server returned ERROR (command not supported)")
		case strings.HasPrefix(line, "CLIENT_ERROR"), strings.HasPrefix(line, "SERVER_ERROR"):
			return lines, fmt.Errorf("%s", line)
		case strings.HasPrefix(line, "VERSION "):
			return append(lines, strings.TrimPrefix(line, "VERSION ")), nil
		default:
			lines = append(lines, line)
		}
	}
}

// isFatal reports whether an error means the connection can no longer be used.
func isFatal(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "read:") || strings.Contains(msg, "write:")
}

// formatStatLine renders "STAT key value" as "key: value" and leaves other
// lines (e.g. a bare version string) untouched.
func formatStatLine(line string) string {
	if rest, ok := strings.CutPrefix(line, "STAT "); ok {
		if i := strings.IndexByte(rest, ' '); i >= 0 {
			return fmt.Sprintf("%s: %s", rest[:i], rest[i+1:])
		}
		return rest
	}
	return line
}

// serverSummary extracts a one-line version/uptime overview from stats output.
func serverSummary(stats []string) string {
	var version, uptime string
	for _, stat := range stats {
		rest, ok := strings.CutPrefix(stat, "STAT ")
		if !ok {
			continue
		}
		key, val, found := strings.Cut(rest, " ")
		if !found {
			continue
		}
		switch key {
		case "version":
			version = val
		case "uptime":
			uptime = val
		}
	}
	if version == "" && uptime == "" {
		return ""
	}
	if uptime == "" {
		return fmt.Sprintf("Memcached %s", version)
	}
	return fmt.Sprintf("Memcached %s (uptime %s)", version, formatUptime(uptime))
}

func formatUptime(uptime string) string {
	secs, err := strconv.Atoi(uptime)
	if err != nil {
		return uptime
	}
	days := secs / 86400
	hours := (secs % 86400) / 3600
	minutes := (secs % 3600) / 60
	return fmt.Sprintf("%d days, %d hours, %d minutes", days, hours, minutes)
}

func printSection(w io.Writer, title string) {
	width := len(title) + 10
	line := strings.Repeat("=", width)
	pad := width - len(title) - 2
	left := pad / 2
	right := pad - left
	fmt.Fprintf(w, "\n %s\n", line)
	fmt.Fprintf(w, "|%s%s%s|\n", strings.Repeat(" ", left), title, strings.Repeat(" ", right))
	fmt.Fprintf(w, " %s\n", line)
}

func printInfo(w io.Writer, msg string) {
	fmt.Fprintf(w, "\x1b[33m[*]\x1b[0m %s\n", msg)
}

func printSuccess(w io.Writer, msg string) {
	fmt.Fprintf(w, "\x1b[32m[+]\x1b[0m %s\n", msg)
}

func printFail(w io.Writer, msg string) {
	fmt.Fprintf(w, "\x1b[31m[-]\x1b[0m %s\n", msg)
}
