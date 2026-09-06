package ftp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPort = 21
	dialTimeout = 10 * time.Second
	rwTimeout   = 15 * time.Second
)

// Client performs FTP enumeration and brute forcing using native TCP sockets (RFC 959).
type Client struct {
	Server   string // host or host:port
	Port     int    // override port; ignored when Server already contains a port
	Anon     bool   // check anonymous login
	Features bool   // list server features via FEAT
	UserList string // path to username wordlist for brute force
	PassList string // path to password wordlist for brute force
}

// Run dispatches based on which flags are set.
func (c *Client) Run() error {
	addr, display := c.serverAddrAndDisplay()

	if c.UserList != "" || c.PassList != "" {
		return c.bruteForce(addr, display)
	}
	if !c.Anon && !c.Features {
		return fmt.Errorf("specify --anon, --features, or --userlist/--passlist")
	}

	fc, err := dialFTP(addr)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", display, err)
	}
	defer fc.quit()

	fmt.Printf("FTP server:   %s\n", display)
	if fc.Greeting != "" {
		fmt.Printf("Banner:       %s\n", fc.Greeting)
	}
	fmt.Println()

	if c.Anon {
		ok, err := fc.login("anonymous", "anonymous@")
		if err != nil {
			return err
		}
		if ok {
			fmt.Println("\x1b[32m[+] Anonymous login ALLOWED\x1b[0m")
			if path, ok2 := fc.pwd(); ok2 {
				fmt.Printf("    Working directory: %s\n", path)
			}
		} else {
			fmt.Println("[-] Anonymous login DENIED")
		}
		if c.Features {
			fmt.Println()
		}
	}

	if c.Features {
		printFeatures(fc)
	}

	return nil
}

// bruteForce tries every (username, password) combination from the provided lists.
// For each username, iteration stops after the first matching password.
func (c *Client) bruteForce(addr, display string) error {
	if c.UserList == "" {
		return fmt.Errorf("--userlist is required for brute force")
	}
	if c.PassList == "" {
		return fmt.Errorf("--passlist is required for brute force")
	}

	users, err := readLines(c.UserList)
	if err != nil {
		return fmt.Errorf("userlist: %w", err)
	}
	passes, err := readLines(c.PassList)
	if err != nil {
		return fmt.Errorf("passlist: %w", err)
	}

	fmt.Printf("FTP server:   %s\n", display)
	fmt.Printf("Users: %d  Passwords: %d\n\n", len(users), len(passes))

	tried, found := 0, 0
	for _, user := range users {
		for _, pass := range passes {
			tried++

			fc, dialErr := dialFTP(addr)
			if dialErr != nil {
				fmt.Fprintf(os.Stderr, "[!] dial: %v\n", dialErr)
				time.Sleep(time.Second)
				continue
			}

			ok, loginErr := fc.login(user, pass)
			fc.quit()

			if loginErr != nil {
				continue
			}
			if ok {
				found++
				fmt.Printf("\x1b[32m[+] %s : %s\x1b[0m\n", user, pass)
				break // move to next user
			}

			if tried%500 == 0 {
				fmt.Fprintf(os.Stderr, "\r%d tried...", tried)
			}
		}
	}

	fmt.Printf("\nTried: %d  Found: %d\n", tried, found)
	return nil
}

func printFeatures(fc *ftpConn) {
	code, msg, err := fc.cmd("FEAT")
	if err != nil {
		fmt.Printf("  [!] FEAT: %v\n", err)
		return
	}
	switch code {
	case 211:
		fmt.Println("[+] Server features:")
		for _, line := range strings.Split(strings.TrimRight(msg, "\n"), "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.EqualFold(line, "end") {
				fmt.Printf("    %s\n", line)
			}
		}
	case 500, 502:
		fmt.Println("[-] FEAT not supported by this server")
	default:
		fmt.Printf("[!] FEAT returned %d: %s\n", code, strings.TrimSpace(msg))
	}
}

// ── address helpers ───────────────────────────────────────────────────────────

func (c *Client) serverAddr() string {
	if _, _, err := net.SplitHostPort(c.Server); err == nil {
		return c.Server // already has port
	}
	port := c.Port
	if port == 0 {
		port = defaultPort
	}
	return net.JoinHostPort(c.Server, strconv.Itoa(port))
}

func (c *Client) serverAddrAndDisplay() (addr, display string) {
	addr = c.serverAddr()
	host, _, _ := net.SplitHostPort(addr)
	if net.ParseIP(host) != nil {
		display = addr
		return
	}
	// hostname — resolve and show IP in parentheses
	if ips, err := net.LookupHost(host); err == nil && len(ips) > 0 {
		display = fmt.Sprintf("%s (%s)", addr, ips[0])
	} else {
		display = addr
	}
	return
}

// ── FTP control connection ────────────────────────────────────────────────────

type ftpConn struct {
	conn     net.Conn
	r        *bufio.Reader
	Greeting string
}

func dialFTP(addr string) (*ftpConn, error) {
	c, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, err
	}
	fc := &ftpConn{conn: c, r: bufio.NewReader(c)}
	code, msg, err := fc.readResp()
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("greeting: %w", err)
	}
	if code != 220 {
		c.Close()
		return nil, fmt.Errorf("unexpected greeting %d: %s", code, strings.TrimSpace(msg))
	}
	fc.Greeting = strings.TrimSpace(msg)
	return fc, nil
}

// cmd sends a command and reads the response.
func (fc *ftpConn) cmd(s string) (int, string, error) {
	fc.conn.SetDeadline(time.Now().Add(rwTimeout))
	if _, err := fmt.Fprintf(fc.conn, "%s\r\n", s); err != nil {
		return 0, "", err
	}
	return fc.readResp()
}

// readResp reads one complete FTP response (possibly multi-line).
// RFC 959 §4.2: single-line "NNN<SP>text", multi-line starts "NNN-text" and ends "NNN<SP>text".
func (fc *ftpConn) readResp() (int, string, error) {
	fc.conn.SetDeadline(time.Now().Add(rwTimeout))
	line, err := fc.r.ReadString('\n')
	if err != nil {
		return 0, "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 3 {
		return 0, "", fmt.Errorf("short response: %q", line)
	}

	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, "", fmt.Errorf("parse response code: %w", err)
	}

	if len(line) < 4 || line[3] != '-' {
		msg := ""
		if len(line) > 4 {
			msg = line[4:]
		}
		return code, msg, nil
	}

	// Multi-line: accumulate until "NNN <text>" terminator
	var sb strings.Builder
	if len(line) > 4 {
		sb.WriteString(line[4:])
		sb.WriteByte('\n')
	}
	term := fmt.Sprintf("%d ", code)
	for {
		fc.conn.SetDeadline(time.Now().Add(rwTimeout))
		line, err = fc.r.ReadString('\n')
		if err != nil {
			return 0, "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, term) {
			if len(line) > 4 {
				sb.WriteString(line[4:])
			}
			break
		}
		// Continuation lines optionally start with a leading space (RFC 959 §4.2)
		sb.WriteString(strings.TrimPrefix(line, " "))
		sb.WriteByte('\n')
	}
	return code, sb.String(), nil
}

func (fc *ftpConn) login(user, pass string) (bool, error) {
	code, _, err := fc.cmd("USER " + user)
	if err != nil {
		return false, err
	}
	switch code {
	case 230:
		return true, nil // logged in without password (rare)
	case 331:
		code, _, err = fc.cmd("PASS " + pass)
		if err != nil {
			return false, err
		}
		return code == 230, nil
	default:
		return false, nil // 530 or other rejection at username stage
	}
}

// pwd returns the server's current working directory.
func (fc *ftpConn) pwd() (string, bool) {
	code, msg, err := fc.cmd("PWD")
	if err != nil || code != 257 {
		return "", false
	}
	// msg: `"/some/path" is the current directory`
	if i := strings.Index(msg, `"`); i >= 0 {
		rest := msg[i+1:]
		if j := strings.Index(rest, `"`); j >= 0 {
			return rest[:j], true
		}
	}
	return strings.TrimSpace(msg), true
}

func (fc *ftpConn) quit() {
	fc.cmd("QUIT")
	fc.conn.Close()
}

// ── file reader ───────────────────────────────────────────────────────────────

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimRight(sc.Text(), "\r"); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}
