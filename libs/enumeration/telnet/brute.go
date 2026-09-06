package telnet

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

const (
	foundTag = "\x1b[32m"

	// TASKS=16, MAXTASKS=64.
	defaultTasks = 16
	maxTasks     = 64
	bruteTimeout = 35 * time.Second
	readSlice    = 2 * time.Second

	optEcho  = 1
	optSGA   = 3
	optTType = 24
	optNAWS  = 31
)

var (
	ansiCSI       = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b[()].|\x1b.`)
	shellAtPrompt = regexp.MustCompile(`(?m)[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+[:~][^\r\n]*[$#%>]\s*$`)
	passPromptRe  = regexp.MustCompile(`(?m)(^|\s)pass:\s*$`)
)

// Bruter guesses Telnet credentials.
// Each worker owns one TCP session.
type Bruter struct {
	Target   string
	Port     int
	UserList string
	PassList string
	Threads  int // (default 16, max 64)
	Timeout  time.Duration
	Out      io.Writer
}

type credJob struct {
	user string
	pass string
}

// Run tries user×password pairs against the Telnet service.
func (b *Bruter) Run() error {
	host := strings.TrimSpace(b.Target)
	if host == "" {
		return fmt.Errorf("--telnet --brute requires --target <ip>")
	}
	if strings.TrimSpace(b.UserList) == "" {
		return fmt.Errorf("--telnet --brute requires --userlist <file>")
	}
	if strings.TrimSpace(b.PassList) == "" {
		return fmt.Errorf("--telnet --brute requires --passlist <file>")
	}

	users, err := readWordList(b.UserList)
	if err != nil {
		return fmt.Errorf("userlist: %w", err)
	}
	passes, err := readWordList(b.PassList)
	if err != nil {
		return fmt.Errorf("passlist: %w", err)
	}
	if len(users) == 0 {
		return fmt.Errorf("userlist is empty: %s", b.UserList)
	}
	if len(passes) == 0 {
		return fmt.Errorf("passlist is empty: %s", b.PassList)
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
	totalPairs := len(users) * len(passes)
	if tasks > totalPairs {
		tasks = totalPairs
	}
	if tasks < 1 {
		tasks = 1
	}
	timeout := b.Timeout
	if timeout <= 0 {
		timeout = bruteTimeout
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
	fmt.Fprintf(out, "%s Target: %s  Users: %d  Passwords: %d  Threads: %d\n",
		telnetTag, addr, len(users), len(passes), tasks)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobs := make(chan credJob, tasks*2)
	var wg sync.WaitGroup
	var tried atomic.Int64
	var foundCount atomic.Int64
	var printMu sync.Mutex
	var foundUsers sync.Map

	worker := func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case job, ok := <-jobs:
				if !ok {
					return
				}
				if _, done := foundUsers.Load(job.user); done {
					continue
				}
				tried.Add(1)
				okLogin, err := tryLogin(addr, timeout, job.user, job.pass)
				if err != nil || !okLogin {
					continue
				}
				if _, loaded := foundUsers.LoadOrStore(job.user, struct{}{}); loaded {
					continue
				}
				foundCount.Add(1)
				printMu.Lock()
				fmt.Fprintf(out, "- %sFound login/password pair: %s / %s\x1b[0m\n",
					foundTag, job.user, job.pass)
				printMu.Unlock()
			}
		}
	}

	wg.Add(tasks)
	for i := 0; i < tasks; i++ {
		go worker()
	}

	go func() {
		defer close(jobs)
		for _, user := range users {
			for _, pass := range passes {
				if _, done := foundUsers.Load(user); done {
					break
				}
				select {
				case <-ctx.Done():
					return
				case jobs <- credJob{user: user, pass: pass}:
				}
			}
		}
	}()

	wg.Wait()
	fmt.Fprintf(out, "%s Done: %d found / %d tried\n",
		telnetTag, foundCount.Load(), tried.Load())
	return nil
}

func readWordList(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}
	return out, sc.Err()
}

type telnetSession struct {
	conn    net.Conn
	timeout time.Duration
	pending []byte
}

func tryLogin(addr string, timeout time.Duration, user, pass string) (bool, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	s := &telnetSession{conn: conn, timeout: timeout}

	banner, err := s.waitForPrompt(timeout)
	if err != nil {
		return false, err
	}
	lower := normalize(banner)

	passwordOnly := isPasswordPrompt(lower) && !isLoginPromptBanner(lower)
	if !passwordOnly && !isLoginPromptBanner(lower) && !isPasswordPrompt(lower) {
		return false, fmt.Errorf("no login/password prompt")
	}

	if !passwordOnly {
		if err := s.sendCred(user); err != nil {
			return false, err
		}
		resp, body, err := s.recvClassify(timeout, false)
		switch resp {
		case respSuccess:
			return true, nil
		case respFailure:
			return false, nil
		case respPassword:
			// continue
		default:
			// Some banners are slow; one more short wait for Password:
			more, _ := s.recvUntil(timeout/3, func(t string) bool {
				return isPasswordPrompt(normalize(t)) || isLoginPrompt(normalize(t)) || isFailure(normalize(t))
			})
			body += more
			resp = classifyResponse(normalize(body), false)
			if resp == respSuccess {
				return true, nil
			}
			if resp == respFailure {
				return false, nil
			}
			if resp != respPassword {
				if err != nil {
					return false, err
				}
				return false, nil
			}
		}
	}

	if err := s.sendCred(pass); err != nil {
		return false, err
	}
	// Ubuntu MOTD (update-notifier, ESM, …) can take many seconds after auth
	// before "Welcome to …" appears — keep reading for the full timeout.
	resp, body, _ := s.recvClassify(timeout, true)
	if resp == respSuccess {
		return true, nil
	}
	if resp == respFailure || resp == respPassword {
		return false, nil
	}
	// Last resort: if the PTY is already a shell but silent, confirm with id(1).
	if strings.TrimSpace(stripANSI(body)) != "" && s.probeShell(6*time.Second) {
		return true, nil
	}
	return false, nil
}

// waitForPrompt negotiates options and reads until a login/password prompt.
func (s *telnetSession) waitForPrompt(timeout time.Duration) (string, error) {
	var text strings.Builder
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		left := time.Until(deadline)
		if left <= 0 {
			break
		}
		slice := readSlice
		if left < slice {
			slice = left
		}
		chunk, err := s.readMore(slice)
		if len(chunk) > 0 {
			plain, replies := negotiate(chunk)
			if len(replies) > 0 {
				_ = s.conn.SetWriteDeadline(time.Now().Add(s.timeout))
				_, _ = s.conn.Write(replies)
			}
			text.WriteString(strings.ReplaceAll(plain, "\x00", " "))
			low := normalize(text.String())
			if strings.Contains(low, "ress enter") {
				_, _ = s.conn.Write([]byte("\r\n"))
				text.Reset()
				continue
			}
			if isLoginPromptBanner(low) || isPasswordPrompt(low) {
				return text.String(), nil
			}
			continue
		}
		// Short-read deadlines are normal between IAC and the login banner.
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			if text.Len() == 0 {
				return "", err
			}
			break
		}
	}
	return text.String(), nil
}

// negotiate responds like a typical Unix telnet client (SGA/ECHO/TTYPE/NAWS).
func negotiate(data []byte) (plain string, replies []byte) {
	var text strings.Builder
	i := 0
	for i < len(data) {
		if data[i] != iac {
			text.WriteByte(data[i])
			i++
			continue
		}
		if i+1 >= len(data) {
			break
		}
		cmd := data[i+1]
		switch cmd {
		case will, wont, doCmd, dont:
			if i+2 >= len(data) {
				return text.String(), replies
			}
			opt := data[i+2]
			switch cmd {
			case will:
				if opt == optEcho || opt == optSGA {
					replies = append(replies, iac, doCmd, opt)
				} else {
					replies = append(replies, iac, dont, opt)
				}
			case doCmd:
				switch opt {
				case optSGA:
					replies = append(replies, iac, will, opt)
				case optTType:
					replies = append(replies, iac, will, opt)
				case optNAWS:
					replies = append(replies,
						iac, will, opt,
						iac, sb, optNAWS, 0, 80, 0, 24, iac, se,
					)
				default:
					replies = append(replies, iac, wont, opt)
				}
			case wont:
				replies = append(replies, iac, dont, opt)
			case dont:
				replies = append(replies, iac, wont, opt)
			}
			i += 3
		case sb:
			if i+3 < len(data) && data[i+2] == optTType && data[i+3] == 1 {
				// SB TERMINAL-TYPE SEND -> IS xterm
				replies = append(replies, iac, sb, optTType, 0)
				replies = append(replies, []byte("xterm")...)
				replies = append(replies, iac, se)
			}
			i += 2
			for i < len(data)-1 {
				if data[i] == iac && data[i+1] == se {
					i += 2
					break
				}
				i++
			}
		case iac:
			text.WriteByte(iac)
			i += 2
		default:
			i += 2
		}
	}
	return text.String(), replies
}

func (s *telnetSession) readMore(slice time.Duration) ([]byte, error) {
	if len(s.pending) > 0 {
		out := s.pending
		s.pending = nil
		return out, nil
	}
	_ = s.conn.SetReadDeadline(time.Now().Add(slice))
	buf := make([]byte, 4096)
	n, err := s.conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}

func (s *telnetSession) recvUntil(maxWait time.Duration, done func(string) bool) (string, error) {
	var text strings.Builder
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		left := time.Until(deadline)
		if left <= 0 {
			break
		}
		if left > readSlice {
			left = readSlice
		}
		chunk, err := s.readMore(left)
		if len(chunk) > 0 {
			plain, replies := negotiate(chunk)
			if len(replies) > 0 {
				_, _ = s.conn.Write(replies)
			}
			text.WriteString(strings.ReplaceAll(plain, "\x00", " "))
			if done(text.String()) {
				break
			}
		}
		if err != nil && len(chunk) == 0 {
			break
		}
	}
	return text.String(), nil
}

type responseKind int

const (
	respNone responseKind = iota
	respSuccess
	respFailure
	respPassword
)

func (s *telnetSession) recvClassify(maxWait time.Duration, afterPassword bool) (responseKind, string, error) {
	var text strings.Builder
	deadline := time.Now().Add(maxWait)
	var lastErr error
	idleRounds := 0

	for time.Now().Before(deadline) {
		left := time.Until(deadline)
		if left <= 0 {
			break
		}
		slice := readSlice
		if left < slice {
			slice = left
		}
		chunk, err := s.readMore(slice)
		lastErr = err
		if len(chunk) > 0 {
			idleRounds = 0
			plain, replies := negotiate(chunk)
			if len(replies) > 0 {
				_, _ = s.conn.Write(replies)
			}
			text.WriteString(strings.ReplaceAll(plain, "\x00", " "))
			kind := classifyResponse(normalize(text.String()), afterPassword)
			if kind != respNone {
				return kind, text.String(), nil
			}
			continue
		}
		idleRounds++
		if idleRounds >= 2 && text.Len() > 0 {
			kind := classifyResponse(normalize(text.String()), afterPassword)
			if kind != respNone {
				return kind, text.String(), nil
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Now().Before(deadline) {
				continue
			}
			break
		}
	}
	kind := classifyResponse(normalize(text.String()), afterPassword)
	return kind, text.String(), lastErr
}

// probeShell confirms an interactive shell after an inconclusive post-password read.
// It must not treat text echoed at a login/password prompt as success.
func (s *telnetSession) probeShell(wait time.Duration) bool {
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.timeout))
	_, _ = s.conn.Write([]byte("id\r\n"))
	body, _ := s.recvUntil(wait/2, func(t string) bool {
		low := normalize(t)
		return strings.Contains(low, "uid=") ||
			isFailure(low) ||
			isLoginPrompt(low) ||
			isPasswordPrompt(low)
	})
	low := normalize(body)
	if isFailure(low) || isLoginPrompt(low) || isPasswordPrompt(low) {
		return false
	}
	if strings.Contains(low, "uid=") {
		return true
	}

	_, _ = s.conn.Write([]byte("echo NDTELNET_OK\r\n"))
	extra, _ := s.recvUntil(wait/2, func(t string) bool {
		low := normalize(t)
		if isFailure(low) || isLoginPrompt(low) || isPasswordPrompt(low) {
			return true
		}
		for _, line := range strings.Split(stripANSI(t), "\n") {
			if strings.TrimSpace(strings.TrimSuffix(line, "\r")) == "NDTELNET_OK" {
				return true
			}
		}
		return false
	})
	combined := body + extra
	low = normalize(combined)
	if isFailure(low) || isLoginPrompt(low) || isPasswordPrompt(low) {
		return false
	}
	for _, line := range strings.Split(stripANSI(combined), "\n") {
		if strings.TrimSpace(strings.TrimSuffix(line, "\r")) == "NDTELNET_OK" {
			return true
		}
	}
	return false
}

// sendCred uses NVT end-of-line CRLF (what interactive telnet / login expect).
func (s *telnetSession) sendCred(value string) error {
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.timeout))
	_, err := s.conn.Write([]byte(value + "\r\n"))
	return err
}

func stripANSI(s string) string {
	return ansiCSI.ReplaceAllString(s, "")
}

func normalize(s string) string {
	return strings.ToLower(stripANSI(s))
}

func isPasswordPrompt(buffer string) bool {
	return strings.Contains(buffer, "asswor") ||
		strings.Contains(buffer, "asscode") ||
		strings.Contains(buffer, "ennwort") ||
		strings.Contains(buffer, "passwd:") ||
		strings.Contains(buffer, "pwd:") ||
		strings.Contains(buffer, "pin:") ||
		strings.Contains(buffer, "enter password") ||
		strings.Contains(buffer, "password for") ||
		passPromptRe.FindString(buffer) != ""
}

func isLoginPrompt(buffer string) bool {
	if strings.Contains(buffer, "ogin:") && !strings.Contains(buffer, "last login") {
		return true
	}
	return strings.Contains(buffer, "sername:")
}

func isLoginPromptBanner(buffer string) bool {
	if isLoginPrompt(buffer) {
		return true
	}
	return strings.Contains(buffer, "user:") ||
		strings.Contains(buffer, "login:") ||
		strings.Contains(buffer, "user id:") ||
		strings.Contains(buffer, "userid:") ||
		strings.Contains(buffer, "account:") ||
		strings.Contains(buffer, "user access verification") ||
		strings.Contains(buffer, "user name:")
}

func isFailure(buffer string) bool {
	phrases := []string{
		"login incorrect", "login failed", "login failure",
		"incorrect password", "incorrect username", "incorrect login",
		"invalid password", "invalid username", "invalid login", "invalid user",
		"bad password", "bad passwords", "wrong password", "wrong login", "wrong username",
		"authentication failed", "authentication failure", "authentication error",
		"authorization failed", "access denied", "permission denied",
		"unable to authenticate",
		"too many attempts", "too many failures", "too many tries", "too many logins",
		"user was locked", "account locked", "account is locked", "ip has been blocked",
		"cannot log on",
		"username or password", "user name or password", "password is incorrect",
		"bye-bye", "% bad passwords", "% authentication failed", "% login failure",
		"local: authentication failure",
		"this account is currently not available",
	}
	for _, p := range phrases {
		if strings.Contains(buffer, p) {
			return true
		}
	}
	return false
}

func hasShellPrompt(buffer string) bool {
	clean := stripANSI(buffer)
	if shellAtPrompt.MatchString(clean) {
		return true
	}
	// Trailing prompt char on last non-empty line.
	lines := strings.Split(clean, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimRightFunc(lines[i], unicode.IsSpace)
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		last := line[len(line)-1]
		return last == '$' || last == '#' || last == '>' || last == '%'
	}
	runes := []rune(strings.TrimRightFunc(clean, unicode.IsSpace))
	if len(runes) == 0 {
		return false
	}
	last := runes[len(runes)-1]
	return last == '$' || last == '#' || last == '>' || last == '%'
}

func isSuccess(buffer string, afterPassword bool) bool {
	if hasShellPrompt(buffer) {
		return true
	}
	if !afterPassword {
		return false
	}
	return strings.Contains(buffer, "last login") ||
		strings.Contains(buffer, "login correct") ||
		strings.Contains(buffer, "welcome to") ||
		strings.Contains(buffer, "uid=")
}

func classifyResponse(buffer string, afterPassword bool) responseKind {
	if strings.TrimSpace(buffer) == "" {
		return respNone
	}
	if isFailure(buffer) {
		return respFailure
	}
	// After password, prefer success cues over a stale "password" word in MOTD.
	if afterPassword && isSuccess(buffer, true) {
		return respSuccess
	}
	if isLoginPrompt(buffer) {
		return respFailure
	}
	if isPasswordPrompt(buffer) {
		return respPassword
	}
	if isSuccess(buffer, afterPassword) {
		return respSuccess
	}
	return respNone
}
