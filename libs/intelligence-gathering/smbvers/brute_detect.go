package smbvers

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
)

// BruteDetect holds invalid username/password probe results.
type BruteDetect struct {
	InvalidUser LoginOutcome
	InvalidPass LoginOutcome
}

// BruteFinding is one reported account outcome.
type BruteFinding struct {
	Username string
	Password string // display token: <blank>, <unknown>, or literal password
	Label    string // e.g. valid (disabled)
}

// BruteProgress receives live attempt notifications (optional).
type BruteProgress func(user, pass string)

// NewBruteDetect probes the target.
func NewBruteDetect(host string, port int, progress BruteProgress) (*BruteDetect, error) {
	if port <= 0 {
		port = portDirect
	}
	u := randomLoginString(8)
	p := randomLoginString(8)
	d := &BruteDetect{}
	var err error
	d.InvalidUser, err = tryLogin(host, port, u, p, "", progress)
	if err != nil {
		return nil, fmt.Errorf("invalid-username probe: %w", err)
	}
	d.InvalidPass, err = tryLogin(host, port, "Administrator", p, "", progress)
	if err != nil {
		return nil, fmt.Errorf("invalid-password probe: %w", err)
	}
	if d.InvalidUser == LoginSuccess || d.InvalidPass == LoginSuccess {
		return nil, fmt.Errorf("server accepts invalid credentials; cannot brute force safely")
	}
	return d, nil
}

func (d *BruteDetect) IsPositive(out LoginOutcome) bool {
	if out == LoginFail {
		return false
	}
	if out == d.InvalidPass {
		return false
	}
	if out == LoginAccountLocked {
		return false
	}
	return true
}

func (d *BruteDetect) IsInvalidAccount(out LoginOutcome) bool {
	return out != d.InvalidPass && out == d.InvalidUser
}

func (d *BruteDetect) IsLockout(out LoginOutcome) bool {
	return out == LoginAccountLocked || out == LoginAccountLockedNow
}

// ValidateBlank runs username validation with blank password check for one user.
func (d *BruteDetect) ValidateBlank(host string, port int, user, domain string, progress BruteProgress) (*BruteFinding, bool, error) {
	out, err := tryLogin(host, port, user, "", domain, progress)
	if err != nil {
		return nil, false, err
	}
	if d.IsInvalidAccount(out) {
		return nil, true, nil
	}
	if d.IsLockout(out) {
		return &BruteFinding{user, "<unknown>", "valid (locked)"}, false, nil
	}
	if !d.IsPositive(out) {
		return nil, false, nil
	}
	randPass := randomLoginString(14)
	randOut, err := tryLogin(host, port, user, randPass, domain, progress)
	if err != nil {
		return nil, false, err
	}
	if randOut == out {
		return &BruteFinding{user, "<anything>", shortOutcomeLabel(out)}, false, nil
	}
	return &BruteFinding{user, "<blank>", shortOutcomeLabel(out)}, false, nil
}

// BruteUser tries smb brute force password waves: username, reversed, passlist, then random lockout probes.
func (d *BruteDetect) BruteUser(host string, port int, user, domain string, passlist []string, progress BruteProgress) (*BruteFinding, error) {
	passwords := []string{user, reverseASCII(user)}
	passwords = append(passwords, passlist...)

	for _, pass := range passwords {
		out, err := tryLogin(host, port, user, pass, domain, progress)
		if err != nil {
			return nil, err
		}
		if d.IsLockout(out) {
			return &BruteFinding{user, "<unknown>", "valid (locked)"}, nil
		}
		if out == LoginFail || out == d.InvalidPass {
			continue
		}
		if d.IsPositive(out) {
			return &BruteFinding{user, displayPassword(pass), shortOutcomeLabel(out)}, nil
		}
	}

	for i := 0; i < 3; i++ {
		pass := randomLoginString(14)
		out, err := tryLogin(host, port, user, pass, domain, progress)
		if err != nil {
			return nil, err
		}
		if d.IsLockout(out) {
			return &BruteFinding{user, "<unknown>", "valid (locked)"}, nil
		}
	}
	return nil, nil
}

func tryLogin(host string, port int, user, pass, domain string, progress BruteProgress) (LoginOutcome, error) {
	if progress != nil {
		progress(user, displayPassword(pass))
	}
	out, err := TryLogin(host, port, user, pass, domain)
	if err != nil {
		return LoginFail, err
	}
	return out, nil
}

// RunBrute executes scanning against all users.
func RunBrute(host string, port int, domain string, users, passlist []string, progress BruteProgress, out io.Writer) error {
	if err := CheckSMBPort(host, port); err != nil {
		return err
	}
	detect, err := NewBruteDetect(host, port, progress)
	if err != nil {
		return err
	}

	findings := map[string]BruteFinding{}
	for _, user := range users {
		f, invalid, err := detect.ValidateBlank(host, port, user, domain, progress)
		if err != nil {
			return fmt.Errorf("%s/<blank>: %w", user, err)
		}
		if invalid {
			continue
		}
		if f != nil {
			findings[user] = *f
			continue
		}
		f2, err := detect.BruteUser(host, port, user, domain, passlist, progress)
		if err != nil {
			return fmt.Errorf("%s: %w", user, err)
		}
		if f2 != nil {
			findings[user] = *f2
		}
	}

	for _, user := range users {
		if f, ok := findings[user]; ok {
			fmt.Fprintf(out, "- %s:%s : %s\n", f.Username, f.Password, f.Label)
		}
	}
	return nil
}

func shortOutcomeLabel(o LoginOutcome) string {
	switch o {
	case LoginSuccess:
		return "valid"
	case LoginGuest:
		return "valid (guest only)"
	case LoginDisabled:
		return "valid (disabled)"
	case LoginAccountLocked, LoginAccountLockedNow:
		return "valid (locked)"
	case LoginNotGranted:
		return "valid (not granted)"
	case LoginExpired:
		return "valid (expired)"
	case LoginChangePassword:
		return "valid (password change required)"
	case LoginInvalidLogonHours:
		return "valid (logon hours)"
	case LoginInvalidWorkstation:
		return "valid (workstation)"
	default:
		return "valid"
	}
}

func displayPassword(pass string) string {
	if pass == "" {
		return "<blank>"
	}
	return pass
}

func reverseASCII(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func randomLoginString(n int) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
	b := make([]byte, n)
	for i := range b {
		v, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[v.Int64()]
	}
	return string(b)
}
