package smb

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"netdestruct/libs/intelligence-gathering/smbvers"
)

const smbTag = "\x1b[33m[SMB]\x1b[0m"

// Bruter runs SMB username/password guessing against one host.
type Bruter struct {
	Target   string
	Port     int
	Domain   string
	UserList string
	PassList string
}

func (b *Bruter) Run() error {
	host, err := parseSingleTarget(b.Target)
	if err != nil {
		return err
	}

	users, usersBuiltin, err := b.loadUsers()
	if err != nil {
		return err
	}
	passes, passesBuiltin, err := b.loadPasswords()
	if err != nil {
		return err
	}

	port := b.Port
	if port <= 0 {
		port = 445
	}

	fmt.Printf("%s Target: %s:%d\n", smbTag, host, port)
	if usersBuiltin {
		fmt.Printf("%s Using built-in default account list\n", smbTag)
	} else if passesBuiltin && b.PassList == "" {
		fmt.Printf("%s Using built-in default password list\n", smbTag)
	}
	fmt.Printf("%s Users: %d  Passwords: %d\n", smbTag, len(users), len(passes))
	fmt.Printf("Testing users: %s\n\n", strings.Join(users, ", "))

	progress := func(user, pass string) {
		fmt.Fprintf(os.Stderr, "%s trying %s/%s\n", smbTag, user, pass)
	}

	if err := smbvers.RunBrute(host, port, b.Domain, users, passes, progress, os.Stdout); err != nil {
		return err
	}
	return nil
}

func (b *Bruter) loadUsers() (users []string, builtin bool, err error) {
	if b.UserList == "" {
		return append([]string(nil), defaultSMBUsernames...), true, nil
	}
	users, err = readLines(b.UserList)
	if err != nil {
		return nil, false, fmt.Errorf("userlist: %w", err)
	}
	return users, false, nil
}

func (b *Bruter) loadPasswords() (passes []string, builtin bool, err error) {
	if b.PassList != "" {
		passes, err = readLines(b.PassList)
		if err != nil {
			return nil, false, fmt.Errorf("passlist: %w", err)
		}
		return passes, false, nil
	}
	if b.UserList == "" {
		return nil, true, nil
	}
	return append([]string(nil), defaultSMBPasswords...), true, nil
}

func parseSingleTarget(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", fmt.Errorf("--target is required")
	}
	if strings.ContainsAny(spec, ",-/") {
		return "", fmt.Errorf("SMB brute force requires a single IP in --target")
	}
	if ip := net.ParseIP(spec); ip != nil && ip.To4() != nil {
		return ip.String(), nil
	}
	return "", fmt.Errorf("invalid target IP %q", spec)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}
