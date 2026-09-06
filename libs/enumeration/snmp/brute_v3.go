package snmp

import (
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	minV3PassLen      = 8
	v3ProbeTimeoutMS  = 300
)

// V3Bruter tries SNMPv3 username/password combinations across security levels.
type V3Bruter struct {
	Target      string
	Port        int
	UserList    string
	PassList    string
	RateLimitMS int
}

type v3Attempt struct {
	Level    string
	AuthName string
	PrivName string
	AuthPass string
	PrivPass string
}

type v3ValidUser struct {
	name       string
	noAuthOK   bool
	noAuthDesc string
}

var (
	v3AuthNames = []string{"MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}
	v3PrivNames = []string{"DES", "AES", "AES-192", "AES-256"}
)

func (b *V3Bruter) Run() error {
	host := strings.TrimSpace(b.Target)
	if host == "" {
		return fmt.Errorf("--snmp --brute --v3 requires --target <ip>")
	}
	userFile := strings.TrimSpace(b.UserList)
	if userFile == "" {
		return fmt.Errorf("--snmp --brute --v3 requires --userlist <file>")
	}
	passFile := strings.TrimSpace(b.PassList)
	if passFile == "" {
		return fmt.Errorf("--snmp --brute --v3 requires --passlist <file>")
	}

	users, err := readCommunities(userFile)
	if err != nil {
		return fmt.Errorf("read userlist: %w", err)
	}
	if len(users) == 0 {
		return fmt.Errorf("userlist is empty: %s", userFile)
	}
	passwords, err := readCommunities(passFile)
	if err != nil {
		return fmt.Errorf("read passlist: %w", err)
	}
	if len(passwords) == 0 {
		return fmt.Errorf("passlist is empty: %s", passFile)
	}

	ip := resolveHost(host)
	if ip == "" {
		return fmt.Errorf("resolve %q", host)
	}

	port := b.Port
	if port <= 0 {
		port = defaultPort
	}

	client, err := newV3Client(ip, port, v3ProbeTimeout)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer client.Close()

	fmt.Fprintf(os.Stdout, "%s Target: %s:%d  Users: %d  Passwords: %d  Timeout: %dms  Version: SNMPv3\n",
		snmpTag, ip, port, len(users), len(passwords), v3ProbeTimeoutMS)

	// Phase 1: enumerate SNMPv3 users (per-user engine discovery).
	fmt.Fprintf(os.Stdout, "\n%s Enumerating SNMPv3 users...\n", snmpTag)

	type validUser = v3ValidUser
	var validUsers []validUser
	for _, user := range users {
		outcome, desc := client.enumUser(user)
		switch outcome {
		case v3OutcomeUnknownUser:
			continue
		case v3OutcomeFail:
			if len(validUsers) == 0 && client.discoveryFailed() {
				break
			}
			continue
		case v3OutcomeOK:
			validUsers = append(validUsers, validUser{name: user, noAuthOK: true, noAuthDesc: desc})
			printV3FoundUser(ip, user)
		case v3OutcomeUserExists:
			validUsers = append(validUsers, validUser{name: user})
			printV3FoundUser(ip, user)
		}
	}
	if len(validUsers) == 0 {
		fmt.Fprintf(os.Stdout, "%s No valid SNMPv3 users found\n", snmpTag)
		return nil
	}

	client.learnEngineFromUsers(namesOfValidUsers(validUsers))
	if !client.hasEngine() {
		fmt.Fprintf(os.Stdout, "%s Warning: SNMP engine ID not learned; skipping password tests\n", snmpTag)
		return nil
	}

	var found int
	for _, vu := range validUsers {
		if vu.noAuthOK {
			found++
			printV3Found(ip, vu.name, v3Attempt{Level: "noAuthNoPriv"}, vu.noAuthDesc)
		}
	}

	// Phase 2: auth passwords.
	fmt.Fprintf(os.Stdout, "\n%s Testing authentication passphrases (authNoPriv)...\n", snmpTag)
	for _, authName := range v3AuthNames {
		for _, vu := range validUsers {
			for _, pass := range passwords {
				if len(pass) < minV3PassLen {
					continue
				}
				att := v3Attempt{Level: "authNoPriv", AuthName: authName, AuthPass: pass}
				if ok, desc := tryV3Cred(client, vu.name, att); ok {
					found++
					printV3Found(ip, vu.name, att, desc)
				}
			}
		}
	}

	// Phase 3: auth + privacy passphrases.
	fmt.Fprintf(os.Stdout, "\n%s Testing privacy passphrases (authPriv)...\n", snmpTag)
	for _, authName := range v3AuthNames {
		for _, privName := range v3PrivNames {
			for _, vu := range validUsers {
				for _, authPass := range passwords {
					if len(authPass) < minV3PassLen {
						continue
					}
					for _, privPass := range passwords {
						if len(privPass) < minV3PassLen {
							continue
						}
						att := v3Attempt{
							Level:    "authPriv",
							AuthName: authName,
							PrivName: privName,
							AuthPass: authPass,
							PrivPass: privPass,
						}
						if ok, desc := tryV3Cred(client, vu.name, att); ok {
							found++
							printV3Found(ip, vu.name, att, desc)
						}
					}
				}
			}
		}
	}

	if found == 0 {
		fmt.Fprintf(os.Stdout, "%s No valid SNMPv3 credentials found\n", snmpTag)
	}
	return nil
}

func resolveHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	for _, a := range addrs {
		if v4 := a.To4(); v4 != nil {
			return v4.String()
		}
	}
	return addrs[0].String()
}

func v3OutcomeName(o v3ProbeOutcome) string {
	switch o {
	case v3OutcomeOK:
		return "ok"
	case v3OutcomeUnknownUser:
		return "unknownUser"
	case v3OutcomeUserExists:
		return "userExists"
	default:
		return "fail"
	}
}

func namesOfValidUsers(valids []v3ValidUser) []string {
	names := make([]string, len(valids))
	for i, vu := range valids {
		names[i] = vu.name
	}
	return names
}

func buildV3Attempts(passwords []string) []v3Attempt {
	var out []v3Attempt
	for _, authName := range v3AuthNames {
		for _, pass := range passwords {
			if len(pass) < minV3PassLen {
				continue
			}
			out = append(out, v3Attempt{
				Level:    "authNoPriv",
				AuthName: authName,
				AuthPass: pass,
			})
		}
		for _, privName := range v3PrivNames {
			for _, authPass := range passwords {
				if len(authPass) < minV3PassLen {
					continue
				}
				for _, privPass := range passwords {
					if len(privPass) < minV3PassLen {
						continue
					}
					out = append(out, v3Attempt{
						Level:    "authPriv",
						AuthName: authName,
						PrivName: privName,
						AuthPass: authPass,
						PrivPass: privPass,
					})
				}
			}
		}
	}
	return out
}

func tryV3Cred(client *v3Client, user string, att v3Attempt) (bool, string) {
	outcome, desc := client.probe(user, att)
	return outcome == v3OutcomeOK, desc
}

func printV3FoundUser(host, user string) {
	fmt.Printf("- %sFound user: %s [%s]\x1b[0m\n", foundTag, user, host)
}

func printV3Found(host, user string, att v3Attempt, sysDescr string) {
	var detail string
	switch att.Level {
	case "noAuthNoPriv":
		detail = fmt.Sprintf("user=%s level=noAuthNoPriv", user)
	case "authNoPriv":
		detail = fmt.Sprintf("user=%s level=authNoPriv auth=%s pass=%s", user, att.AuthName, att.AuthPass)
	case "authPriv":
		detail = fmt.Sprintf("user=%s level=authPriv auth=%s priv=%s authPass=%s privPass=%s",
			user, att.AuthName, att.PrivName, att.AuthPass, att.PrivPass)
	}
	fmt.Printf("- %sFound credentials: %s\x1b[0m\n", foundTag, detail)
	fmt.Fprintf(os.Stdout, "- POC: %s\n", v3POCLine(host, user, att))
	if sysDescr != "" {
		fmt.Fprintf(os.Stdout, "%s   sysDescr: %s\n", snmpTag, sysDescr)
	}
	fmt.Println()
}

func v3POCLine(host, user string, att v3Attempt) string {
	switch att.Level {
	case "noAuthNoPriv":
		return fmt.Sprintf("snmpwalk -v3 -u %s %s iso.3.6.1.2.1.1.1.0", user, host)
	case "authNoPriv":
		return fmt.Sprintf("snmpwalk -v3 -u %s -A %s %s -l authNoPriv -a %s iso.3.6.1.2.1.1.1.0",
			user, att.AuthPass, host, att.AuthName)
	default:
		return fmt.Sprintf("snmpwalk -v3 -u %s -A %s -a %s -X %s -x %s %s -l authPriv iso.3.6.1.2.1.1.1.0",
			user, att.AuthPass, att.AuthName, att.PrivPass, att.PrivName, host)
	}
}
