package smb

import (
	"os"
	"strings"

	"netdestruct/libs/intelligence-gathering/smbvers"
)

// Enumerator runs SMB enumeration against one host.
type Enumerator struct {
	Target   string
	Port     int
	Username string
	Password string
}

func (e *Enumerator) Run() error {
	host, err := parseSingleTarget(e.Target)
	if err != nil {
		return err
	}
	port := e.Port
	if port <= 0 {
		port = 445
	}
	user, domain := parseSMBAccount(e.Username)
	return smbvers.RunSMBEnum(host, port, user, e.Password, domain, os.Stdout)
}

// parseSMBAccount splits DOMAIN\user or DOMAIN/user; plain names use an empty domain.
func parseSMBAccount(account string) (user, domain string) {
	account = strings.TrimSpace(account)
	if account == "" {
		return "", ""
	}
	if i := strings.LastIndex(account, `\`); i >= 0 {
		return account[i+1:], account[:i]
	}
	if i := strings.Index(account, `/`); i >= 0 {
		return account[i+1:], account[:i]
	}
	return account, ""
}
