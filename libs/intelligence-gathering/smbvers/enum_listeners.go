package smbvers

import (
	"fmt"
	"net"
	"time"
)

type listenerResult struct {
	Name    string
	Port    int
	Open    bool
	Timeout bool
}

func scanListeners(host string, timeout time.Duration) []listenerResult {
	checks := []struct {
		name string
		port int
	}{
		{"LDAP", 389},
		{"LDAPS", 636},
		{"SMB", portDirect},
		{"SMB over NetBIOS", portNBSS},
	}
	var out []listenerResult
	for _, c := range checks {
		out = append(out, probeTCP(host, c.port, c.name, timeout))
	}
	return out
}

func probeTCP(host string, port int, name string, timeout time.Duration) listenerResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return listenerResult{Name: name, Port: port, Timeout: true}
		}
		return listenerResult{Name: name, Port: port}
	}
	conn.Close()
	return listenerResult{Name: name, Port: port, Open: true}
}
