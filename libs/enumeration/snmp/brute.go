package snmp

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const foundTag = "\x1b[32m" // green for valid community lines

// Bruter tries SNMPv2c community strings from a wordlist against one or more hosts.
// Valid communities are printed in green and followed by an snmpwalk (SNMPv2c).
type Bruter struct {
	Target      string
	Port        int
	PassList    string
	RateLimitMS int
}

func (b *Bruter) Run() error {
	spec := strings.TrimSpace(b.Target)
	if spec == "" {
		return fmt.Errorf("--snmp --brute requires --target <ip|range>")
	}
	passFile := strings.TrimSpace(b.PassList)
	if passFile == "" {
		return fmt.Errorf("--snmp --brute requires --passlist <file>")
	}

	communities, err := readCommunities(passFile)
	if err != nil {
		return err
	}
	if len(communities) == 0 {
		return fmt.Errorf("passlist is empty: %s", passFile)
	}

	targets, err := expandTargets(spec)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no targets resolved from %q", spec)
	}

	port := b.Port
	if port <= 0 {
		port = defaultPort
	}
	rate := b.RateLimitMS
	if rate <= 0 {
		rate = 100
	}
	wait := time.Duration(rate) * time.Millisecond

	fmt.Fprintf(os.Stdout, "%s Targets: %d  Communities: %d  Port: %d  RateLimit: %dms  Version: SNMPv2c\n",
		snmpTag, len(targets), len(communities), port, rate)

	var found int
	for _, target := range targets {
		for _, community := range communities {
			ok, _, err := probeV2c(target, port, community)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s probe error (%s @ %s): %v\n", snmpTag, community, target, err)
				time.Sleep(wait)
				continue
			}
			if !ok {
				time.Sleep(wait)
				continue
			}

			found++
			if len(targets) == 1 {
				fmt.Printf("- %sFound string: %s\x1b[0m\n", foundTag, community)
			} else {
				fmt.Printf("- %sFound string: %s [%s]\x1b[0m\n", foundTag, community, target)
			}

			w := &Walker{
				Target:    target.String(),
				Port:      port,
				Community: community,
				Out:       os.Stdout,
			}
			if err := w.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "%s walk failed (%s @ %s): %v\n", snmpTag, community, target, err)
			}
			fmt.Println()
			time.Sleep(wait)
		}
	}

	if found == 0 {
		fmt.Fprintf(os.Stdout, "%s No valid communities found\n", snmpTag)
	}
	return nil
}
