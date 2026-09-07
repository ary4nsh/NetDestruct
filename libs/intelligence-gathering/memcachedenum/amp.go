package memcachedenum

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ampProbePayload is the Memcached text-protocol command used for the UDP
// amplification check (CVE-2018-1000115).
const ampProbePayload = "stats\r\n"

// buildUDPStatsProbe builds a Memcached UDP request frame:
//
//	request ID (uint16) | seq (0) | datagrams (1) | reserved (0) | "stats\r\n"
func buildUDPStatsProbe() []byte {
	var reqID uint16
	_ = binary.Read(rand.Reader, binary.BigEndian, &reqID)

	frame := make([]byte, 8+len(ampProbePayload))
	binary.BigEndian.PutUint16(frame[0:2], reqID)
	binary.BigEndian.PutUint16(frame[2:4], 0) // sequence number
	binary.BigEndian.PutUint16(frame[4:6], 1) // datagrams in this sequence
	binary.BigEndian.PutUint16(frame[6:8], 0) // reserved
	copy(frame[8:], ampProbePayload)
	return frame
}

// isMemcachedStatsUDPResponse reports whether data looks like a Memcached
// UDP stats reply (matches /\x0d\x0aSTAT\x20/).
func isMemcachedStatsUDPResponse(data []byte) bool {
	return strings.Contains(string(data), "\r\nSTAT ")
}

// proveAmplification:
// packet amplification when >1 response datagram, bandwidth amplification when
// total response bytes exceed the request size.
func proveAmplification(request []byte, responses [][]byte) (vulnerable bool, proof string) {
	if len(responses) == 0 {
		return false, "no UDP stats response"
	}

	var parts []string
	if len(responses) > 1 {
		vulnerable = true
		parts = append(parts, fmt.Sprintf("%dx packet amplification", len(responses)))
	} else {
		parts = append(parts, "No packet amplification")
	}

	totalSize := 0
	for _, r := range responses {
		totalSize += len(r)
	}
	bandwidthAmp := totalSize - len(request)
	if bandwidthAmp > 0 {
		vulnerable = true
		multiplier := totalSize
		if len(request) > 0 {
			multiplier = totalSize / len(request) // integer division
		}
		parts = append(parts, fmt.Sprintf("a %dx, %d-byte bandwidth amplification", multiplier, bandwidthAmp))
	} else {
		parts = append(parts, "no bandwidth amplification")
	}

	return vulnerable, strings.Join(parts, " and ")
}

// runAmplificationTest probes UDP memcached with a stats request and reports
// whether the service is usable for DRDoS amplification
func runAmplificationTest(out io.Writer, host string, port int, timeout time.Duration) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	printSection(out, fmt.Sprintf("Amplification Test @ %s/udp", addr))
	printInfo(out, "Sending Memcached UDP stats probe (CVE-2018-1000115)")

	probe := buildUDPStatsProbe()
	fmt.Fprintf(out, "- Probe size: %d bytes\n", len(probe))

	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		printFail(out, fmt.Sprintf("UDP dial failed: %v", err))
		return
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(probe); err != nil {
		printFail(out, fmt.Sprintf("UDP write failed: %v", err))
		return
	}

	var responses [][]byte
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		pkt := append([]byte(nil), buf[:n]...)
		if isMemcachedStatsUDPResponse(pkt) {
			responses = append(responses, pkt)
		}
		// Keep reading until the deadline; large stats replies may span packets.
		_ = conn.SetDeadline(deadline)
	}

	if len(responses) == 0 {
		printFail(out, fmt.Sprintf("%s - Not vulnerable to memcached stats amplification: no UDP stats response (UDP may be closed or filtered)", addr))
		return
	}

	total := 0
	for _, r := range responses {
		total += len(r)
	}
	fmt.Fprintf(out, "- Response datagrams: %d\n", len(responses))
	fmt.Fprintf(out, "- Response size: %d bytes\n", total)

	vulnerable, proof := proveAmplification(probe, responses)
	what := "memcached stats amplification"
	if vulnerable {
		printSuccess(out, fmt.Sprintf("%s - Vulnerable to %s: %s", addr, what, proof))
	} else {
		printInfo(out, fmt.Sprintf("%s - Not vulnerable to %s: %s", addr, what, proof))
	}
}
