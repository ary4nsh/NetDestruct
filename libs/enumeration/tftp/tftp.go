package tftp

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// TFTP opcodes (RFC 1350)
const (
	opRRQ   uint16 = 1
	opWRQ   uint16 = 2
	opData  uint16 = 3
	opACK   uint16 = 4
	opError uint16 = 5
)

const (
	blockSize   = 512
	xferTimeout = 5 * time.Second
	maxDownload = 64 * 1024 // stop downloading after 64 KB
	maxDisplay  = 4096      // bytes shown inline
)

// Client downloads (--get) or uploads (--put) files on a TFTP server.
type Client struct {
	Server   string   // host, host:port, or domain name (default port 69)
	Port     int      // override port; ignored when Server already contains a port
	GetFiles []string // remote filenames to download/probe
	PutFiles []string // local file paths to upload
}

type probeResult struct {
	found   bool
	denied  bool   // access violation (errcode 2)
	size    int
	content []byte // up to maxDisplay bytes
}

// Run resolves the server address then dispatches to upload or download.
func (c *Client) Run() error {
	// Append :69 only when no port is present.
	// SplitHostPort handles bare IPv6 addresses (2001:db8::1) correctly —
	// they contain ":" but are not in host:port form.
	addr := c.Server
	if _, _, err := net.SplitHostPort(addr); err != nil {
		port := 69
		if c.Port != 0 {
			port = c.Port
		}
		addr = net.JoinHostPort(addr, strconv.Itoa(port))
	}

	serverAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", addr, err)
	}

	// Match socket family to the resolved address to avoid family mismatches
	// on Windows when WriteToUDP is called with a dual-stack socket.
	network := "udp4"
	if serverAddr.IP.To4() == nil {
		network = "udp6"
	}

	// Show the resolved IP when the user passed a hostname.
	host := c.Server
	if h, _, splitErr := net.SplitHostPort(c.Server); splitErr == nil {
		host = h
	}
	displayAddr := addr
	if net.ParseIP(host) == nil {
		displayAddr = fmt.Sprintf("%s (%s)", addr, serverAddr.IP)
	}

	if len(c.PutFiles) > 0 {
		return c.runPut(serverAddr, network, displayAddr)
	}
	return c.runGet(serverAddr, network, displayAddr)
}

// runGet probes/downloads each file in GetFiles.
func (c *Client) runGet(serverAddr *net.UDPAddr, network, displayAddr string) error {
	fmt.Printf("TFTP server:  %s\n", displayAddr)
	fmt.Printf("Downloading %d file(s)...\n\n", len(c.GetFiles))

	found := 0
	for _, name := range c.GetFiles {
		r, err := downloadFile(serverAddr, name, network)
		if err != nil {
			fmt.Printf("  [!] %-32s error: %v\n", name, err)
			continue
		}
		switch {
		case r.denied:
			found++
			fmt.Printf("\x1b[33m  [+] %-32s EXISTS (access denied)\x1b[0m\n", name)
		case r.found:
			found++
			fmt.Printf("\x1b[32m  [+] %-32s FOUND (%d bytes)\x1b[0m\n", name, r.size)
			if len(r.content) > 0 {
				printContent(r.content, r.size > maxDisplay)
			}
		default:
			fmt.Printf("  [-] %-32s not found\n", name)
		}
	}

	fmt.Printf("\nFound: %d/%d\n", found, len(c.GetFiles))
	return nil
}

// runPut uploads each local file in PutFiles, using the file's basename as
// the remote name on the server.
func (c *Client) runPut(serverAddr *net.UDPAddr, network, displayAddr string) error {
	fmt.Printf("TFTP server:  %s\n", displayAddr)
	fmt.Printf("Uploading %d file(s)...\n\n", len(c.PutFiles))

	ok := 0
	for _, localPath := range c.PutFiles {
		remoteName := filepath.Base(localPath)
		err := uploadFile(serverAddr, remoteName, localPath, network)
		if err != nil {
			fmt.Printf("  [!] %-30s -> %-24s error: %v\n", localPath, remoteName, err)
			continue
		}
		ok++
		fmt.Printf("\x1b[32m  [+] %-30s -> %-24s uploaded\x1b[0m\n", localPath, remoteName)
	}

	fmt.Printf("\nUploaded: %d/%d\n", ok, len(c.PutFiles))
	return nil
}

func printContent(data []byte, truncated bool) {
	sep := "    " + strings.Repeat("-", 56)
	fmt.Println(sep)
	text := strings.TrimRight(string(data), "\r\n\x00")
	for _, line := range strings.Split(text, "\n") {
		fmt.Printf("    %s\n", strings.TrimRight(line, "\r"))
	}
	if truncated {
		fmt.Println("    [... truncated ...]")
	}
	fmt.Println(sep)
}

// downloadFile sends an RRQ and receives the full response (up to maxDownload).
func downloadFile(serverAddr *net.UDPAddr, filename, network string) (*probeResult, error) {
	conn, err := net.ListenUDP(network, &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := udpWrite(conn, serverAddr, rrqPacket(filename)); err != nil {
		return nil, err
	}

	var tidAddr *net.UDPAddr
	var data []byte
	buf := make([]byte, 4+blockSize)

	for {
		conn.SetDeadline(time.Now().Add(xferTimeout))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Partial transfer: server timed out mid-stream — still report as found.
			if len(data) > 0 {
				return &probeResult{found: true, size: len(data), content: capContent(data)}, nil
			}
			return nil, err
		}
		if n < 4 {
			continue
		}

		// Establish transfer TID on the first received packet (RFC 1350 §4).
		if tidAddr == nil {
			tidAddr = from
		} else if !from.IP.Equal(tidAddr.IP) || from.Port != tidAddr.Port {
			// net.IP.Equal handles IPv4 vs IPv4-mapped-IPv6 correctly.
			udpWrite(conn, from, errorPacket(5, "Unknown transfer ID"))
			continue
		}

		op := binary.BigEndian.Uint16(buf[:2])

		switch op {
		case opData:
			block := binary.BigEndian.Uint16(buf[2:4])
			chunk := make([]byte, n-4)
			copy(chunk, buf[4:n])
			data = append(data, chunk...)

			udpWrite(conn, tidAddr, ackPacket(block))

			if n-4 < blockSize {
				return &probeResult{found: true, size: len(data), content: capContent(data)}, nil
			}
			if len(data) >= maxDownload {
				return &probeResult{found: true, size: len(data), content: capContent(data)}, nil
			}

		case opError:
			code := binary.BigEndian.Uint16(buf[2:4])
			switch code {
			case 1: // File not found
				return &probeResult{found: false}, nil
			case 2: // Access violation — file exists but unreadable
				return &probeResult{found: true, denied: true}, nil
			default:
				msg := strings.TrimRight(string(buf[4:n]), "\x00")
				return nil, fmt.Errorf("server error %d: %s", code, msg)
			}
		}
	}
}

// uploadFile sends a WRQ then streams the local file to the server in
// 512-byte DATA blocks, waiting for an ACK after each block.
// Block numbers wrap from 65535 → 1 to support files larger than 32 MB.
func uploadFile(serverAddr *net.UDPAddr, remoteName, localPath, network string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	conn, err := net.ListenUDP(network, &net.UDPAddr{})
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := udpWrite(conn, serverAddr, wrqPacket(remoteName)); err != nil {
		return err
	}

	// Server responds with ACK 0 from its chosen TID port.
	buf := make([]byte, 4+blockSize)
	conn.SetDeadline(time.Now().Add(xferTimeout))
	n, tidAddr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return fmt.Errorf("waiting for ACK 0: %w", err)
	}
	if n < 4 {
		return fmt.Errorf("short packet from server")
	}
	switch op := binary.BigEndian.Uint16(buf[:2]); op {
	case opError:
		code := binary.BigEndian.Uint16(buf[2:4])
		msg := strings.TrimRight(string(buf[4:n]), "\x00")
		return fmt.Errorf("server error %d: %s", code, msg)
	case opACK:
		if ack := binary.BigEndian.Uint16(buf[2:4]); ack != 0 {
			return fmt.Errorf("expected ACK 0, got ACK %d", ack)
		}
	default:
		return fmt.Errorf("expected ACK 0, got opcode %d", op)
	}

	var block uint16 = 1
	offset := 0
	for {
		end := offset + blockSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]

		if err := udpWrite(conn, tidAddr, dataPacket(block, chunk)); err != nil {
			return err
		}

		// Wait for the matching ACK; ignore duplicate ACKs, reject wrong TIDs.
	ackLoop:
		for {
			conn.SetDeadline(time.Now().Add(xferTimeout))
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return fmt.Errorf("waiting for ACK %d: %w", block, err)
			}
			if n < 4 {
				continue
			}
			if !from.IP.Equal(tidAddr.IP) || from.Port != tidAddr.Port {
				udpWrite(conn, from, errorPacket(5, "Unknown transfer ID"))
				continue
			}
			switch op := binary.BigEndian.Uint16(buf[:2]); op {
			case opError:
				code := binary.BigEndian.Uint16(buf[2:4])
				msg := strings.TrimRight(string(buf[4:n]), "\x00")
				return fmt.Errorf("server error %d: %s", code, msg)
			case opACK:
				if binary.BigEndian.Uint16(buf[2:4]) == block {
					break ackLoop // correct ACK received
				}
				// Duplicate or out-of-order ACK — keep waiting
			default:
				return fmt.Errorf("unexpected opcode %d during upload", op)
			}
		}

		if len(chunk) < blockSize {
			break // final block acknowledged; transfer complete
		}

		offset = end
		block++
		if block == 0 {
			block = 1 // wrap-around for files > 32 MB
		}
	}

	return nil
}

func capContent(data []byte) []byte {
	if len(data) <= maxDisplay {
		return data
	}
	return data[:maxDisplay]
}

func rrqPacket(filename string) []byte {
	return requestPacket(opRRQ, filename)
}

func wrqPacket(filename string) []byte {
	return requestPacket(opWRQ, filename)
}

func requestPacket(op uint16, filename string) []byte {
	const mode = "octet"
	b := make([]byte, 2+len(filename)+1+len(mode)+1)
	binary.BigEndian.PutUint16(b, op)
	copy(b[2:], filename)
	b[2+len(filename)] = 0
	copy(b[2+len(filename)+1:], mode)
	return b
}

func dataPacket(block uint16, payload []byte) []byte {
	b := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(b, opData)
	binary.BigEndian.PutUint16(b[2:], block)
	copy(b[4:], payload)
	return b
}

func ackPacket(block uint16) []byte {
	var b [4]byte
	binary.BigEndian.PutUint16(b[:], opACK)
	binary.BigEndian.PutUint16(b[2:], block)
	return b[:]
}

func errorPacket(code uint16, msg string) []byte {
	b := make([]byte, 4+len(msg)+1)
	binary.BigEndian.PutUint16(b, opError)
	binary.BigEndian.PutUint16(b[2:], code)
	copy(b[4:], msg)
	return b
}

func udpWrite(conn *net.UDPConn, addr *net.UDPAddr, pkt []byte) error {
	conn.SetDeadline(time.Now().Add(xferTimeout))
	_, err := conn.WriteToUDP(pkt, addr)
	return err
}
