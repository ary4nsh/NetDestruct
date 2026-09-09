package credsniff

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// readPcap reads a classic pcap file and runs each frame through the credential parser.
// Flow state is reset at the start of each file so pairing (e.g. FTP USER+PASS)
// works correctly within a single capture without bleeding across files.
func readPcap(path, ignoreIP string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	// Detect byte order from the 4-byte magic
	var magicBuf [4]byte
	if _, err := io.ReadFull(f, magicBuf[:]); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}
	magic := uint32(magicBuf[0])<<24 | uint32(magicBuf[1])<<16 | uint32(magicBuf[2])<<8 | uint32(magicBuf[3])

	var order binary.ByteOrder
	switch magic {
	case 0xa1b2c3d4, 0xa1b23c4d: // big-endian (µs and ns timestamps)
		order = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1: // little-endian (µs and ns timestamps)
		order = binary.LittleEndian
	default:
		return fmt.Errorf("not a pcap file (magic=0x%08x); pcapng is not supported", magic)
	}

	// Remaining 20 bytes of global header
	var ghdr struct {
		VerMajor, VerMinor uint16
		Thiszone           int32
		Sigfigs            uint32
		Snaplen            uint32
		Network            uint32
	}
	if err := binary.Read(f, order, &ghdr); err != nil {
		return fmt.Errorf("read global header: %w", err)
	}
	linkType := ghdr.Network
	fmt.Printf("%s reading %s (link-type %d)\n", tag, path, linkType)

	// Reset per-file flow state (USER→PASS pairing, NTLM challenges, etc.)
	// The output writer's dedup cache is NOT reset so we don't write duplicates
	// across multiple files in a --pcap-dir run.
	resetState()

	// Per-packet record loop
	var phdr struct {
		TsSec, TsUsec    uint32
		InclLen, OrigLen uint32
	}
	var count int
	for {
		if err := binary.Read(f, order, &phdr); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("read packet record header: %w", err)
		}
		data := make([]byte, phdr.InclLen)
		if _, err := io.ReadFull(f, data); err != nil {
			return fmt.Errorf("read packet data: %w", err)
		}
		count++
		parseByLinkType(data, linkType, ignoreIP)
	}

	fmt.Printf("%s processed %d packets from %s\n", tag, count, path)
	return nil
}

// readPcapDir walks dir recursively and processes every .pcap file found.
func readPcapDir(dir, ignoreIP string) error {
	var found int
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		lower := strings.ToLower(path)
		if strings.HasSuffix(lower, ".pcap") || strings.HasSuffix(lower, ".pcapng") {
			found++
			if e := readPcap(path, ignoreIP); e != nil {
				fmt.Printf("%s [!] %v\n", tag, e)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if found == 0 {
		fmt.Printf("%s no .pcap files found in %s\n", tag, dir)
	}
	return nil
}

func parseByLinkType(data []byte, linkType uint32, ignoreIP string) {
	switch linkType {
	case 1: // Ethernet II
		parsePacket(data, ignoreIP)

	case 113: // Linux cooked capture (SLL) — 16-byte header, EtherType at [14:16]
		if len(data) < 16 {
			return
		}
		fake := make([]byte, 14+len(data[16:]))
		fake[12] = data[14]
		fake[13] = data[15]
		copy(fake[14:], data[16:])
		parsePacket(fake, ignoreIP)

	case 101, 228: // raw IPv4 — synthesise a 14-byte Ethernet stub
		if len(data) < 20 {
			return
		}
		fake := make([]byte, 14+len(data))
		fake[12] = 0x08
		fake[13] = 0x00
		copy(fake[14:], data)
		parsePacket(fake, ignoreIP)
	}
}
