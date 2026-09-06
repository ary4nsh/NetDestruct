package vtpdelete

import (
	"net"
	"strings"
	"testing"
)

func TestForgeRevision(t *testing.T) {
	d := &Deleter{RevisionNumber: -1}
	if got := d.forgeRevision(21); got != 22 {
		t.Fatalf("auto revision: got %d want 22", got)
	}
	d.RevisionNumber = 50
	if got := d.forgeRevision(21); got != 50 {
		t.Fatalf("override revision: got %d want 50", got)
	}
}

func TestGenerateVTPMD5(t *testing.T) {
	domain := []byte("default")
	digest := generateVTPMD5(defaultUpdater, 2, domain, len(domain), vlanCiscoDelAll, 1)
	if len(digest) != 16 {
		t.Fatalf("expected 16-byte digest, got %d", len(digest))
	}
}

func TestBuildSummaryAndSubset(t *testing.T) {
	src := []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	domain := []byte("default")
	digest := make([]byte, 16)
	summary := buildSummaryFrame(src, 1, 1, domain, len(domain), 2, defaultUpdater, nil, digest)
	if len(summary) < 22+vtpSummarySize {
		t.Fatal("summary frame too short")
	}
	subset := buildSubsetFrame(src, 1, 1, domain, len(domain), 2, vlanCiscoDelAll)
	if len(subset) < 22+vtpSubsetHdr+len(vlanCiscoDelAll) {
		t.Fatal("subset frame too short")
	}
}

func TestFormatVTPSubset(t *testing.T) {
	src := []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	domain := []byte("default")
	frame := buildSubsetFrame(src, 1, 1, domain, len(domain), 2, vlanCiscoDelAll)
	mac, body, ok := formatVTPFrame(frame, "eth0", 1)
	if !ok {
		t.Fatal("expected VTP frame format")
	}
	if mac != formatMAC(src) {
		t.Fatalf("unexpected src mac %s", mac)
	}
	if body == "" {
		t.Fatal("expected body")
	}
	if !strings.Contains(body, "VLAN Trunking Protocol") {
		t.Fatal("expected VTP decode")
	}
}

func TestFormatVTPSubsetWiresharkSample(t *testing.T) {
	// GNS3LAB Subset Advertisement from user capture (226 bytes).
	frame := []byte{
		0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc, 0x00, 0x0c, 0x29, 0x17, 0xf5, 0x95, 0x00, 0xd4, 0xaa, 0xaa,
		0x03, 0x00, 0x00, 0x0c, 0x20, 0x03, 0x02, 0x02, 0x01, 0x07, 0x47, 0x4e, 0x53, 0x33, 0x4c, 0x41,
		0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x14, 0x00,
		0x01, 0x07, 0x00, 0x01, 0x05, 0xdc, 0x00, 0x01, 0x86, 0xa1, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c,
		0x74, 0x00, 0x20, 0x00, 0x02, 0x0c, 0x03, 0xea, 0x05, 0xdc, 0x00, 0x01, 0x8a, 0x8a, 0x66, 0x64,
		0x64, 0x69, 0x2d, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x01, 0x01, 0x00, 0x00, 0x04, 0x01,
		0x00, 0x00, 0x28, 0x00, 0x03, 0x12, 0x03, 0xeb, 0x05, 0xdc, 0x00, 0x01, 0x8a, 0x8b, 0x74, 0x6f,
		0x6b, 0x65, 0x6e, 0x2d, 0x72, 0x69, 0x6e, 0x67, 0x2d, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74,
		0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x24, 0x00, 0x04, 0x0f, 0x03, 0xec,
		0x05, 0xdc, 0x00, 0x01, 0x8a, 0x8c, 0x66, 0x64, 0x64, 0x69, 0x6e, 0x65, 0x74, 0x2d, 0x64, 0x65,
		0x66, 0x61, 0x75, 0x6c, 0x74, 0x00, 0x02, 0x01, 0x00, 0x00, 0x03, 0x01, 0x00, 0x01, 0x24, 0x00,
		0x05, 0x0d, 0x03, 0xed, 0x05, 0xdc, 0x00, 0x01, 0x8a, 0x8d, 0x74, 0x72, 0x6e, 0x65, 0x74, 0x2d,
		0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x03, 0x01,
		0x00, 0x02,
	}
	mac, body, ok := formatVTPFrame(frame, "eth0", 92)
	if !ok {
		t.Fatal("expected VTP frame format")
	}
	if mac != "00:0c:29:17:f5:95" {
		t.Fatalf("unexpected src mac %s", mac)
	}
	checks := []string{
		"Frame 92: Packet, 226 bytes",
		"IEEE 802.3 Ethernet",
		"Logical-Link Control",
		"Version: 0x02",
		"Code: Subset Advertisement (0x02)",
		"Sequence Number: 1",
		"Management Domain: GNS3LAB",
		"Configuration Revision Number: 17",
		"VLAN Name: default",
		"VLAN Name: fddi-default",
		"Spanning-Tree Protocol Type: SRT (0x0001)",
		"Spanning-Tree Protocol Type: SRB (0x0002)",
	}
	for _, want := range checks {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in body:\n%s", want, body)
		}
	}
}

func TestDeleteVlanFromBlob(t *testing.T) {
	modified, err := deleteVlanFromBlob(vlanCiscoDelAll, 0x03ea)
	if err != nil {
		t.Fatalf("delete vlan 1002: %v", err)
	}
	if len(modified) >= len(vlanCiscoDelAll) {
		t.Fatal("expected shorter blob after vlan removal")
	}
	_, err = deleteVlanFromBlob(vlanCiscoDelAll, 0x0999)
	if err == nil {
		t.Fatal("expected error for missing vlan")
	}
}

func TestBuildRequestFrame(t *testing.T) {
	src := []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	domain := []byte("default")
	frame := buildRequestFrame(src, 1, domain, len(domain), 1)
	if len(frame) < 22+vtpRequestSize {
		t.Fatal("request frame too short")
	}
	mac, body, ok := formatVTPFrame(frame, "eth0", 1)
	if !ok {
		t.Fatal("expected VTP request format")
	}
	if mac != formatMAC(src) {
		t.Fatalf("unexpected src mac %s", mac)
	}
	if body == "" {
		t.Fatal("expected body")
	}
}

func TestParseLearnedVTP(t *testing.T) {
	src := net.HardwareAddr{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	domain := []byte("testdom")
	frame := buildSummaryFrame(src, 1, 0, domain, len(domain), 5, defaultUpdater, nil, make([]byte, 16))
	learned, ok := parseLearnedVTP(frame)
	if !ok {
		t.Fatal("expected parse")
	}
	if learned.Revision != 5 {
		t.Fatalf("revision %d", learned.Revision)
	}
	if learned.DomLen != len(domain) {
		t.Fatalf("dom len %d", learned.DomLen)
	}
}
