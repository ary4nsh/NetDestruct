package dot1xenum

import (
	"strings"
	"testing"
)

func TestFormatPacketExampleRequest(t *testing.T) {
	frame := []byte{
		0x00, 0x02, 0x00, 0x01, 0x00, 0x06, 0x0c, 0xd4, 0x08, 0x34, 0x00, 0x00, 0x00, 0x00, 0x88, 0x8e,
		0x03, 0x00, 0x00, 0x05, 0x01, 0x01, 0x00, 0x05, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	pkt, ok := formatPacket(frame)
	if !ok {
		t.Fatal("expected 802.1X packet")
	}
	if pkt.SourceMAC != "0c:d4:08:34:00:00" {
		t.Fatalf("unexpected src mac: %q", pkt.SourceMAC)
	}
	body := pkt.Body
	checks := []string{
		"Linux cooked capture v1",
		"Packet type: Multicast (2)",
		"Link-layer address type: Ethernet (1)",
		"Protocol: 802.1X Authentication (0x888e)",
		"802.1X Authentication",
		"Version: 802.1X-2010 (3)",
		"Type: EAP Packet (0)",
		"Length: 5",
		"Extensible Authentication Protocol",
		"Code: Request (1)",
		"Id: 1",
		"Type: Identity (1)",
	}
	for _, c := range checks {
		if !strings.Contains(body, c) {
			t.Fatalf("missing %q in:\n%s", c, body)
		}
	}
}

func TestBuildProbeFrameDefaultEAPInfo(t *testing.T) {
	frame := buildProbeFrame([]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, "Cisco Production")
	if !strings.Contains(string(frame), "Cisco Production") {
		t.Fatal("expected default EAP identity in probe")
	}
}

func TestBuildProbeFrameCustomEAPInfo(t *testing.T) {
	frame := buildProbeFrame([]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}, "mamad")
	if !strings.Contains(string(frame), "mamad") {
		t.Fatal("expected custom EAP identity in probe")
	}
}

func TestFormatPacketEthernetIdentityResponse(t *testing.T) {
	identity := []byte("Andrea Amati")
	eapLen := 4 + 1 + len(identity)
	dot1xLen := 4 + eapLen
	frame := make([]byte, 14+dot1xLen)
	copy(frame[0:6], dot1xDst[:])
	copy(frame[6:12], []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55})
	frame[12] = 0x88
	frame[13] = 0x8e
	frame[14] = 0x01
	frame[15] = 0x00
	frame[16] = byte(dot1xLen >> 8)
	frame[17] = byte(dot1xLen)
	frame[18] = 0x02
	frame[19] = 0x00
	frame[20] = byte(eapLen >> 8)
	frame[21] = byte(eapLen)
	frame[22] = 0x01
	copy(frame[23:], identity)

	pkt, ok := formatPacket(frame)
	if !ok {
		t.Fatal("expected ethernet 802.1X packet")
	}
	if !strings.Contains(pkt.Body, "Code: Response (2)") {
		t.Fatalf("missing response: %s", pkt.Body)
	}
	if !strings.Contains(pkt.Body, `Identity: "Andrea Amati"`) {
		t.Fatalf("missing identity: %s", pkt.Body)
	}
}

func TestFormatPacketEAPSuccess(t *testing.T) {
	frame := []byte{
		0x00, 0x02, 0x00, 0x01, 0x00, 0x06, 0x0c, 0xd4, 0x08, 0x34, 0x00, 0x00, 0x00, 0x00, 0x88, 0x8e,
		0x01, 0x00, 0x00, 0x04, 0x03, 0x02, 0x00, 0x04,
	}
	pkt, ok := formatPacket(frame)
	if !ok {
		t.Fatal("expected success packet")
	}
	if !strings.Contains(pkt.Body, "Code: Success (3)") {
		t.Fatalf("missing success: %s", pkt.Body)
	}
}

func TestFormatPacketSkipsNonDot1X(t *testing.T) {
	frame := []byte{
		0x00, 0x02, 0x00, 0x01, 0x00, 0x06, 0x0c, 0xd4, 0x08, 0x34, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
		0x45, 0x00, 0x00, 0x28,
	}
	if _, ok := formatPacket(frame); ok {
		t.Fatal("non-802.1X packet should be skipped")
	}
}
