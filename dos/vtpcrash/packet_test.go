package vtpcrash

import (
	"testing"
)

func TestVlanCiscoCrashBlob(t *testing.T) {
	if len(vlanCiscoCrash) != 188 {
		t.Fatalf("crash blob length: got %d want 188", len(vlanCiscoCrash))
	}
	if vlanCiscoCrash[0] != 0x75 {
		t.Fatalf("first entry length: got 0x%02x want 0x75", vlanCiscoCrash[0])
	}
}

func TestForgeRevision(t *testing.T) {
	c := &Crasher{RevisionNumber: -1}
	if got := c.forgeRevision(10); got != 11 {
		t.Fatalf("auto revision: got %d want 11", got)
	}
	c.RevisionNumber = 99
	if got := c.forgeRevision(10); got != 99 {
		t.Fatalf("override revision: got %d want 99", got)
	}
}

func TestGenerateVTPMD5Crash(t *testing.T) {
	domain := []byte("GNS3LAB")
	digest := generateVTPMD5(defaultUpdater, 37, domain, len(domain), vlanCiscoCrash, 1)
	if len(digest) != 16 {
		t.Fatalf("digest length %d", len(digest))
	}
}
