package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPEMRSARejectsFalsePositive(t *testing.T) {
	root := findRepoRoot(t)
	keyPath := filepath.Join(root, "rsa_ssh.txt")
	if _, err := os.Stat(keyPath); err != nil {
		t.Skip("rsa_ssh.txt not present")
	}
	hashes, err := parsePrivateKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 1 {
		t.Fatalf("expected 1 hash, got %d", len(hashes))
	}
	h := &hashes[0]
	if tryPassword(h, "roxana") {
		t.Fatal(`false positive: "roxana" must not decrypt RSA PEM`)
	}
	if !tryPassword(h, "!!**john**!!") {
		t.Fatal(`expected password "!!**john**!!" to decrypt RSA PEM`)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("go.mod not found")
	return ""
}
