package telnet

import (
	"strings"
	"testing"
)

func TestClassifyFailureLoginIncorrect(t *testing.T) {
	buf := normalize("Login incorrect\r\nlogin: ")
	if got := classifyResponse(buf, true); got != respFailure {
		t.Fatalf("got %v want failure", got)
	}
}

func TestClassifyPasswordPrompt(t *testing.T) {
	buf := normalize("Password: ")
	if got := classifyResponse(buf, false); got != respPassword {
		t.Fatalf("got %v want password", got)
	}
}

func TestClassifySuccessShellPrompt(t *testing.T) {
	buf := normalize("Last login: Mon Sep 1\r\nuser@host:~$ ")
	if got := classifyResponse(buf, true); got != respSuccess {
		t.Fatalf("got %v want success", got)
	}
}

func TestClassifySuccessANSIPrompt(t *testing.T) {
	// Colored prompt with SGR reset AFTER '$' — trailing-byte check alone fails.
	raw := "\x1b[01;32mubuntu-clone@ubuntu\x1b[00m:\x1b[01;34m~\x1b[00m$\x1b[0m"
	if got := classifyResponse(normalize(raw), true); got != respSuccess {
		t.Fatalf("got %v want success for ANSI prompt", got)
	}
}

func TestClassifySuccessLastLoginOnly(t *testing.T) {
	buf := normalize("Last login: Mon Sep 1 from 1.2.3.4\r\n")
	if got := classifyResponse(buf, true); got != respSuccess {
		t.Fatalf("got %v want success via last login", got)
	}
}

func TestClassifyLastLoginNotFailure(t *testing.T) {
	buf := normalize("Last login: Mon Sep 1\r\n")
	if isLoginPrompt(buf) {
		t.Fatal("last login must not count as login re-prompt")
	}
}

func TestHasShellPromptTrailingOnly(t *testing.T) {
	if hasShellPrompt("path/to/#notaprompt\nhello") {
		t.Fatal("mid-buffer # must not count")
	}
	if !hasShellPrompt("root@box:~# ") {
		t.Fatal("trailing # should count")
	}
}

func TestClassifySuccessPreferredOverPasswordWord(t *testing.T) {
	buf := normalize("Welcome to Ubuntu\r\nSome password tips here\r\nuser@host:~$ ")
	if got := classifyResponse(buf, true); got != respSuccess {
		t.Fatalf("got %v want success (not password)", got)
	}
}

func TestStripANSI(t *testing.T) {
	in := "\x1b[32mhello\x1b[0m"
	if got := stripANSI(in); got != "hello" {
		t.Fatalf("got %q", got)
	}
	_ = strings.TrimSpace(in)
}
