package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// dialAgent runs one agent session over an in-memory pipe and authenticates
// with key, returning the reader/conn and the agent's WELCOME line.
func dialAgent(t *testing.T, agentKey, key string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	a, b := net.Pipe()
	go agentSession(a, agentKey)
	t.Cleanup(func() { b.Close() })
	b.SetDeadline(time.Now().Add(5 * time.Second))
	rd := bufio.NewReader(b)
	f := strings.Fields(readLine(rd))
	if len(f) != 2 || f[0] != "HELLO" {
		t.Fatalf("bad greeting %q", f)
	}
	fmt.Fprintf(b, "AUTH %s\n", testAuthMAC(key, f[1]))
	return b, rd, strings.TrimSpace(readLine(rd))
}

func TestTestAgentRejectsWrongKey(t *testing.T) {
	_, _, reply := dialAgent(t, "right-key", "wrong-key")
	if reply == "WELCOME" {
		t.Fatal("agent accepted a wrong key")
	}
}

func TestTestAgentValidatesArgs(t *testing.T) {
	c, rd, reply := dialAgent(t, "k", "k")
	if reply != "WELCOME" {
		t.Fatalf("agent rejected the right key: %q", reply)
	}
	bad := []string{
		`SERVER tcp 47000 1=1.2.3.4:22","0.0.0.0:2222 47900`, // config injection
		`SERVER bogus 47000 47100 47900`,
		`SERVER tcp 70000 47100 47900`,
		`SERVER tcp" 47000 47100 47900`,
		`DIRECT 47200 10.0.0.1/0 10.0.0.2`,
		`DIRECT 47200 10.0.0.1 not-an-ip`,
		`PROBE 0`,
		`PROBE 80;rm`,
	}
	for _, cmd := range bad {
		fmt.Fprintln(c, cmd)
		if got := strings.TrimSpace(readLine(rd)); got != "FAIL" {
			t.Errorf("%q: got %q, want FAIL", cmd, got)
		}
	}
}

func TestTestTokenDerivation(t *testing.T) {
	if testToken("k", "n1") == testToken("k", "n2") || testToken("k", "n") == testToken("k2", "n") {
		t.Error("tunnel token must depend on both key and nonce")
	}
	if testToken("k", "n") == testAuthMAC("k", "n") {
		t.Error("token must differ from the auth MAC that crosses the wire")
	}
}
