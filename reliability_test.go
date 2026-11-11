package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A peer that goes silent while a writer is blocked on the transport (a
// blackholed path with data in flight) must still be detected by the
// keepalive: the session has to close after ~3 heartbeats, not hang until TCP
// itself gives up many minutes later.
func TestMuxClosesWhenPeerSilentAndWriterBlocked(t *testing.T) {
	a, b := net.Pipe() // b never reads: every write on a blocks
	defer b.Close()
	hb := 150 * time.Millisecond
	s := NewSession(a, 32*1024, 512*1024, hb)
	defer s.Close()
	go s.Open(protoTCP, "127.0.0.1:1", "") // blocks in conn.Write holding the write lock

	select {
	case <-s.Done():
	case <-time.After(20 * hb):
		t.Fatalf("session still open %v after the peer went silent (keepalive stuck behind a blocked writer)", 20*hb)
	}
}

// After the client reconnects, visitors must not be handed pooled data conns
// that belonged to the previous (dead) client instance.
func TestServerDropsStalePoolOnReconnect(t *testing.T) {
	setLogLevel("error")
	target := echoTCP(t)
	tunnelPort, pub := freePort(t), freePort(t)
	common := defaultCommon()
	common.Transport = "tcp"
	common.Token = "tok"
	common.Heartbeat = 2 * time.Second
	sc := &ServerConfig{Common: common, BindAddr: fmt.Sprintf("127.0.0.1:%d", tunnelPort),
		Ports: []string{fmt.Sprintf("127.0.0.1:%d=%s", pub, target)}}
	srv, err := NewServer(sc)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Run()
	time.Sleep(200 * time.Millisecond)

	// first client instance: a control conn and 4 pooled data conns, then it dies
	dial := func(kind byte) net.Conn {
		c, err := net.Dial("tcp", sc.BindAddr)
		if err != nil {
			t.Fatal(err)
		}
		w, err := clientHandshake(c, "tok", kind, false)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	old := []net.Conn{dial(connControl)}
	for i := 0; i < 4; i++ {
		old = append(old, dial(connData))
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(srv.pool); n != 4 {
		t.Fatalf("pool has %d conns, want 4", n)
	}
	for _, c := range old {
		c.Close()
	}
	time.Sleep(200 * time.Millisecond)

	// the client comes back
	cc := &ClientConfig{Common: common, RemoteAddr: sc.BindAddr, ConnectionPool: 4, RetryInterval: time.Second}
	go NewClient(cc).Run()
	time.Sleep(1500 * time.Millisecond)

	failed := 0
	for i := 0; i < 6; i++ {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", pub))
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		msg := []byte("hello-pol")
		c.Write(msg)
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil || string(got) != string(msg) {
			failed++
		}
		c.Close()
	}
	if failed > 0 {
		t.Fatalf("%d of 6 visitors failed right after the client reconnected (stale pooled conns)", failed)
	}
}

// A value of the wrong type must be an error, not silently replaced by the
// default: `encryption = "true"` used to leave the tunnel unencrypted.
func TestConfigRejectsWrongType(t *testing.T) {
	for _, body := range []string{
		"[server]\ntoken = \"t\"\nencryption = \"true\"\nports = [\"443\"]\n",
		"[server]\ntoken = \"t\"\nheartbeat = \"20\"\nports = [\"443\"]\n",
		"[client]\ntoken = \"t\"\nremote_addr = \"1.2.3.4:1\"\nproxy_protocol = 1\n",
	} {
		p := filepath.Join(t.TempDir(), "c.toml")
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("config accepted a wrong-typed value:\n%s", body)
		}
	}
}

// Every shipped example (and what the installer writes) must still load.
func TestExampleConfigsLoad(t *testing.T) {
	files, _ := filepath.Glob("examples/*.toml")
	if len(files) == 0 {
		t.Fatal("no example configs found")
	}
	for _, f := range files {
		if _, err := LoadConfig(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}
