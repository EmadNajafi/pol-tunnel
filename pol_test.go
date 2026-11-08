package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	cases := map[string][2]string{
		"443":                        {"0.0.0.0:443", "127.0.0.1:443"},
		"4000=5000":                  {"0.0.0.0:4000", "127.0.0.1:5000"},
		"443-445:5201":               {"0.0.0.0:445", "127.0.0.1:5201"},
		"443-445=1.1.1.1:5201":       {"0.0.0.0:445", "1.1.1.1:5201"},
		"127.0.0.2:443=5201":         {"127.0.0.2:443", "127.0.0.1:5201"},
		"127.0.0.2:443=1.1.1.1:5201": {"127.0.0.2:443", "1.1.1.1:5201"},
		"500-502":                    {"0.0.0.0:502", "127.0.0.1:502"},
	}
	for in, want := range cases {
		got, err := ParsePorts([]string{in})
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		last := got[len(got)-1]
		if last.Listen != want[0] || last.Target != want[1] {
			t.Errorf("%s: got %+v want %v", in, last, want)
		}
	}
	for _, bad := range []string{"0", "70000", "600-500", "abc", "1.2.3:80"} {
		if _, err := ParsePorts([]string{bad}); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func echoTCP(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func echoUDP(t *testing.T) string {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, a, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			uc.WriteToUDP(buf[:n], a)
		}
	}()
	return uc.LocalAddr().String()
}

// freePort returns a port free for both TCP and UDP: the callers bind it as
// either (the spoof transports and the public UDP mapping use UDP), and a
// TCP-only check let it collide with the ephemeral UDP sockets of earlier
// spoof tests ("bind: address already in use", flaky under -race in CI).
func freePort(t *testing.T) int {
	for i := 0; i < 50; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := ln.Addr().(*net.TCPAddr).Port
		uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p})
		ln.Close()
		if err == nil {
			uc.Close()
			return p
		}
	}
	t.Fatal("no port free for both tcp and udp")
	return 0
}

func TestEndToEnd(t *testing.T) {
	setLogLevel("warn")
	for _, tr := range []string{"tcp", "tcpmux", "ws", "wsmux", "wss", "wssmux", "spoof", "spoofmux"} {
		for _, enc := range []bool{false, true} {
			name := tr
			if enc {
				name += "+enc"
			}
			t.Run(name, func(t *testing.T) { runE2E(t, tr, enc) })
		}
	}
}

func runE2E(t *testing.T, transport string, encrypt bool) {
	tcpTarget, udpTarget := echoTCP(t), echoUDP(t)
	tunnelPort, pubTCP, pubUDP := freePort(t), freePort(t), freePort(t)
	common := defaultCommon()
	common.Transport = transport
	common.Token = "test-token"
	common.Heartbeat = 2 * time.Second
	common.Encryption = encrypt

	sc := &ServerConfig{Common: common, BindAddr: fmt.Sprintf("127.0.0.1:%d", tunnelPort), AcceptUDP: true,
		Ports: []string{fmt.Sprintf("127.0.0.1:%d=%s", pubTCP, tcpTarget)}}
	srv, err := NewServer(sc)
	if err != nil {
		t.Fatal(err)
	}
	// separate UDP mapping so it can point at the udp echo server
	up, _ := ParsePorts([]string{fmt.Sprintf("127.0.0.1:%d=%s", pubUDP, udpTarget)})
	go srv.Run()
	time.Sleep(200 * time.Millisecond)
	if err := srv.listenUDP(up[0]); err != nil {
		t.Fatal(err)
	}

	cc := &ClientConfig{Common: common, RemoteAddr: sc.BindAddr, ConnectionPool: 4, RetryInterval: time.Second}
	go NewClient(cc).Run()
	time.Sleep(1500 * time.Millisecond)

	// many concurrent TCP connections with 2 MB each
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", pubTCP))
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			data := make([]byte, 2<<20)
			rand.Read(data)
			go func() { c.Write(data); c.(*net.TCPConn).CloseWrite() }()
			c.SetReadDeadline(time.Now().Add(30 * time.Second))
			got, err := io.ReadAll(c)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, data) {
				errs <- fmt.Errorf("data mismatch: got %d bytes", len(got))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// UDP round trip
	uc, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", pubUDP))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	ok := 0
	buf := make([]byte, 2000)
	for i := 0; i < 20; i++ {
		msg := []byte(fmt.Sprintf("hello-%d", i))
		uc.Write(msg)
		uc.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := uc.Read(buf)
		if err == nil && bytes.Equal(buf[:n], msg) {
			ok++
		}
	}
	if ok < 18 {
		t.Errorf("udp: only %d/20 echoes", ok)
	}

	// wrong token must be rejected
	bad := *cc
	bad.Token = "wrong"
	conn, err := NewDialer(&bad)(context.Background())
	if err == nil {
		if _, herr := clientHandshake(conn, bad.Token, connControl, false); herr == nil {
			t.Error("wrong token accepted")
		}
		conn.Close()
	}
}
