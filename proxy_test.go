package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestBuildProxyV2(t *testing.T) {
	h := buildProxyV2("203.0.113.7:4321", "198.51.100.9:80")
	if h == nil {
		t.Fatal("nil header")
	}
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	if !bytes.Equal(h[:12], sig) {
		t.Error("bad signature")
	}
	if h[12] != 0x21 || h[13] != 0x11 { // v2 PROXY, AF_INET+STREAM
		t.Errorf("bad vercmd/fam: %x %x", h[12], h[13])
	}
	if binary.BigEndian.Uint16(h[14:16]) != 12 {
		t.Error("bad addr block length")
	}
	if !bytes.Equal(h[16:20], net.ParseIP("203.0.113.7").To4()) {
		t.Error("bad src ip")
	}
	if binary.BigEndian.Uint16(h[24:26]) != 4321 {
		t.Error("bad src port")
	}
	// IPv6 and unparseable cases
	if h6 := buildProxyV2("[2001:db8::1]:1", "[2001:db8::2]:2"); h6 == nil || h6[13] != 0x21 {
		t.Error("ipv6 header wrong")
	}
	if buildProxyV2("not-an-addr", "1.2.3.4:5") != nil {
		t.Error("should reject unparseable src")
	}
}

// End-to-end: client with proxy_protocol on must make the backend see the real
// visitor IP via a PROXY v2 header.
func TestProxyProtocolE2E(t *testing.T) {
	setLogLevel("warn")
	gotSrc := make(chan string, 1)
	// backend: parse PROXY v2 header, report src IP, then echo the rest
	bl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bl.Close()
	go func() {
		conn, err := bl.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		hdr := make([]byte, 16)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		alen := int(binary.BigEndian.Uint16(hdr[14:16]))
		ab := make([]byte, alen)
		io.ReadFull(conn, ab)
		gotSrc <- net.IP(ab[0:4]).String() // v4 src
		io.Copy(conn, conn)
	}()

	tunnelPort, pubTCP := freePort(t), freePort(t)
	common := defaultCommon()
	common.Transport = "tcpmux"
	common.Token = "tok"
	common.Heartbeat = 2 * time.Second
	sc := &ServerConfig{Common: common, BindAddr: fmt.Sprintf("127.0.0.1:%d", tunnelPort),
		Ports: []string{fmt.Sprintf("127.0.0.1:%d=%s", pubTCP, bl.Addr().String())}}
	srv, err := NewServer(sc)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Run()
	cc := &ClientConfig{Common: common, RemoteAddr: sc.BindAddr, ConnectionPool: 2, RetryInterval: time.Second}
	cc.ProxyProtocol = true
	go NewClient(cc).Run()
	time.Sleep(1500 * time.Millisecond)

	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", pubTCP))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hello"))
	buf := make([]byte, 5)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	io.ReadFull(c, buf)
	if string(buf) != "hello" {
		t.Errorf("echo through proxy-protocol failed: %q", buf)
	}
	select {
	case src := <-gotSrc:
		if src != "127.0.0.1" {
			t.Errorf("backend saw src %q, want 127.0.0.1", src)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend never got a PROXY header")
	}
}
