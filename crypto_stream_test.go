package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

// A single Write larger than one record's uint16 length field must still
// arrive intact (it is split into several records), e.g. a 65535-byte mux
// frame plus its 7-byte header on an encrypted session.
func TestAEADConnLargeWrite(t *testing.T) {
	ss := make([]byte, 32)
	rand.Read(ss)
	ck, err := deriveKeys("tok", ss, true)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := deriveKeys("tok", ss, false)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	ca, cb := newAEADConn(a, ck), newAEADConn(b, sk)
	defer ca.Close()
	defer cb.Close()

	for _, size := range []int{1, 65507, 65508, 65536, 65542, 200000} {
		msg := make([]byte, size)
		rand.Read(msg)
		errc := make(chan error, 1)
		go func() { _, err := ca.Write(msg); errc <- err }()
		got := make([]byte, size)
		cb.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(cb, got); err != nil {
			t.Fatalf("size %d: read: %v", size, err)
		}
		if err := <-errc; err != nil {
			t.Fatalf("size %d: write: %v", size, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("size %d: payload corrupted", size)
		}
	}
}

// Zero/negative tuning values fall back to defaults instead of breaking the
// tunnel (0 channel_size dropped every pooled conn; negative panicked).
func TestConfigClampsZeroValues(t *testing.T) {
	sec := section{"channel_size": int64(-1), "dial_timeout": int64(0), "udp_idle_timeout": int64(0)}
	c := loadCommon(sec)
	d := defaultCommon()
	if c.ChannelSize != d.ChannelSize || c.DialTimeout != d.DialTimeout || c.UDPIdle != d.UDPIdle {
		t.Fatalf("got channel_size=%d dial_timeout=%v udp_idle=%v, want defaults", c.ChannelSize, c.DialTimeout, c.UDPIdle)
	}
}
