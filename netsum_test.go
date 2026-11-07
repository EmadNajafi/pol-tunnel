package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// verifyChecksum returns true if the Internet checksum over b is 0, i.e. the
// checksum field already in b is correct.
func verifyChecksum(b []byte) bool { return checksum(b) == 0 }

func TestIPv4HeaderRoundTrip(t *testing.T) {
	src, dst := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	h := ipv4Header(src, dst, ipProtoTCP, 100, true)
	if !verifyChecksum(h) {
		t.Error("IPv4 header checksum invalid")
	}
	if h[6]&0x40 == 0 {
		t.Error("Don't Fragment bit not set")
	}
	if got := int(binary.BigEndian.Uint16(h[2:])); got != 120 {
		t.Errorf("total length = %d, want 120", got)
	}
	// parseIPv4 wants a full datagram; append a dummy payload of the stated size
	full := append(h, make([]byte, 100)...)
	proto, gotSrc, l4, ok := parseIPv4(full)
	if !ok || proto != ipProtoTCP || !gotSrc.Equal(src.To4()) || len(l4) != 100 {
		t.Errorf("parseIPv4 = %v %v len(l4)=%d ok=%v", proto, gotSrc, len(l4), ok)
	}
	if _, _, _, ok := parseIPv4(h[:10]); ok {
		t.Error("parseIPv4 accepted a truncated header")
	}
	noDF := ipv4Header(src, dst, ipProtoICMP, 0, false)
	if noDF[6]&0x40 != 0 {
		t.Error("DF set when it should not be")
	}
}

func TestTCPSegRoundTrip(t *testing.T) {
	src, dst := net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")
	payload := []byte("tunnel datagram bytes")
	seg := buildTCPSeg(src, dst, 4000, 4000, 111, 222, tcpPSH|tcpACK, payload)

	// the TCP checksum verifies over the pseudo-header + segment
	if l4Checksum(src, dst, ipProtoTCP, seg) != 0 {
		t.Error("TCP checksum invalid")
	}
	sp, dp, flags, got, ok := parseTCP(seg)
	if !ok || sp != 4000 || dp != 4000 || !bytes.Equal(got, payload) {
		t.Errorf("parseTCP = %d %d %q ok=%v", sp, dp, got, ok)
	}
	if flags&tcpPSH == 0 || flags&tcpACK == 0 {
		t.Errorf("flags = %#x, want PSH|ACK", flags)
	}
	if _, _, _, _, ok := parseTCP(seg[:10]); ok {
		t.Error("parseTCP accepted a short segment")
	}
}

func TestICMPEchoRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 300)
	m := buildICMPEcho(icmpEchoReply, 0x1234, 7, payload)
	if !verifyChecksum(m) {
		t.Error("ICMP checksum invalid")
	}
	typ, id, got, ok := parseICMPEcho(m)
	if !ok || typ != icmpEchoReply || id != 0x1234 || !bytes.Equal(got, payload) {
		t.Errorf("parseICMPEcho = %d %#x len=%d ok=%v", typ, id, len(got), ok)
	}
	if _, _, _, ok := parseICMPEcho(m[:4]); ok {
		t.Error("parseICMPEcho accepted a short message")
	}
}

func TestFakeClientHello(t *testing.T) {
	rec := fakeClientHello("www.cloudflare.com")
	if !looksLikeTLSHandshake(rec) {
		t.Fatal("decoy is not recognized as a TLS handshake")
	}
	// record length field must match the body that follows
	if got := int(binary.BigEndian.Uint16(rec[3:5])); got != len(rec)-5 {
		t.Errorf("record length = %d, want %d", got, len(rec)-5)
	}
	// handshake type client_hello, and the SNI must appear verbatim
	if rec[5] != 0x01 {
		t.Errorf("handshake type = %#x, want 0x01", rec[5])
	}
	if !bytes.Contains(rec, []byte("www.cloudflare.com")) {
		t.Error("SNI not found in the ClientHello")
	}
	// a plain tunnel datagram must NOT look like a handshake (so it is carried)
	if looksLikeTLSHandshake([]byte{0x45, 0x00, 0x00}) || looksLikeTLSHandshake([]byte{0x16}) {
		t.Error("non-handshake bytes misclassified as a handshake")
	}
}

func TestUDPChecksumNonZero(t *testing.T) {
	// a UDP checksum computed as 0 must be sent as 0xffff (0 means "none")
	src, dst := []byte{0, 0, 0, 0}, []byte{0, 0, 0, 0}
	if cs := udpChecksum(src, dst, make([]byte, 8)); cs == 0 {
		t.Error("udpChecksum returned 0")
	}
}
