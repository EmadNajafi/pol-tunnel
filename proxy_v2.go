package main

import (
	"encoding/binary"
	"net"
	"strconv"
)

// buildProxyV2 builds a PROXY protocol v2 header announcing the original client
// (src) and the destination it reached (dst), so the backend behind the client
// sees the real visitor IP instead of 127.0.0.1. Returns nil when the addresses
// can't be expressed (then the caller sends no header).
//
// https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt
func buildProxyV2(src, dst string) []byte {
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	sIP, sPort, ok1 := splitIPPort(src)
	dIP, dPort, ok2 := splitIPPort(dst)
	if !ok1 || !ok2 {
		return nil
	}
	s4, d4 := sIP.To4(), dIP.To4()
	var fam byte
	var ab []byte
	if s4 != nil && d4 != nil {
		fam = 0x11 // AF_INET + STREAM
		ab = make([]byte, 12)
		copy(ab[0:4], s4)
		copy(ab[4:8], d4)
		binary.BigEndian.PutUint16(ab[8:10], sPort)
		binary.BigEndian.PutUint16(ab[10:12], dPort)
	} else {
		s16, d16 := sIP.To16(), dIP.To16()
		if s16 == nil || d16 == nil {
			return nil
		}
		fam = 0x21 // AF_INET6 + STREAM
		ab = make([]byte, 36)
		copy(ab[0:16], s16)
		copy(ab[16:32], d16)
		binary.BigEndian.PutUint16(ab[32:34], sPort)
		binary.BigEndian.PutUint16(ab[34:36], dPort)
	}
	out := make([]byte, 0, 16+len(ab))
	out = append(out, sig...)
	out = append(out, 0x21, fam) // v2 PROXY command, family/transport
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(ab)))
	out = append(out, l[:]...)
	out = append(out, ab...)
	return out
}

func splitIPPort(s string) (net.IP, uint16, bool) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, false
	}
	ip := net.ParseIP(host)
	p, err := strconv.Atoi(portStr)
	if ip == nil || err != nil {
		return nil, 0, false
	}
	return ip, uint16(p), true
}
