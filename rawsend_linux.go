//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
)

// rawSender forges the source IP of outgoing UDP packets via an IP_HDRINCL raw
// socket. Needs CAP_NET_RAW (root) and a datacenter that does not enforce egress
// filtering (BCP38); otherwise the spoofed packet is dropped at the first hop.
type rawSender struct {
	mu      sync.Mutex
	fd      int
	srcIP   [4]byte
	srcPort uint16
	df      atomic.Bool // set Don't Fragment (direct mode's auto MTU probing)
}

func (s *rawSender) setDF(on bool) { s.df.Store(on) }

func buildSender(sock *net.UDPConn, spoofSrc, refAddr string) (packetSender, error) {
	if spoofSrc == "" {
		return plainSender{sock}, nil
	}
	ip := net.ParseIP(spoofSrc).To4()
	if ip == nil {
		return nil, fmt.Errorf("spoof_source %q is not an IPv4 address", spoofSrc)
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("raw socket (need root / CAP_NET_RAW): %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	s := &rawSender{fd: fd}
	copy(s.srcIP[:], ip)
	if sock != nil {
		if la, ok := sock.LocalAddr().(*net.UDPAddr); ok {
			s.srcPort = uint16(la.Port)
		}
	}
	if s.srcPort == 0 {
		s.srcPort = 40000
	}
	return s, nil
}

func (s *rawSender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd >= 0 {
		err := syscall.Close(s.fd)
		s.fd = -1
		return err
	}
	return nil
}

func (s *rawSender) sendTo(payload []byte, dst *net.UDPAddr) error {
	dip := dst.IP.To4()
	if dip == nil {
		return fmt.Errorf("spoof: destination %v is not IPv4", dst.IP)
	}
	pkt := s.build(payload, dip, uint16(dst.Port))
	var a [4]byte
	copy(a[:], dip)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fd < 0 {
		return net.ErrClosed
	}
	return syscall.Sendto(s.fd, pkt, 0, &syscall.SockaddrInet4{Addr: a})
}

// build assembles IPv4 + UDP + payload with the forged source address.
func (s *rawSender) build(payload, dstIP []byte, dstPort uint16) []byte {
	const ipHdr, udpHdr = 20, 8
	total := ipHdr + udpHdr + len(payload)
	b := make([]byte, total)

	// IPv4 header
	b[0] = 0x45 // version 4, IHL 5
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	binary.BigEndian.PutUint16(b[4:], 0) // id (kernel fills when 0 on many kernels; fine)
	if s.df.Load() {
		binary.BigEndian.PutUint16(b[6:], 0x4000) // flags: Don't Fragment
	} else {
		binary.BigEndian.PutUint16(b[6:], 0) // flags/frag
	}
	b[8] = 64 // TTL
	b[9] = syscall.IPPROTO_UDP
	copy(b[12:16], s.srcIP[:])
	copy(b[16:20], dstIP)
	binary.BigEndian.PutUint16(b[10:], checksum(b[:ipHdr]))

	// UDP header
	u := b[ipHdr:]
	binary.BigEndian.PutUint16(u[0:], s.srcPort)
	binary.BigEndian.PutUint16(u[2:], dstPort)
	binary.BigEndian.PutUint16(u[4:], uint16(udpHdr+len(payload)))
	copy(u[udpHdr:], payload)
	binary.BigEndian.PutUint16(u[6:], udpChecksum(s.srcIP[:], dstIP, u))
	return b
}
