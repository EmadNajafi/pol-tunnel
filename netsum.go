package main

import (
	"crypto/rand"
	"encoding/binary"
	"net"
)

// Packet framing shared by the raw-socket direct carriers (spoof, pck, sni,
// icmp). These are pure byte-slice builders and parsers with no I/O, so they
// are the same on every OS and are unit-tested without root. The raw sockets
// that actually send and receive them live in carrier_linux.go.

const (
	ipProtoICMP = 1
	ipProtoTCP  = 6
	ipProtoUDP  = 17
)

// checksum is the one's-complement Internet checksum (RFC 1071) over b.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// l4Checksum is the TCP/UDP checksum over the IPv4 pseudo-header + segment.
func l4Checksum(src, dst net.IP, proto byte, seg []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src.To4())
	add(dst.To4())
	sum += uint32(proto)
	sum += uint32(len(seg))
	add(seg)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// udpChecksum returns the UDP checksum, mapping 0 to 0xffff (0 means "none").
func udpChecksum(src, dst, udp []byte) uint16 {
	cs := l4Checksum(net.IP(src), net.IP(dst), ipProtoUDP, udp)
	if cs == 0 {
		cs = 0xffff
	}
	return cs
}

// ipv4Header builds a 20-byte IPv4 header for a payload of payloadLen bytes.
// id is set randomly so a path's packets look like independent datagrams.
func ipv4Header(src, dst net.IP, proto byte, payloadLen int, df bool) []byte {
	b := make([]byte, 20)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(20+payloadLen))
	var id [2]byte
	rand.Read(id[:])
	copy(b[4:6], id[:])
	if df {
		binary.BigEndian.PutUint16(b[6:], 0x4000) // Don't Fragment
	}
	b[8] = 64 // TTL
	b[9] = proto
	copy(b[12:16], src.To4())
	copy(b[16:20], dst.To4())
	binary.BigEndian.PutUint16(b[10:], checksum(b))
	return b
}

// parseIPv4 splits a received raw IPv4 datagram into its protocol, source IP
// and layer-4 bytes. Raw sockets on Linux hand up the IP header, so carriers
// parse it here.
func parseIPv4(buf []byte) (proto byte, src net.IP, l4 []byte, ok bool) {
	if len(buf) < 20 || buf[0]>>4 != 4 {
		return 0, nil, nil, false
	}
	ihl := int(buf[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(buf[2:4]))
	if ihl < 20 || len(buf) < ihl || total < ihl || total > len(buf) {
		return 0, nil, nil, false
	}
	return buf[9], net.IP(append([]byte(nil), buf[12:16]...)), buf[ihl:total], true
}

// ---- TCP (pck / sni) ----

// tcpFlags for the segments we emit: data looks like an established connection.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

// buildTCPSeg builds a TCP segment (header + payload) with its checksum filled.
// seq/ack are arbitrary but plausible; flags is PSH|ACK for data.
func buildTCPSeg(src, dst net.IP, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	seg := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(seg[0:], srcPort)
	binary.BigEndian.PutUint16(seg[2:], dstPort)
	binary.BigEndian.PutUint32(seg[4:], seq)
	binary.BigEndian.PutUint32(seg[8:], ack)
	seg[12] = 5 << 4 // data offset 5 words, no options
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:], 0xffff) // window
	copy(seg[20:], payload)
	binary.BigEndian.PutUint16(seg[16:], l4Checksum(src, dst, ipProtoTCP, seg))
	return seg
}

// parseTCP returns the ports, flags and payload of a TCP segment.
func parseTCP(seg []byte) (srcPort, dstPort uint16, flags byte, payload []byte, ok bool) {
	if len(seg) < 20 {
		return 0, 0, 0, nil, false
	}
	off := int(seg[12]>>4) * 4
	if off < 20 || off > len(seg) {
		return 0, 0, 0, nil, false
	}
	return binary.BigEndian.Uint16(seg[0:]), binary.BigEndian.Uint16(seg[2:]), seg[13] & 0x3f, seg[off:], true
}

// ---- ICMP (icmp carrier) ----

// buildICMPEcho builds an ICMP echo message (header + payload). We use echo
// REPLY (type 0) in both directions: the kernel generates nothing in response
// to an unsolicited reply, so no port, no listener and no firewall rule are
// needed, and the raw socket still receives a copy.
const icmpEchoReply = 0

func buildICMPEcho(typ byte, id, seq uint16, payload []byte) []byte {
	m := make([]byte, 8+len(payload))
	m[0] = typ // 0 = echo reply
	binary.BigEndian.PutUint16(m[4:], id)
	binary.BigEndian.PutUint16(m[6:], seq)
	copy(m[8:], payload)
	binary.BigEndian.PutUint16(m[2:], checksum(m))
	return m
}

// parseICMPEcho returns the type, identifier and payload of an ICMP echo message.
func parseICMPEcho(m []byte) (typ byte, id uint16, payload []byte, ok bool) {
	if len(m) < 8 {
		return 0, 0, nil, false
	}
	return m[0], binary.BigEndian.Uint16(m[4:]), m[8:], true
}

// ---- TLS ClientHello decoy (sni carrier) ----

// fakeClientHello builds a syntactically valid TLS 1.2 ClientHello record whose
// SNI extension names sni. The sni carrier sends one at the start of a flow so
// a classifier keying on the first bytes sees a handshake to an allowed name;
// the peer drops any TLS-handshake-looking segment, so it never reaches the
// tunnel. It carries no real key material and starts no real session.
func fakeClientHello(sni string) []byte {
	host := []byte(sni)
	// server_name extension
	sniList := make([]byte, 0, 5+len(host))
	sniList = append(sniList, 0x00)                                           // name_type: host_name
	sniList = appendU16(sniList, uint16(len(host)))                           // host length
	sniList = append(sniList, host...)                                        //
	ext := make([]byte, 0, 4+2+len(sniList))                                  //
	ext = appendU16(ext, 0x0000)                                              // extension_type: server_name
	ext = appendU16(ext, uint16(len(sniList)+2))                              // extension_data length
	ext = appendU16(ext, uint16(len(sniList)))                                // server_name_list length
	ext = append(ext, sniList...)                                             //
	var random [32]byte                                                       //
	rand.Read(random[:])                                                      //
	body := make([]byte, 0, 64+len(ext))                                      //
	body = appendU16(body, 0x0303)                                            // client_version TLS 1.2
	body = append(body, random[:]...)                                         // random
	body = append(body, 0x00)                                                 // session_id length 0
	body = appendU16(body, 0x0002)                                            // cipher_suites length
	body = appendU16(body, 0x1301)                                            // TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)                                           // compression: 1 method, null
	body = appendU16(body, uint16(len(ext)))                                  // extensions length
	body = append(body, ext...)                                               //
	hs := make([]byte, 0, 4+len(body))                                        //
	hs = append(hs, 0x01)                                                     // handshake type: client_hello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body))) // length (24-bit)
	hs = append(hs, body...)                                                  //
	rec := make([]byte, 0, 5+len(hs))                                         //
	rec = append(rec, 0x16, 0x03, 0x01)                                       // content_type handshake, version TLS 1.0
	rec = appendU16(rec, uint16(len(hs)))                                     // record length
	rec = append(rec, hs...)                                                  //
	return rec
}

// looksLikeTLSHandshake reports whether p begins with a TLS handshake record
// (content type 22, major version 3). The sni decoy and any stray real TLS
// both match, so such segments are dropped rather than fed to the tunnel.
func looksLikeTLSHandshake(p []byte) bool {
	return len(p) >= 3 && p[0] == 0x16 && p[1] == 0x03
}

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }
