package main

import (
	"fmt"
	"net"
)

// pathIO is one path's transport underneath the direct engine. The engine only
// ever hands it an opaque payload (an INIT / RESP / DATA datagram) addressed by
// ip:port and reads opaque payloads back, so every carrier looks the same to it.
//
//   - udp / spoof: a real UDP socket (spoof additionally forges the source IP
//     of outgoing packets through a raw sender; it still receives on the socket).
//   - pck / sni:  raw TCP segments with no socket or connection (Linux, root).
//   - icmp:       ICMP echo messages (Linux, root).
//
// For the icmp carrier the port field of an address is the ICMP identifier.
type pathIO interface {
	send(payload []byte, dst *net.UDPAddr) error
	recv(buf []byte) (n int, src *net.UDPAddr, err error)
	setDF(on bool) // Don't-Fragment, for auto-MTU probing
	localPort() int
	Close() error
}

// udpIO carries the tunnel over a UDP socket. sender is the plain socket writer
// or, for carrier = "spoof", the forging raw sender; either way packets are
// received on the socket (a forged source is ignored by the receiver).
type udpIO struct {
	conn   *net.UDPConn
	sender packetSender
}

// conn returns the path's UDP socket when it has one (udp/spoof), for tests.
func (p *directPath) conn() *net.UDPConn {
	if u, ok := p.io.(*udpIO); ok {
		return u.conn
	}
	return nil
}

func (u *udpIO) send(p []byte, dst *net.UDPAddr) error    { return u.sender.sendTo(p, dst) }
func (u *udpIO) recv(b []byte) (int, *net.UDPAddr, error) { return u.conn.ReadFromUDP(b) }
func (u *udpIO) localPort() int                           { return u.conn.LocalAddr().(*net.UDPAddr).Port }
func (u *udpIO) Close() error                             { u.sender.Close(); return u.conn.Close() }

func (u *udpIO) setDF(on bool) {
	if err := setPMTUProbe(u.conn, on); err != nil {
		logf("debug", "direct: pmtu probe mode: %v", err)
	}
	if d, ok := u.sender.(interface{ setDF(bool) }); ok {
		d.setDF(on)
	}
}

// udpPaths wraps ready UDP sockets into udp/spoof paths.
func udpPaths(cfg *DirectConfig, socks []*net.UDPConn) ([]*directPath, error) {
	var paths []*directPath
	for i, s := range socks {
		bigBuffers(s, 8<<20)
		io := &udpIO{conn: s, sender: plainSender{s}}
		if cfg.Carrier == "spoof" {
			snd, err := buildSender(s, cfg.SpoofSource, "")
			if err != nil {
				for _, p := range paths {
					p.io.Close()
				}
				return nil, err
			}
			io.sender = snd
		}
		paths = append(paths, &directPath{idx: i, io: io})
	}
	return paths, nil
}

// openDirectPaths builds the per-path transports for the configured carrier,
// the per-path peer addresses (client: the remote; server: nil until learned),
// and a cleanup func to run on shutdown (e.g. removing a firewall rule).
func openDirectPaths(cfg *DirectConfig) ([]*directPath, []*net.UDPAddr, func(), error) {
	switch cfg.Carrier {
	case "udp", "spoof":
		socks, peers, err := openDirectSockets(cfg)
		if err != nil {
			return nil, nil, nil, err
		}
		paths, err := udpPaths(cfg, socks)
		if err != nil {
			for _, s := range socks {
				s.Close()
			}
			return nil, nil, nil, err
		}
		return paths, peers, func() {}, nil
	case "pck", "sni", "icmp":
		return newRawPaths(cfg) // Linux only (carrier_linux.go / carrier_other.go)
	default:
		return nil, nil, nil, fmt.Errorf("direct: unknown carrier %q", cfg.Carrier)
	}
}

// rawPeers builds the per-path peer address list shared by every raw carrier:
// the client sends path i to remote port base+i; the server learns each from
// authenticated packets. For icmp the port is the ICMP identifier.
func rawPeers(cfg *DirectConfig) ([]*net.UDPAddr, int, error) {
	peers := make([]*net.UDPAddr, cfg.Paths)
	addrStr := cfg.BindAddr
	if cfg.Role == "client" {
		addrStr = cfg.RemoteAddr
	}
	host, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		return nil, 0, err
	}
	base, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, 0, fmt.Errorf("direct: bad port %q: %w", portStr, err)
	}
	if cfg.Role == "client" {
		ip := net.ParseIP(host)
		if ip == nil {
			ips, err := net.LookupIP(host)
			if err != nil || len(ips) == 0 {
				return nil, 0, fmt.Errorf("direct: cannot resolve %q: %v", host, err)
			}
			ip = ips[0]
		}
		if ip.To4() == nil {
			return nil, 0, fmt.Errorf("direct: raw carriers need an IPv4 peer, got %v", ip)
		}
		for i := range peers {
			peers[i] = &net.UDPAddr{IP: ip.To4(), Port: base + i}
		}
	}
	return peers, base, nil
}
