//go:build linux

package main

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
)

// Raw-socket direct carriers for Linux (need root / CAP_NET_RAW):
//
//   pck   TCP segments built by hand, with no socket and no connection. The
//         path looks like one TCP flow carrying data; there is no handshake.
//   sni   pck, with a TLS ClientHello naming an allowed domain sent first, so a
//         classifier keying on the start of the flow sees a handshake to that
//         name. The decoy carries no key material and starts no real session.
//   icmp  ICMP echo-reply messages carrying the tunnel, in both directions.
//
// All of them send a full IPv4 packet through one IP_HDRINCL socket (so the
// source IP and Don't-Fragment bit are ours to set) and receive through a raw
// socket for their protocol. The payload they carry is the same opaque
// INIT/RESP/DATA datagram every carrier moves, so the engine is unchanged.

// rawIO is the shared machinery: a send socket (IP_HDRINCL) and a receive
// socket for one IP protocol.
type rawIO struct {
	sendFd int
	recvFd int
	proto  byte
	df     atomic.Bool

	srcMu sync.Mutex
	srcIP map[string]net.IP // outbound source IP per destination, cached
}

func openRawIO(proto byte) (*rawIO, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("raw carrier needs root / CAP_NET_RAW")
	}
	sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("raw send socket: %w", err)
	}
	if err := syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(sendFd)
		return nil, err
	}
	recvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, int(proto))
	if err != nil {
		syscall.Close(sendFd)
		return nil, fmt.Errorf("raw recv socket: %w", err)
	}
	// a raw socket sees every packet of its protocol on the host: give it room
	forceSockBuf(recvFd, 8<<20)
	forceSockBuf(sendFd, 8<<20)
	return &rawIO{sendFd: sendFd, recvFd: recvFd, proto: proto, srcIP: map[string]net.IP{}}, nil
}

// srcFor returns the source IP the kernel would use to reach dst (so our hand
// built IP header and its checksum match the route the packet actually takes).
func (r *rawIO) srcFor(dst net.IP) net.IP {
	key := dst.String()
	r.srcMu.Lock()
	defer r.srcMu.Unlock()
	if ip, ok := r.srcIP[key]; ok {
		return ip
	}
	ip := net.IPv4(127, 0, 0, 1).To4()
	if c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: dst, Port: 9}); err == nil {
		if la, ok := c.LocalAddr().(*net.UDPAddr); ok && la.IP.To4() != nil {
			ip = la.IP.To4()
		}
		c.Close()
	}
	r.srcIP[key] = ip
	return ip
}

func (r *rawIO) sendIP(pkt []byte, dst net.IP) error {
	var a [4]byte
	copy(a[:], dst.To4())
	return syscall.Sendto(r.sendFd, pkt, 0, &syscall.SockaddrInet4{Addr: a})
}

func (r *rawIO) setDF(on bool) { r.df.Store(on) }

func (r *rawIO) Close() error {
	syscall.Close(r.sendFd)
	syscall.Close(r.recvFd)
	return nil
}

// ---- pck / sni: TCP segments ----

type pckIO struct {
	raw  *rawIO
	port uint16 // this path's TCP port (same on both ends)
	sni  string // "" = pck; a domain = sni (sends a decoy ClientHello first)

	helloMu   sync.Mutex
	helloSent map[string]bool // per-destination, whether the decoy was sent
}

func (p *pckIO) send(payload []byte, dst *net.UDPAddr) error {
	src := p.raw.srcFor(dst.IP)
	if p.sni != "" {
		p.helloMu.Lock()
		if !p.helloSent[dst.IP.String()] {
			p.helloSent[dst.IP.String()] = true
			p.helloMu.Unlock()
			p.sendSeg(src, dst.IP, fakeClientHello(p.sni))
		} else {
			p.helloMu.Unlock()
		}
	}
	return p.sendSeg(src, dst.IP, payload)
}

func (p *pckIO) sendSeg(src, dst net.IP, payload []byte) error {
	seg := buildTCPSeg(src, dst, p.port, p.port, rand.Uint32(), rand.Uint32(), tcpPSH|tcpACK, payload)
	pkt := append(ipv4Header(src, dst, ipProtoTCP, len(seg), p.raw.df.Load()), seg...)
	return p.raw.sendIP(pkt, dst)
}

func (p *pckIO) recv(buf []byte) (int, *net.UDPAddr, error) {
	for {
		n, from, err := syscall.Recvfrom(p.raw.recvFd, buf, 0)
		if err != nil {
			return 0, nil, err
		}
		proto, src, l4, ok := parseIPv4(buf[:n])
		if !ok || proto != ipProtoTCP {
			continue
		}
		_, dstPort, flags, payload, ok := parseTCP(l4)
		if !ok || dstPort != p.port || flags&(tcpRST|tcpSYN|tcpFIN) != 0 {
			continue // not ours, or a control segment we don't carry data in
		}
		if len(payload) == 0 || looksLikeTLSHandshake(payload) {
			continue // keep-open segment or the sni decoy: never tunnel data
		}
		_ = from
		copy(buf, payload)
		return len(payload), &net.UDPAddr{IP: src, Port: int(p.port)}, nil
	}
}

func (p *pckIO) setDF(on bool)  { p.raw.setDF(on) }
func (p *pckIO) localPort() int { return int(p.port) }
func (p *pckIO) Close() error   { return p.raw.Close() }

// ---- icmp: echo request (client) / echo reply (server) ----
//
// The flow mimics a normal ping: the client sends echo REQUESTS and the server
// answers with echo REPLIES. This matters because stateful middleboxes drop an
// echo reply that has no matching request, so echo replies in both directions
// (which would avoid the kernel's auto-reply) do not survive real paths. The
// cost of the request direction is that the server's kernel also auto-answers
// the client's requests; those carry the client's own (i2r-sealed) bytes back,
// so the client fails to open them and drops them — wasteful but harmless.
type icmpIO struct {
	raw      *rawIO
	id       uint16 // this path's ICMP identifier
	seq      atomic.Uint32
	sendType byte // client: echo request (8); server: echo reply (0)
	recvType byte // the type the peer sends (opposite of sendType)
}

func (c *icmpIO) send(payload []byte, dst *net.UDPAddr) error {
	src := c.raw.srcFor(dst.IP)
	seq := uint16(c.seq.Add(1))
	msg := buildICMPEcho(c.sendType, c.id, seq, payload)
	pkt := append(ipv4Header(src, dst.IP, ipProtoICMP, len(msg), c.raw.df.Load()), msg...)
	return c.raw.sendIP(pkt, dst.IP)
}

func (c *icmpIO) recv(buf []byte) (int, *net.UDPAddr, error) {
	for {
		n, _, err := syscall.Recvfrom(c.raw.recvFd, buf, 0)
		if err != nil {
			return 0, nil, err
		}
		proto, src, l4, ok := parseIPv4(buf[:n])
		if !ok || proto != ipProtoICMP {
			continue
		}
		typ, id, payload, ok := parseICMPEcho(l4)
		if !ok || typ != c.recvType || id != c.id || len(payload) == 0 {
			continue
		}
		copy(buf, payload)
		return len(payload), &net.UDPAddr{IP: src, Port: int(c.id)}, nil
	}
}

func (c *icmpIO) setDF(on bool)  { c.raw.setDF(on) }
func (c *icmpIO) localPort() int { return int(c.id) }
func (c *icmpIO) Close() error   { return c.raw.Close() }

// ---- construction + RST guard ----

// rstGuardTag marks the iptables rule that drops the kernel's RSTs for the pck
// and sni ports, so it can be found and removed on exit (or after a crash).
const rstGuardTag = "pol-direct-rst-guard"

func newRawPaths(cfg *DirectConfig) ([]*directPath, []*net.UDPAddr, func(), error) {
	peers, base, err := rawPeers(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	paths := make([]*directPath, 0, cfg.Paths)
	cleanup := func() {}
	fail := func(err error) ([]*directPath, []*net.UDPAddr, func(), error) {
		for _, p := range paths {
			p.io.Close()
		}
		cleanup()
		return nil, nil, nil, err
	}

	switch cfg.Carrier {
	case "pck", "sni":
		if err := installRSTGuard(base, cfg.Paths); err != nil {
			logf("warn", "direct: could not add the RST-drop firewall rule (%v); the kernel may reset the %s flow, weakening it", err, cfg.Carrier)
		} else {
			cleanup = func() { removeRSTGuard(base, cfg.Paths) }
		}
		for i := 0; i < cfg.Paths; i++ {
			raw, err := openRawIO(ipProtoTCP)
			if err != nil {
				return fail(err)
			}
			paths = append(paths, &directPath{idx: i, io: &pckIO{
				raw: raw, port: uint16(base + i), sni: cfg.SNIDomain, helloSent: map[string]bool{},
			}})
		}
	case "icmp":
		sendType, recvType := byte(icmpEchoRequest), byte(icmpEchoReply) // client
		if cfg.Role == "server" {
			sendType, recvType = icmpEchoReply, icmpEchoRequest
		}
		for i := 0; i < cfg.Paths; i++ {
			raw, err := openRawIO(ipProtoICMP)
			if err != nil {
				return fail(err)
			}
			paths = append(paths, &directPath{idx: i, io: &icmpIO{
				raw: raw, id: uint16(base + i), sendType: sendType, recvType: recvType,
			}})
		}
	default:
		return nil, nil, nil, fmt.Errorf("direct: %q is not a raw carrier", cfg.Carrier)
	}
	return paths, peers, cleanup, nil
}

func iptablesRuleArgs(base, n int) []string {
	return []string{
		"OUTPUT", "-p", "tcp",
		"--sport", fmt.Sprintf("%d:%d", base, base+n-1),
		"--tcp-flags", "RST", "RST", "-j", "DROP",
		"-m", "comment", "--comment", rstGuardTag,
	}
}

// installRSTGuard drops the kernel's RSTs for our TCP ports. Incoming segments
// land on ports with no listening socket, so without this the kernel resets
// them, which a middlebox would see as the flow dying. Any identical rule left
// by an earlier run (same ports) is cleared first so repeats don't pile up.
func installRSTGuard(base, n int) error {
	if _, err := exec.LookPath("iptables"); err != nil {
		return err
	}
	removeRSTGuard(base, n)
	out, err := exec.Command("iptables", append([]string{"-I"}, iptablesRuleArgs(base, n)...)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (%s)", err, out)
	}
	return nil
}

// removeRSTGuard deletes the RST-guard rule for these ports, repeatedly, until
// none is left (so duplicates from a crash are cleaned up too). The rule spec,
// including our comment, identifies exactly the rules we added.
func removeRSTGuard(base, n int) {
	if _, err := exec.LookPath("iptables"); err != nil {
		return
	}
	for i := 0; i < 64; i++ {
		if err := exec.Command("iptables", append([]string{"-D"}, iptablesRuleArgs(base, n)...)...).Run(); err != nil {
			return // no more matching rules
		}
	}
}
