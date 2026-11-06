package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Connectivity probe: a listener on one server and a tester on the other decide
// which transports the network path between them actually allows. It measures
// TCP reachability + latency, UDP reachability + loss, and whether the tester's
// datacenter lets it send packets with a forged source IP (BCP38).
//
// A TCP control connection carries the test commands; UDP datagrams carry the
// data probes. The listener reports what it received back over the control link.

// ---- listener ----

type probeListener struct {
	mu    sync.Mutex
	seen  map[string]int    // tag -> datagrams received
	src   map[string]string // tag -> last observed source IP
}

func runProbeListen(addr string) error {
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	pl := &probeListener{seen: map[string]int{}, src: map[string]string{}}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	uc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			tag := string(buf[:n])
			pl.mu.Lock()
			pl.seen[tag]++
			pl.src[tag] = from.IP.String()
			pl.mu.Unlock()
		}
	}()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Printf("probe listener up on %s (tcp+udp). Run the tester on the other server; Ctrl-C when done.\n", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go pl.handle(c)
	}
}

func (pl *probeListener) handle(c net.Conn) {
	defer c.Close()
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "PING":
			fmt.Fprintln(c, "PONG")
		case "COUNT":
			if len(f) < 2 {
				fmt.Fprintln(c, "COUNT 0 -")
				continue
			}
			pl.mu.Lock()
			n, src := pl.seen[f[1]], pl.src[f[1]]
			pl.mu.Unlock()
			if src == "" {
				src = "-"
			}
			fmt.Fprintf(c, "COUNT %d %s\n", n, src)
		case "BYE":
			return
		}
	}
}

// ---- tester ----

type probeResult struct {
	tcpOK         bool
	tcpRTT        time.Duration
	udpOK         bool
	udpLoss       int // percent
	udpRTTnote    string
	spoofTested   bool
	spoofOK       bool
	spoofSeenFrom string
}

func runProbe(peer, spoofSrc string) error {
	host, port, err := net.SplitHostPort(peer)
	if err != nil {
		return fmt.Errorf("peer must be HOST:PORT: %w", err)
	}
	var r probeResult
	fmt.Printf("testing path to %s ...\n\n", peer)

	// --- TCP control ---
	var cc net.Conn
	var rd *bufio.Reader
	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", peer, 8*time.Second)
	if err != nil {
		fmt.Printf("TCP %-14s %s\n", peer, "UNREACHABLE: "+err.Error())
	} else {
		cc = conn
		rd = bufio.NewReader(cc)
		r.tcpOK = true
		r.tcpRTT = time.Since(t0)
		defer cc.Close()
		fmt.Fprintln(cc, "PING")
		cc.SetReadDeadline(time.Now().Add(5 * time.Second))
		rd.ReadString('\n')
	}

	// --- UDP plain ---
	udpPeer := net.JoinHostPort(host, port)
	if uc, err := net.Dial("udp", udpPeer); err == nil {
		tag := fmt.Sprintf("U%d", time.Now().UnixNano())
		for i := 0; i < 20; i++ {
			uc.Write([]byte(tag))
			time.Sleep(20 * time.Millisecond)
		}
		uc.Close()
		if r.tcpOK {
			got, _ := askCount(cc, rd, tag)
			r.udpOK = got > 0
			r.udpLoss = (20 - got) * 100 / 20
			if r.udpLoss < 0 {
				r.udpLoss = 0
			}
		} else {
			r.udpRTTnote = "cannot confirm (TCP control down)"
		}
	}

	// --- IP spoofing (Linux, needs the raw sender) ---
	if spoofSrc != "" && r.tcpOK {
		r.spoofTested = true
		if sender, err := buildSender(nil, spoofSrc, peer); err == nil {
			tag := fmt.Sprintf("S%d", time.Now().UnixNano())
			dst, _ := net.ResolveUDPAddr("udp", peer)
			for i := 0; i < 20; i++ {
				sender.sendTo([]byte(tag), dst)
				time.Sleep(20 * time.Millisecond)
			}
			sender.Close()
			got, from := askCount(cc, rd, tag)
			r.spoofOK = got > 0
			r.spoofSeenFrom = from
		} else {
			r.spoofTested = false // not supported here (non-Linux / no root)
			fmt.Printf("(ip-spoofing test skipped: %v)\n", err)
		}
	}

	printProbeReport(r)
	return nil
}

func askCount(cc net.Conn, br *bufio.Reader, tag string) (int, string) {
	if cc == nil {
		return 0, ""
	}
	time.Sleep(300 * time.Millisecond) // let the last datagrams land
	fmt.Fprintf(cc, "COUNT %s\n", tag)
	cc.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, _ := br.ReadString('\n')
	var n int
	var src string
	fmt.Sscanf(strings.TrimSpace(line), "COUNT %d %s", &n, &src)
	return n, src
}

func printProbeReport(r probeResult) {
	ok := func(b bool) string {
		if b {
			return "✓"
		}
		return "✗"
	}
	fmt.Println("── results ─────────────────────────────────")
	if r.tcpOK {
		fmt.Printf("TCP reachable   %s  (%.0f ms)\n", ok(true), float64(r.tcpRTT.Milliseconds()))
	} else {
		fmt.Printf("TCP reachable   %s\n", ok(false))
	}
	if r.udpOK {
		fmt.Printf("UDP reachable   %s  (%d%% loss)\n", ok(true), r.udpLoss)
	} else {
		fmt.Printf("UDP reachable   %s  %s\n", ok(false), r.udpRTTnote)
	}
	if r.spoofTested {
		if r.spoofOK {
			fmt.Printf("IP spoofing     %s  (peer saw forged source %s)\n", ok(true), r.spoofSeenFrom)
		} else {
			fmt.Printf("IP spoofing     %s  (datacenter filters forged source — BCP38)\n", ok(false))
		}
	} else {
		fmt.Printf("IP spoofing     -  (not tested; Linux+root only)\n")
	}
	fmt.Println("────────────────────────────────────────────")
	fmt.Println("you can build these tunnels:")
	if r.tcpOK {
		fmt.Println("  • tcp, tcpmux, ws, wsmux, wss, wssmux   (TCP path open)")
	} else {
		fmt.Println("  • (no TCP-based transport — TCP path blocked)")
	}
	if r.udpOK {
		fmt.Println("  • spoof, spoofmux, direct               (UDP path open)")
		if r.spoofOK {
			fmt.Println("  • spoof_source usable                   (forged-source UDP allowed)")
		}
	} else {
		fmt.Println("  • (no UDP transport — UDP path blocked)")
	}
}
