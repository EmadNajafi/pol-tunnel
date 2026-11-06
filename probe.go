package main

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

// Link test (BackPack-style): a listener on one server and a tester on the other
// measure the route — latency, jitter and packet loss over both TCP and UDP —
// check whether the datacenter allows a forged source IP, and recommend a
// transport. A TCP control connection carries PING/PONG and the UDP-arrival
// counts; UDP datagrams carry the data probes (the listener echoes them back).

// ---- listener ----

type probeListener struct {
	mu   sync.Mutex
	seen map[string]int
	src  map[string]string
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
			// echo back (for the UDP latency/loss test); spoofed packets' echoes
			// go to the forged source and are lost — those use the COUNT path.
			uc.WriteToUDP(buf[:n], from)
		}
	}()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Printf("link-test listener up on %s (tcp+udp). Run the test on the other server; Ctrl-C when done.\n", addr)
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

type linkStats struct {
	ok       bool
	sent     int
	recv     int
	avgMS    float64
	jitterMS float64
	lossPct  int
}

type probeResult struct {
	tcp           linkStats
	udp           linkStats
	spoofTested   bool
	spoofOK       bool
	spoofSeenFrom string
}

const probeSamples = 30

func runProbe(peer, spoofSrc string) error {
	host, port, err := net.SplitHostPort(peer)
	if err != nil {
		return fmt.Errorf("peer must be HOST:PORT: %w", err)
	}
	var r probeResult
	fmt.Printf("link test to %s  (%d samples each) ...\n\n", peer, probeSamples)

	// --- TCP control + latency/jitter/loss via PING/PONG ---
	var cc net.Conn
	var rd *bufio.Reader
	if conn, err := net.DialTimeout("tcp", peer, 8*time.Second); err == nil {
		cc = conn
		rd = bufio.NewReader(cc)
		defer cc.Close()
		r.tcp = pingLoop(cc, rd)
	} else {
		fmt.Printf("TCP connect failed: %v\n", err)
	}

	// --- UDP latency/jitter/loss via echo ---
	if uc, err := net.Dial("udp", net.JoinHostPort(host, port)); err == nil {
		r.udp = udpEcho(uc)
		uc.Close()
	}

	// --- IP spoofing (Linux + root): does a forged source reach the peer? ---
	if spoofSrc != "" && cc != nil {
		if sender, err := buildSender(nil, spoofSrc, peer); err == nil {
			r.spoofTested = true
			tag := fmt.Sprintf("S%d", time.Now().UnixNano())
			dst, _ := net.ResolveUDPAddr("udp", peer)
			for i := 0; i < 20; i++ {
				sender.sendTo([]byte(tag), dst)
				time.Sleep(15 * time.Millisecond)
			}
			sender.Close()
			got, from := askCount(cc, rd, tag)
			r.spoofOK = got > 0
			r.spoofSeenFrom = from
		} else {
			fmt.Printf("(ip-spoofing test skipped: %v)\n", err)
		}
	}

	printLinkReport(r)
	return nil
}

// pingLoop measures TCP RTTs with sequential PING/PONG.
func pingLoop(cc net.Conn, rd *bufio.Reader) linkStats {
	var rtts []float64
	st := linkStats{ok: true, sent: probeSamples}
	for i := 0; i < probeSamples; i++ {
		t0 := time.Now()
		if _, err := fmt.Fprintln(cc, "PING"); err != nil {
			break
		}
		cc.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := rd.ReadString('\n'); err != nil {
			continue // lost / timed out
		}
		rtts = append(rtts, float64(time.Since(t0).Microseconds())/1000.0)
		time.Sleep(10 * time.Millisecond)
	}
	cc.SetReadDeadline(time.Time{})
	fill(&st, rtts)
	return st
}

// udpEcho measures UDP RTT/loss with sequential echo requests.
func udpEcho(uc net.Conn) linkStats {
	var rtts []float64
	st := linkStats{sent: probeSamples}
	buf := make([]byte, 2048)
	for i := 0; i < probeSamples; i++ {
		msg := fmt.Sprintf("E%d-%d", i, time.Now().UnixNano())
		t0 := time.Now()
		if _, err := uc.Write([]byte(msg)); err != nil {
			break
		}
		uc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := uc.Read(buf)
		if err != nil || string(buf[:n]) != msg {
			continue
		}
		rtts = append(rtts, float64(time.Since(t0).Microseconds())/1000.0)
		time.Sleep(10 * time.Millisecond)
	}
	st.ok = len(rtts) > 0
	fill(&st, rtts)
	return st
}

// fill computes recv count, loss%, average latency and jitter (mean absolute
// difference between consecutive RTTs, RFC 3550 style).
func fill(st *linkStats, rtts []float64) {
	st.recv = len(rtts)
	if st.sent > 0 {
		st.lossPct = (st.sent - st.recv) * 100 / st.sent
	}
	if len(rtts) == 0 {
		return
	}
	var sum, jit float64
	for i, v := range rtts {
		sum += v
		if i > 0 {
			jit += math.Abs(v - rtts[i-1])
		}
	}
	st.avgMS = sum / float64(len(rtts))
	if len(rtts) > 1 {
		st.jitterMS = jit / float64(len(rtts)-1)
	}
}

func askCount(cc net.Conn, br *bufio.Reader, tag string) (int, string) {
	if cc == nil {
		return 0, ""
	}
	time.Sleep(300 * time.Millisecond)
	fmt.Fprintf(cc, "COUNT %s\n", tag)
	cc.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, _ := br.ReadString('\n')
	cc.SetReadDeadline(time.Time{})
	var n int
	var src string
	fmt.Sscanf(strings.TrimSpace(line), "COUNT %d %s", &n, &src)
	return n, src
}

func printLinkReport(r probeResult) {
	row := func(name string, s linkStats) {
		if !s.ok {
			fmt.Printf("  %-5s  ✗ unreachable\n", name)
			return
		}
		fmt.Printf("  %-5s  ✓  latency %.1f ms   jitter %.1f ms   loss %d%%\n", name, s.avgMS, s.jitterMS, s.lossPct)
	}
	fmt.Println("── link test ───────────────────────────────")
	row("TCP", r.tcp)
	row("UDP", r.udp)
	if r.spoofTested {
		if r.spoofOK {
			fmt.Printf("  SPOOF  ✓  forged source allowed (peer saw %s)\n", r.spoofSeenFrom)
		} else {
			fmt.Printf("  SPOOF  ✗  datacenter filters forged source (BCP38)\n")
		}
	} else {
		fmt.Printf("  SPOOF  -  not tested (Linux+root only)\n")
	}
	fmt.Println("────────────────────────────────────────────")
	fmt.Println("recommendation:")
	for _, line := range recommend(r) {
		fmt.Println("  " + line)
	}
}

// recommend picks a transport from the measured route, in the spirit of
// BackPack's link test (favouring the ARQ/KCP-style transport on lossy routes,
// and TCP-mux on clean ones).
func recommend(r probeResult) []string {
	tcp, udp := r.tcp, r.udp
	var out []string
	switch {
	case !tcp.ok && !udp.ok:
		return []string{"✗ neither TCP nor UDP reached the peer — the path looks fully blocked.",
			"check the port/firewall, or try port 443 / a different server."}
	case udp.ok && (udp.lossPct >= 5 || udp.jitterMS >= 30) && (!tcp.ok || udp.lossPct <= tcp.lossPct+10):
		out = append(out, "→ spoofmux   (UDP path, lossy/jittery — the KCP-style ARQ handles loss best)")
	case tcp.ok && tcp.lossPct <= 2 && tcp.jitterMS < 30:
		out = append(out, "→ tcpmux     (clean, low-latency route — simplest and efficient)")
	case tcp.ok:
		out = append(out, "→ tcpmux     (TCP path works; mux rides out the loss/jitter)")
	case udp.ok:
		out = append(out, "→ spoofmux   (only UDP got through)")
	}
	out = append(out, "+ add  encryption = true  on both ends for an encrypted tunnel")
	if tcp.ok {
		out = append(out, "• to look like plain HTTPS (CDN / DPI): use  wssmux")
	}
	if r.spoofOK {
		out = append(out, "• forged-source UDP is allowed here: you may also set  spoof_source")
	}
	return out
}
