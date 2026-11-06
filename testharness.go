package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Live tunnel test: actually stands up every real tunnel (the six reverse
// transports, spoof/spoofmux, and direct L3) between the two servers, one at a
// time, verifies traffic flows through it, prints progress live on both sides,
// and at the end lists which tunnels run on this pair of servers.
//
// One server runs the AGENT (`pol -test-agent :CTRL`); the other runs the
// RUNNER (`pol -test-run AGENT_IP:CTRL`). The runner drives the test; both exec
// the real pol binary for each tunnel, so what succeeds here is what will work.
//
// The agent prints a random test key; the runner must be given that key. The
// control connection is authenticated with it (challenge/response, the key
// never crosses the wire) and the tunnel token is derived from it, so nobody
// else who can reach the agent's port can drive it.
//
// Control protocol (text lines over TCP):
//   agent->runner: HELLO <nonce>
//   runner->agent: AUTH <hex HMAC(key, "pol-test-auth" | nonce)>
//   agent->runner: WELCOME          (or the agent closes on a bad key)
//   runner->agent: SERVER <transport> <tunnelPort> <pubPort> <echoPort>
//                  DIRECT <udpPort> <localIP> <peerIP> | PROBE <pubPort> | STOP | BYE
//   agent->runner: READY | OK | FAIL | STOPPED
// Every argument is validated (known transport, numeric port, IPv4 address)
// before it reaches a generated config.

var testTransports = []string{"tcp", "tcpmux", "ws", "wsmux", "wss", "wssmux", "spoof", "spoofmux"}

func startPol(cfg string) (*exec.Cmd, string, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, "", err
	}
	f, err := os.CreateTemp("", "poltest-*.toml")
	if err != nil {
		return nil, "", err
	}
	f.WriteString(cfg)
	f.Close()
	cmd := exec.Command(exe, "-c", f.Name())
	if err := cmd.Start(); err != nil {
		os.Remove(f.Name())
		return nil, "", err
	}
	return cmd, f.Name(), nil
}

func killPol(cmd *exec.Cmd, cfgPath string) {
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
	if cfgPath != "" {
		os.Remove(cfgPath)
	}
}

// ---- agent (runs on the server that will host the tunnels) ----

const testCmdTimeout = 2 * time.Minute

func testAuthMAC(key, nonce string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte("pol-test-auth|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// testToken derives the per-session tunnel token from the key and nonce, so the
// token is never sent in the clear.
func testToken(key, nonce string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte("pol-test-token|" + nonce))
	return hex.EncodeToString(h.Sum(nil))
}

func validPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0 && n < 65536 && strconv.Itoa(n) == s
}

func validIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && ip.String() == s
}

func runTestAgent(addr string) error {
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	kb := make([]byte, 12)
	if _, err := rand.Read(kb); err != nil {
		return err
	}
	key := hex.EncodeToString(kb)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Printf("test agent up on %s\n", addr)
	fmt.Printf("test key: %s   ← enter this on the other server when it asks\n", key)
	fmt.Println("Ctrl-C when done.")
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		agentSession(c, key)
	}
}

func agentSession(c net.Conn, key string) {
	defer c.Close()
	var child *exec.Cmd
	var cfgPath string
	defer func() { killPol(child, cfgPath) }()

	nb := make([]byte, 16)
	rand.Read(nb)
	nonce := hex.EncodeToString(nb)
	c.SetDeadline(time.Now().Add(15 * time.Second))
	fmt.Fprintf(c, "HELLO %s\n", nonce)
	rd := bufio.NewReader(io.LimitReader(c, 1<<20))
	line, err := rd.ReadString('\n')
	f := strings.Fields(line)
	if err != nil || len(f) != 2 || f[0] != "AUTH" ||
		!hmac.Equal([]byte(f[1]), []byte(testAuthMAC(key, nonce))) {
		fmt.Printf("  [agent] rejected a connection from %v (wrong test key)\n", c.RemoteAddr())
		time.Sleep(time.Second)
		return
	}
	fmt.Fprintln(c, "WELCOME")
	token := testToken(key, nonce)
	fmt.Printf("  [agent] runner %v authenticated\n", c.RemoteAddr())

	sc := bufio.NewScanner(rd)
	for {
		c.SetDeadline(time.Now().Add(testCmdTimeout))
		if !sc.Scan() {
			return
		}
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "SERVER":
			if len(f) != 5 || !validTransport(f[1]) || !validPort(f[2]) || !validPort(f[3]) || !validPort(f[4]) {
				fmt.Fprintln(c, "FAIL")
				continue
			}
			killPol(child, cfgPath)
			transport, tunnelPort, pubPort, echoPort := f[1], f[2], f[3], f[4]
			fmt.Printf("  [agent] %-9s server :%s  →  echo 127.0.0.1:%s\n", transport, tunnelPort, echoPort)
			cfg := fmt.Sprintf("[server]\nbind_addr=\"0.0.0.0:%s\"\ntransport=\"%s\"\ntoken=\"%s\"\nlog_level=\"error\"\nports=[\"127.0.0.1:%s=127.0.0.1:%s\"]\n",
				tunnelPort, transport, token, pubPort, echoPort)
			child, cfgPath, _ = startPol(cfg)
			time.Sleep(1500 * time.Millisecond)
			fmt.Fprintln(c, "READY")
		case "DIRECT":
			if len(f) != 4 || !validPort(f[1]) || !validIPv4(f[2]) || !validIPv4(f[3]) {
				fmt.Fprintln(c, "FAIL")
				continue
			}
			killPol(child, cfgPath)
			udpPort, lip, pip := f[1], f[2], f[3]
			fmt.Printf("  [agent] direct    udp :%s  (%s ⇄ %s)\n", udpPort, lip, pip)
			cfg := fmt.Sprintf("[direct]\nrole=\"server\"\nbind_addr=\"0.0.0.0:%s\"\ntoken=\"%s\"\ntun_name=\"poltest0\"\nlocal_ip=\"%s\"\npeer_ip=\"%s\"\nmtu=1400\nlog_level=\"error\"\n",
				udpPort, token, lip, pip)
			child, cfgPath, _ = startPol(cfg)
			time.Sleep(1500 * time.Millisecond)
			fmt.Fprintln(c, "READY")
		case "PROBE":
			if len(f) != 2 || !validPort(f[1]) {
				fmt.Fprintln(c, "FAIL")
				continue
			}
			if agentProbe(f[1]) {
				fmt.Fprintln(c, "OK")
			} else {
				fmt.Fprintln(c, "FAIL")
			}
		case "STOP":
			killPol(child, cfgPath)
			child, cfgPath = nil, ""
			fmt.Fprintln(c, "STOPPED")
		case "BYE":
			return
		}
	}
}

// agentProbe connects to the local public port, sends a nonce and checks it
// comes back through the tunnel (server → peer's client → peer's echo → back).
func agentProbe(pubPort string) bool {
	var conn net.Conn
	var err error
	for i := 0; i < 20; i++ { // give the peer's client a moment to attach
		conn, err = net.DialTimeout("tcp", "127.0.0.1:"+pubPort, time.Second)
		if err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		return false
	}
	defer conn.Close()
	nonce := make([]byte, 32)
	rand.Read(nonce)
	conn.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := conn.Write(nonce); err != nil {
		return false
	}
	got := make([]byte, 32)
	if _, err := io.ReadFull(conn, got); err != nil {
		return false
	}
	return bytes.Equal(got, nonce)
}

// ---- runner (drives the test from the other server) ----

func runTestRun(agentAddr, key string) error {
	host, _, err := net.SplitHostPort(agentAddr)
	if err != nil {
		return fmt.Errorf("agent address must be HOST:PORT: %w", err)
	}
	ctl, err := net.DialTimeout("tcp", agentAddr, 8*time.Second)
	if err != nil {
		return fmt.Errorf("cannot reach the agent at %s: %w", agentAddr, err)
	}
	defer ctl.Close()
	rd := bufio.NewReader(ctl)

	if key == "" {
		fmt.Print("test key (printed by the agent): ")
		k, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		key = strings.TrimSpace(k)
	}
	ctl.SetDeadline(time.Now().Add(15 * time.Second))
	f := strings.Fields(readLine(rd))
	if len(f) != 2 || f[0] != "HELLO" {
		return errors.New("agent did not greet (is it a current pol -test-agent?)")
	}
	nonce := f[1]
	fmt.Fprintf(ctl, "AUTH %s\n", testAuthMAC(key, nonce))
	if strings.TrimSpace(readLine(rd)) != "WELCOME" {
		return errors.New("agent rejected the test key")
	}
	ctl.SetDeadline(time.Time{})
	token := testToken(key, nonce)

	const echoPort = "47900"
	stopEcho := startEcho("127.0.0.1:" + echoPort)
	defer stopEcho()

	fmt.Printf("live tunnel test against agent %s\n\n", host)
	type res struct {
		name string
		ok   bool
	}
	var results []res

	for i, tr := range testTransports {
		tunnelPort := fmt.Sprintf("%d", 47000+i)
		pubPort := fmt.Sprintf("%d", 47100+i)
		fmt.Printf("  testing %-9s ... ", tr)
		os.Stdout.Sync()
		fmt.Fprintf(ctl, "SERVER %s %s %s %s\n", tr, tunnelPort, pubPort, echoPort)
		readLine(rd) // READY
		cfg := fmt.Sprintf("[client]\nremote_addr=\"%s\"\ntransport=\"%s\"\ntoken=\"%s\"\nconnection_pool=2\nlog_level=\"error\"\n",
			net.JoinHostPort(host, tunnelPort), tr, token)
		child, cfgPath, _ := startPol(cfg)
		time.Sleep(2500 * time.Millisecond)
		fmt.Fprintf(ctl, "PROBE %s\n", pubPort)
		ok := strings.TrimSpace(readLine(rd)) == "OK"
		fmt.Println(mark(ok))
		results = append(results, res{tr, ok})
		killPol(child, cfgPath)
		fmt.Fprintln(ctl, "STOP")
		readLine(rd) // STOPPED
	}

	// direct L3
	fmt.Printf("  testing %-9s ... ", "direct")
	os.Stdout.Sync()
	aip, bip := "10.231.0.1", "10.231.0.2"
	fmt.Fprintf(ctl, "DIRECT %s %s %s\n", "47200", aip, bip)
	readLine(rd) // READY
	dcfg := fmt.Sprintf("[direct]\nrole=\"client\"\nremote_addr=\"%s\"\ntoken=\"%s\"\ntun_name=\"poltest0\"\nlocal_ip=\"%s\"\npeer_ip=\"%s\"\nmtu=1400\nlog_level=\"error\"\n",
		net.JoinHostPort(host, "47200"), token, bip, aip)
	dchild, dpath, _ := startPol(dcfg)
	time.Sleep(2500 * time.Millisecond)
	dok := pingHost(aip)
	fmt.Println(mark(dok))
	results = append(results, res{"direct", dok})
	killPol(dchild, dpath)
	fmt.Fprintln(ctl, "STOP")
	readLine(rd)
	fmt.Fprintln(ctl, "BYE")

	// summary
	fmt.Println("\n── which tunnels run on these two servers ──")
	var good []string
	for _, r := range results {
		fmt.Printf("  %-9s %s\n", r.name, mark(r.ok))
		if r.ok {
			good = append(good, r.name)
		}
	}
	fmt.Println("────────────────────────────────────────────")
	if len(good) == 0 {
		fmt.Println("no tunnel got through — check firewall/ports between the servers.")
	} else {
		fmt.Printf("usable: %s\n", strings.Join(good, ", "))
	}
	return nil
}

func mark(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}

func readLine(rd *bufio.Reader) string {
	line, _ := rd.ReadString('\n')
	return line
}

func startEcho(addr string) func() {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return func() {}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return func() { ln.Close() }
}

func pingHost(ip string) bool {
	return exec.Command("ping", "-c", "2", "-W", "3", ip).Run() == nil
}
