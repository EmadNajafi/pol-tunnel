package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand/v2"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Connection Test: which tunnels actually survive the path between two servers.
//
// Whether a transport works between a given pair of servers is a property of
// the route, not of the program: some paths let a new flow carry a few packets
// and then cut it, some drop UDP, some reset TLS. The only honest way to know
// is to run every tunnel across the route for real, so this does.
//
// The Iran server starts a real pol engine (a separate process with a
// throwaway config) for every transport on free ports, plus a small
// coordinator, and prints a short link. The kharej, given the link, asks the
// coordinator for the test's settings, starts its own end of every tunnel and
// an echo service, and says it has joined. The Iran server then pushes traffic
// through every tunnel at once — one echo a second for a minute over the same
// connection, as a user's connection would see it — measures download and
// upload speed on the ones that carried everything, and reports which carried
// it all (OK), which dropped (UNSTABLE) and which never came up (DOWN). Both
// servers draw the same live table and print the verdict and the best
// settings. Nothing is left behind: the engines, their configs and the test
// interfaces are gone when it ends.
//
// The Iran side is the judge because that is where users arrive. The kharej
// learns the verdict from the coordinator, one short authenticated exchange per
// question, so even a path that cuts flows after a few packets still carries it.

// Variables rather than constants so a test can run the whole thing in seconds.
var (
	ctJoinWait    = 15 * time.Minute // how long Iran waits for the kharej
	ctConnectWait = 60 * time.Second // how long a tunnel has to carry its first echo
	ctSoak        = 60               // one-second echoes a tunnel must carry
	ctEchoEvery   = time.Second
	ctSpeedWarm   = time.Second
	ctSpeedDur    = 3 * time.Second
	ctSlack       = 5 * time.Minute // kharej gives up this long past the schedule
	ctPollEvery   = time.Second
	ctStartGrace  = 1500 * time.Millisecond // an engine that exits before this failed to start
)

// ctBinary is the engine to run (this same binary); ctEngineEnv is extra
// environment for it. Variables so the tests can run engines from the test binary.
var (
	ctBinary    = os.Executable
	ctEngineEnv []string
)

// The reverse transports a test covers, in table order.
var ctReverse = []string{"tcp", "tcpmux", "ws", "wsmux", "wss", "wssmux", "spoof", "spoofmux"}

// The direct-mode carriers a test covers, in table order. All need root on both
// servers. "spoof" is not here: its only question — does the datacenter allow a
// forged source — is the one the bidirectional IP Spoof rows already answer,
// and a direct spoof tunnel would need the server to know the client's real IP
// before the client connects.
var ctDirectCarriers = []string{"udp", "pck", "sni", "icmp"}

// ctSNIDomain is the decoy name the sni carrier's ClientHello uses during a test.
const ctSNIDomain = "www.cloudflare.com"

// ctSpoofSource is the forged source address the IP-spoofing rows probe with.
const ctSpoofSource = "10.10.10.10"

const (
	ctLinkScheme = "pol://t."
	ctLinkVer    = 1
	ctSecretLen  = 12
	ctEchoLen    = 512
	ctSpeedMagic = "POLSPD1" // + 'D' (kharej sends) or 'U' (kharej receives and counts)
	ctSpoofTag   = "polct-spoof-"
	ctSpoofN     = 20
)

// Result statuses and phases.
const (
	ctTesting  = "testing"
	ctOK       = "ok"
	ctUnstable = "unstable"
	ctDown     = "down"
	ctSkipped  = "skipped"
	ctWaiting  = "waiting" // before the kharej has joined
)

// ctResult is one row of the table: one tunnel (or spoofing direction).
type ctResult struct {
	Kind      string  `json:"k"` // reverse | direct | spoof
	Transport string  `json:"t"`
	Status    string  `json:"s"`
	Phase     string  `json:"p,omitempty"` // queued | speed
	Detail    string  `json:"d,omitempty"`
	Connect   float64 `json:"c,omitempty"` // seconds to the first echo
	OK        int     `json:"o"`
	Tried     int     `json:"n"`
	Total     int     `json:"z"`
	RTTms     int     `json:"r,omitempty"`
	JitterMs  int     `json:"j,omitempty"`
	WorstMs   int     `json:"w,omitempty"`
	Down      float64 `json:"dn,omitempty"` // Mbps, Iran ← kharej
	Up        float64 `json:"up,omitempty"` // Mbps, Iran → kharej
}

// ctBest is the recommendation printed under the verdict.
type ctBest struct {
	Kind, Transport  string
	Down, Up         float64
	RTTms, JitterMs  int
	WorstMs          int
	LossPct          float64
	BDPKB            int
	MuxWindowKB      int
	Heartbeat        int
	KeepaliveSeconds int
}

// ---- the link ----

// ctLink is what the copied link says: where the coordinator is and the secret.
type ctLink struct {
	Host   string
	Port   int
	Secret []byte
}

func (l ctLink) String() string {
	b := []byte{ctLinkVer, byte(l.Port >> 8), byte(l.Port)}
	b = append(b, l.Secret...)
	if ip := net.ParseIP(l.Host).To4(); ip != nil {
		b = append(b, ip...)
	} else {
		b = append(b, l.Host...)
	}
	return ctLinkScheme + base64.RawURLEncoding.EncodeToString(b)
}

// parseCTLink reads a link wherever it sits in what was pasted.
func parseCTLink(s string) (ctLink, error) {
	i := strings.Index(s, ctLinkScheme)
	if i < 0 {
		return ctLink{}, fmt.Errorf("that is not a pol connection-test link — it begins with %s", ctLinkScheme)
	}
	s = s[i+len(ctLinkScheme):]
	if j := strings.IndexFunc(s, func(r rune) bool {
		return !(r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
	}); j >= 0 {
		s = s[:j]
	}
	damaged := errors.New("the test link is damaged or cut short — copy all of it again")
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) <= 3+ctSecretLen || b[0] != ctLinkVer {
		return ctLink{}, damaged
	}
	l := ctLink{Port: int(b[1])<<8 | int(b[2]), Secret: append([]byte(nil), b[3:3+ctSecretLen]...)}
	host := b[3+ctSecretLen:]
	if len(host) == 4 {
		l.Host = net.IP(host).String()
	} else {
		l.Host = string(host)
	}
	if l.Port == 0 || l.Host == "" {
		return ctLink{}, damaged
	}
	return l, nil
}

// ctToken is one tunnel's token, derived from the test's secret so that neither
// the link nor the coordinator's answers carry it.
func ctToken(secret []byte, kind, tr string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("pol-conntest/" + kind + "/" + tr))
	return hex.EncodeToString(m.Sum(nil))
}

func ctMAC(secret []byte, nonce, line string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("pol-conntest-coord|" + nonce + "|" + line))
	return hex.EncodeToString(m.Sum(nil))
}

// ---- what the coordinator hands the kharej ----

type ctCase struct {
	Kind string `json:"k"` // reverse | direct
	Tr   string `json:"t"` // reverse: transport; direct: carrier (udp/pck/sni/icmp)
	Port int    `json:"p"` // reverse: the tunnel port on Iran; direct: its base port
	L3   *ctL3  `json:"l3,omitempty"`
	Tun  string `json:"tn,omitempty"` // direct: the TUN interface name

	entry  int // Iran: where the reverse tunnel's users arrive (127.0.0.1)
	skip   string
	rtts   []time.Duration
	engine *ctEngine
}

type ctL3 struct {
	Iran   string `json:"i"` // Iran's tunnel address
	Kharej string `json:"x"` // the kharej's tunnel address
	Echo   int    `json:"e"` // the kharej's echo port on its tunnel address
}

type ctConfig struct {
	Cases    []*ctCase `json:"c"`
	Echo     int       `json:"e"`            // the kharej's TCP echo the reverse tunnels forward to
	SpoofI   int       `json:"si,omitempty"` // Iran's UDP receiver for forged probes
	SpoofSrc string    `json:"ss,omitempty"`
	Soak     int       `json:"sk"`
	Until    int64     `json:"u"` // unix seconds: the kharej stops by then whatever happens
}

type ctStatus struct {
	Rows    []ctResult `json:"r"`
	Done    bool       `json:"d"`
	Stopped bool       `json:"x,omitempty"`
	Best    *ctBest    `json:"b,omitempty"`
	Joined  bool       `json:"j"`
	// SpoofTag is what Iran forged towards the kharej; the kharej reports how
	// many of those it saw on its next STATUS.
	SpoofTag string `json:"st,omitempty"`
}

// ---- engines: one pol process per tunnel end ----

type ctEngine struct {
	cmd  *exec.Cmd
	log  string
	done chan struct{}
	err  error
}

func startCTEngine(dir, name, cfg string) (*ctEngine, error) {
	exe, err := ctBinary()
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(dir, name+".toml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		return nil, err
	}
	logPath := filepath.Join(dir, name+".log")
	lf, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, "-c", cfgPath)
	cmd.Stdout, cmd.Stderr = lf, lf
	cmd.Env = append(os.Environ(), ctEngineEnv...)
	cmd.SysProcAttr = ctEngineSysProcAttr() // the engine dies with the test, never outlives it
	if err := cmd.Start(); err != nil {
		lf.Close()
		return nil, err
	}
	e := &ctEngine{cmd: cmd, log: logPath, done: make(chan struct{})}
	go func() { e.err = cmd.Wait(); lf.Close(); close(e.done) }()
	return e, nil
}

// exited reports whether the engine has stopped, with the last line it logged.
func (e *ctEngine) exited() (bool, string) {
	if e == nil {
		return false, ""
	}
	select {
	case <-e.done:
		return true, ctLastLine(e.log)
	default:
		return false, ""
	}
}

func (e *ctEngine) stop() {
	if e == nil || e.cmd.Process == nil {
		return
	}
	e.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-e.done:
	case <-time.After(3 * time.Second):
		e.cmd.Process.Kill()
		<-e.done
	}
}

func ctLastLine(path string) string {
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			// drop the log timestamp
			if f := strings.SplitN(l, " ", 3); len(f) == 3 && strings.Count(f[0], "/") == 2 {
				l = f[2]
			}
			if len(l) > 160 {
				l = l[:160] + "…"
			}
			return l
		}
	}
	return "exited"
}

func ctStopAll(engines []*ctEngine) {
	var wg sync.WaitGroup
	for _, e := range engines {
		wg.Add(1)
		go func(e *ctEngine) { defer wg.Done(); e.stop() }(e)
	}
	wg.Wait()
}

func ctServerConfig(tr, token string, port, entry, echo int) string {
	return fmt.Sprintf("[server]\nbind_addr = \"0.0.0.0:%d\"\ntransport = \"%s\"\ntoken = \"%s\"\nlog_level = \"warn\"\n"+
		"ports = [\"127.0.0.1:%d=127.0.0.1:%d\"]\n", port, tr, token, entry, echo)
}

func ctClientConfig(tr, token, remote string) string {
	return fmt.Sprintf("[client]\nremote_addr = \"%s\"\ntransport = \"%s\"\ntoken = \"%s\"\nlog_level = \"warn\"\n"+
		"connection_pool = 4\nretry_interval = 1\n", remote, tr, token)
}

func ctDirectConfig(role, addrKey, addr, token, local, peer, carrier, tun string) string {
	cfg := fmt.Sprintf("[direct]\nrole = \"%s\"\n%s = \"%s\"\ntoken = \"%s\"\ntun_name = \"%s\"\n"+
		"local_ip = \"%s\"\npeer_ip = \"%s\"\nmtu = 1400\nauto_mtu = false\ncarrier = \"%s\"\nlog_level = \"warn\"\n",
		role, addrKey, addr, token, tun, local, peer, carrier)
	if carrier == "sni" {
		cfg += fmt.Sprintf("sni_domain = \"%s\"\n", ctSNIDomain)
	}
	return cfg
}

// ---- ports and addresses ----

// ctPickPort returns a random port free for TCP and UDP and not yet used. It
// stays below the kernel's ephemeral range so an outgoing connection cannot
// take it between the check and the engine binding it.
func ctPickPort(used map[int]bool) int {
	for i := 0; i < 1000; i++ {
		p := 20000 + mrand.IntN(12000)
		if used[p] {
			continue
		}
		t, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			continue
		}
		u, err := net.ListenPacket("udp", fmt.Sprintf(":%d", p))
		t.Close()
		if err != nil {
			continue
		}
		u.Close()
		used[p] = true
		return p
	}
	return 0
}

// ctFreeL3 picks a 10.x.y.0/30 pair not already on this server and not already
// handed out this run (taken records the pairs chosen so far).
func ctFreeL3(taken map[string]bool) (string, string) {
	addrs, _ := net.InterfaceAddrs()
	inUse := func(ip net.IP) bool {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.Contains(ip) {
				return true
			}
		}
		return false
	}
	for i := 0; i < 200; i++ {
		x, y := 200+mrand.IntN(50), mrand.IntN(250)
		key := fmt.Sprintf("%d.%d", x, y)
		if taken[key] {
			continue
		}
		a, b := net.IPv4(10, byte(x), byte(y), 1), net.IPv4(10, byte(x), byte(y), 2)
		if !inUse(a) && !inUse(b) {
			taken[key] = true
			return a.String(), b.String()
		}
	}
	return "10.231.77.1", "10.231.77.2"
}

// ctPublicIP is this server's address on its default route.
func ctPublicIP() string {
	c, err := net.Dial("udp", "1.1.1.1:53")
	if err != nil {
		return ""
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func ctCanDirect() bool { return runtime.GOOS == "linux" && os.Geteuid() == 0 }
func ctCanSpoof() bool  { return runtime.GOOS == "linux" && os.Geteuid() == 0 }
func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// ---- the echo / speed service on the kharej ----

// ctServeEcho echoes everything, unless the connection opens with the speed
// magic: 'D' streams random data until closed, 'U' counts what arrives and
// reports the running total (8 bytes) every 200ms.
func ctServeEcho(c net.Conn) {
	defer c.Close()
	head := make([]byte, len(ctSpeedMagic)+1)
	n, err := io.ReadFull(c, head)
	if err != nil {
		c.Write(head[:n])
		return
	}
	if string(head[:len(ctSpeedMagic)]) == ctSpeedMagic {
		switch head[len(ctSpeedMagic)] {
		case 'D':
			buf := make([]byte, 32<<10)
			rand.Read(buf)
			for {
				c.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := c.Write(buf); err != nil {
					return
				}
			}
		case 'U':
			var total uint64
			var mu sync.Mutex
			stop := make(chan struct{})
			go func() {
				t := time.NewTicker(200 * time.Millisecond)
				defer t.Stop()
				var b [8]byte
				for {
					select {
					case <-stop:
						return
					case <-t.C:
					}
					mu.Lock()
					binary.BigEndian.PutUint64(b[:], total)
					mu.Unlock()
					if _, err := c.Write(b[:]); err != nil {
						return
					}
				}
			}()
			buf := make([]byte, 64<<10)
			for {
				c.SetReadDeadline(time.Now().Add(10 * time.Second))
				n, err := c.Read(buf)
				mu.Lock()
				total += uint64(n)
				mu.Unlock()
				if err != nil {
					close(stop)
					return
				}
			}
		}
	}
	if _, err := c.Write(head); err != nil {
		return
	}
	io.Copy(c, c)
}

func ctListenEcho(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go ctServeEcho(c)
		}
	}()
	return ln, nil
}

// ---- the coordinator (on Iran) ----

type ctIran struct {
	link   ctLink
	cfg    ctConfig
	dir    string
	host   string
	ln     net.Listener
	spoofC *net.UDPConn

	mu          sync.Mutex
	rows        []ctResult
	cases       []*ctCase // parallel to the first len(cases) rows
	joined      chan struct{}
	joinOnce    sync.Once
	kharejIP    string
	kharejRoot  bool
	kharejSpoof int // the kharej's receiver for forged probes; 0 = none
	spoofTag    string
	spoofSeenK  int // forged probes the kharej saw
	spoofSeenI  int // forged probes Iran saw from the forged source
	spoofFromI  string
	done        bool
	stopped     bool
	best        *ctBest
	fetchedDone chan struct{}
	fetchOnce   sync.Once
	left        chan struct{} // the kharej stopped the test (LEAVE)
	leftOnce    sync.Once
	engines     []*ctEngine
}

// kharejLeft reports whether the kharej stopped the test.
func (s *ctIran) kharejLeft() bool {
	select {
	case <-s.left:
		return true
	default:
		return false
	}
}

func (s *ctIran) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

// handle answers one question: challenge, one MAC'd request line, one answer.
func (s *ctIran) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	nb := make([]byte, 16)
	rand.Read(nb)
	nonce := hex.EncodeToString(nb)
	fmt.Fprintf(c, "POLCT1 %s\n", nonce)
	line, err := bufio.NewReader(io.LimitReader(c, 64<<10)).ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	i := strings.LastIndexByte(line, ' ')
	if i < 0 || !hmac.Equal([]byte(line[i+1:]), []byte(ctMAC(s.link.Secret, nonce, line[:i]))) {
		time.Sleep(time.Second)
		return // wrong secret: say nothing
	}
	f := strings.Fields(line[:i])
	if len(f) == 0 {
		return
	}
	args := map[string]string{}
	for _, kv := range f[1:] {
		if k, v, ok := strings.Cut(kv, "="); ok {
			args[k] = v
		}
	}
	switch f[0] {
	case "CONFIG":
		b, _ := json.Marshal(s.cfg)
		c.Write(append(b, '\n'))
	case "JOIN":
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		s.mu.Lock()
		s.kharejIP = host
		s.kharejRoot = args["root"] == "1"
		s.kharejSpoof, _ = strconv.Atoi(args["spoof"])
		if s.kharejSpoof < 1 || s.kharejSpoof > 65535 {
			s.kharejSpoof = 0
		}
		if e := args["err"]; e != "" {
			// the kharej could not start some ends; mark them
			for _, tr := range strings.Split(e, ",") {
				for ci, cs := range s.cases {
					if cs.Kind+"/"+cs.Tr == tr {
						s.rows[ci].Status, s.rows[ci].Detail = ctDown, "the kharej could not start its end"
					}
				}
			}
		}
		s.mu.Unlock()
		s.joinOnce.Do(func() { close(s.joined) })
		fmt.Fprintln(c, "OK")
	case "STATUS":
		s.mu.Lock()
		if v, err := strconv.Atoi(args["seen"]); err == nil && args["tag"] == s.spoofTag && s.spoofTag != "" {
			s.spoofSeenK = v
		}
		st := ctStatus{Rows: append([]ctResult(nil), s.rows...), Done: s.done, Stopped: s.stopped, Best: s.best,
			SpoofTag: s.spoofTag}
		select {
		case <-s.joined:
			st.Joined = true
		default:
		}
		s.mu.Unlock()
		b, _ := json.Marshal(st)
		c.Write(append(b, '\n'))
		if st.Done {
			s.fetchOnce.Do(func() { close(s.fetchedDone) })
		}
	case "LEAVE":
		// the kharej was stopped: stop here too instead of probing dead
		// tunnels until every timeout runs out
		s.leftOnce.Do(func() { close(s.left) })
		fmt.Fprintln(c, "OK")
	}
}

// spoofReceiver counts forged probes from the kharej at Iran's receiver.
func (s *ctIran) spoofReceiver() {
	buf := make([]byte, 256)
	for {
		n, from, err := s.spoofC.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !strings.HasPrefix(string(buf[:n]), ctSpoofTag+"k2i") {
			continue
		}
		s.mu.Lock()
		if from.IP.String() == ctSpoofSource {
			s.spoofSeenI++
		} else {
			s.spoofFromI = from.IP.String()
		}
		s.mu.Unlock()
	}
}

func (s *ctIran) set(i int, f func(r *ctResult)) {
	s.mu.Lock()
	f(&s.rows[i])
	s.mu.Unlock()
}

func (s *ctIran) snapshot() []ctResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ctResult(nil), s.rows...)
}

func (s *ctIran) close() {
	ctStopAll(s.engines)
	if s.ln != nil {
		s.ln.Close()
	}
	if s.spoofC != nil {
		s.spoofC.Close()
	}
	os.RemoveAll(s.dir)
}

// ctIranOptions are what the Iran operator chooses.
type ctIranOptions struct {
	Host    string // this server's address as the kharej dials it
	Direct  bool   // include the direct (L3) tunnel; needs root + Linux on both
	Spoof   bool   // include the IP-spoofing check; needs root + Linux on both
	Reverse []string
}

// startCTIran starts every Iran-side engine and the coordinator.
func startCTIran(o ctIranOptions) (*ctIran, error) {
	if o.Reverse == nil {
		o.Reverse = ctReverse
	}
	dir, err := os.MkdirTemp("", "pol-conntest-")
	if err != nil {
		return nil, err
	}
	secret := make([]byte, ctSecretLen)
	rand.Read(secret)
	used := map[int]bool{}
	s := &ctIran{dir: dir, host: o.Host, joined: make(chan struct{}), fetchedDone: make(chan struct{}), left: make(chan struct{})}
	coordPort := ctPickPort(used)
	s.link = ctLink{Host: o.Host, Port: coordPort, Secret: secret}
	s.cfg = ctConfig{Echo: ctPickPort(used), Soak: ctSoak, Until: time.Now().Add(ctJoinWait + ctSlack + time.Duration(ctSoak)*ctEchoEvery + ctConnectWait).Unix()}

	if s.ln, err = net.Listen("tcp", fmt.Sprintf(":%d", coordPort)); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("coordinator: %w", err)
	}

	for _, tr := range o.Reverse {
		c := &ctCase{Kind: "reverse", Tr: tr, Port: ctPickPort(used), entry: ctPickPort(used)}
		s.cfg.Cases = append(s.cfg.Cases, c)
	}
	l3Taken := map[string]bool{}
	for _, car := range ctDirectCarriers {
		direct := &ctCase{Kind: "direct", Tr: car, Tun: "polct-" + car}
		switch {
		case !o.Direct:
			direct.skip = "not selected"
		case !ctCanDirect():
			direct.skip = "needs root on Linux (this server)"
		default:
			direct.Port = ctPickPort(used)
			a, b := ctFreeL3(l3Taken)
			direct.L3 = &ctL3{Iran: a, Kharej: b, Echo: ctPickPort(used)}
		}
		s.cfg.Cases = append(s.cfg.Cases, direct)
	}

	for _, c := range s.cfg.Cases {
		s.cases = append(s.cases, c)
		r := ctResult{Kind: c.Kind, Transport: c.Tr, Status: ctWaiting, Total: ctSoak}
		if c.skip != "" {
			r.Status, r.Detail = ctSkipped, c.skip
		}
		s.rows = append(s.rows, r)
	}
	// the spoofing rows
	spoofSkip := ""
	switch {
	case !o.Spoof:
		spoofSkip = "not selected"
	case !ctCanSpoof():
		spoofSkip = "needs root on Linux (this server)"
	default:
		s.cfg.SpoofI = ctPickPort(used)
		s.cfg.SpoofSrc = ctSpoofSource
		if s.spoofC, err = net.ListenUDP("udp", &net.UDPAddr{Port: s.cfg.SpoofI}); err != nil {
			spoofSkip = "receiver: " + err.Error()
			s.cfg.SpoofI, s.cfg.SpoofSrc = 0, ""
		} else {
			go s.spoofReceiver()
		}
	}
	for _, dirn := range []string{"iran→kharej", "kharej→iran"} {
		r := ctResult{Kind: "spoof", Transport: dirn, Status: ctWaiting, Total: ctSpoofN}
		if spoofSkip != "" {
			r.Status, r.Detail = ctSkipped, spoofSkip
		}
		s.rows = append(s.rows, r)
	}

	// start every Iran-side engine
	for i, c := range s.cases {
		if c.skip != "" {
			continue
		}
		tok := ctToken(secret, c.Kind, c.Tr)
		var cfg string
		if c.Kind == "direct" {
			cfg = ctDirectConfig("server", "bind_addr", fmt.Sprintf("0.0.0.0:%d", c.Port), tok, c.L3.Iran, c.L3.Kharej, c.Tr, c.Tun)
		} else {
			cfg = ctServerConfig(c.Tr, tok, c.Port, c.entry, s.cfg.Echo)
		}
		e, err := startCTEngine(dir, c.Kind+"-"+c.Tr, cfg)
		if err != nil {
			s.rows[i].Status, s.rows[i].Detail = ctDown, "engine: "+err.Error()
			continue
		}
		c.engine = e
		s.engines = append(s.engines, e)
	}
	time.Sleep(ctStartGrace)
	for i, c := range s.cases {
		if dead, why := c.engine.exited(); dead {
			s.rows[i].Status, s.rows[i].Detail = ctDown, "the Iran end did not start: "+why
		}
	}
	go s.serve()
	return s, nil
}

// run waits for the kharej, then tests everything. progress is called with the
// table whenever it may have changed.
func (s *ctIran) run(ctx context.Context, progress func([]ctResult)) []ctResult {
	// a LEAVE from the kharej stops the test like a local Ctrl+C would
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-s.left:
			cancel()
		case <-ctx.Done():
		}
	}()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if progress != nil {
					progress(s.snapshot())
				}
				s.mu.Lock()
				d := s.done
				s.mu.Unlock()
				if d {
					return
				}
			}
		}
	}()

	select {
	case <-s.joined:
	case <-ctx.Done():
		s.finish(true)
		return s.snapshot()
	case <-time.After(ctJoinWait):
		s.mu.Lock()
		for i := range s.rows {
			if s.rows[i].Status == ctWaiting {
				s.rows[i].Status, s.rows[i].Detail = ctDown, "the kharej never joined"
			}
		}
		s.mu.Unlock()
		s.finish(false)
		return s.snapshot()
	}

	s.mu.Lock()
	kharejRoot, kharejIP, kharejSpoof := s.kharejRoot, s.kharejIP, s.kharejSpoof
	for i, c := range s.cases {
		if c.Kind == "direct" && s.rows[i].Status == ctWaiting && !kharejRoot {
			s.rows[i].Status, s.rows[i].Detail = ctSkipped, "needs root on Linux (the kharej)"
		}
		if s.rows[i].Status == ctWaiting {
			s.rows[i].Status = ctTesting
		}
	}
	s.mu.Unlock()

	var wg sync.WaitGroup
	for i, c := range s.cases {
		if s.snapshot()[i].Status != ctTesting {
			continue
		}
		wg.Add(1)
		go func(i int, c *ctCase) {
			defer wg.Done()
			s.probe(ctx, i, c)
		}(i, c)
	}
	// IP spoofing, both ways
	si := len(s.cases)
	if s.snapshot()[si].Status == ctWaiting {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.spoofProbe(ctx, si, kharejRoot, kharejIP, kharejSpoof)
		}()
	}
	wg.Wait()

	// speed, one tunnel at a time so they do not share the path
	for i, c := range s.cases {
		if ctx.Err() != nil {
			break
		}
		r := s.snapshot()[i]
		if r.Status != ctOK || r.Phase != "queued" {
			continue
		}
		s.set(i, func(r *ctResult) { r.Phase = "speed" })
		down, up, err := ctSpeed(ctx, func() (net.Conn, error) { return s.dial(ctx, c) })
		s.set(i, func(r *ctResult) {
			r.Phase = ""
			if err != nil {
				r.Detail = "speed test failed: " + err.Error()
				return
			}
			r.Down, r.Up = down, up
		})
	}
	s.finish(ctx.Err() != nil)
	return s.snapshot()
}

func (s *ctIran) finish(stopped bool) {
	rows := s.snapshot()
	best := ctComputeBest(rows, s.cases)
	s.mu.Lock()
	for i := range s.rows {
		if s.rows[i].Status == ctWaiting || s.rows[i].Status == ctTesting {
			s.rows[i].Status, s.rows[i].Detail = ctDown, "stopped"
		}
		s.rows[i].Phase = ""
	}
	s.done, s.stopped, s.best = true, stopped, best
	s.mu.Unlock()
}

// waitFetched gives the kharej a moment to read the verdict before Iran closes.
//
// It returns at once when there is nobody to wait for: the kharej never
// joined, or it already left (it stopped the test itself). When this side
// was stopped (Ctrl+C) it only lingers briefly — the kharej polls every
// ctPollEvery, so a few seconds are enough for it to see the stop — and on a
// normal finish skip (Ctrl+C) cuts the wait short. Before, it always waited
// the full d, so a stopped test looked frozen for 20s.
func (s *ctIran) waitFetched(d time.Duration, stopped bool, skip <-chan struct{}) {
	select {
	case <-s.joined:
	default:
		return // never joined
	}
	select {
	case <-s.left:
		return
	case <-s.fetchedDone:
		return
	default:
	}
	if stopped {
		d, skip = 3*ctPollEvery, nil
	} else {
		// usually it reads within a poll; say something only if it is slow
		select {
		case <-s.fetchedDone:
			return
		case <-s.left:
			return
		case <-skip:
			return
		case <-time.After(2 * ctPollEvery):
		}
		fmt.Println("  Waiting for the kharej to read the result… (Ctrl+C to skip)")
	}
	select {
	case <-s.fetchedDone:
	case <-s.left:
	case <-skip:
	case <-time.After(d):
	}
}

func (s *ctIran) dial(ctx context.Context, c *ctCase) (net.Conn, error) {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(c.entry))
	if c.Kind == "direct" {
		addr = net.JoinHostPort(c.L3.Kharej, strconv.Itoa(c.L3.Echo))
	}
	return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", addr)
}

// ctEcho sends a random payload and requires it back unchanged.
func ctEcho(c net.Conn) error {
	msg := make([]byte, ctEchoLen)
	rand.Read(msg)
	c.SetDeadline(time.Now().Add(4 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write(msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if string(got) != string(msg) {
		return errors.New("the echo came back different")
	}
	return nil
}

func ctSleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// probe pushes traffic through one tunnel and judges it.
func (s *ctIran) probe(ctx context.Context, i int, c *ctCase) {
	wait := ctConnectWait
	if c.Kind == "direct" {
		wait += 30 * time.Second // the kharej builds its interface too
	}
	// Up: the first echo that comes back.
	start := time.Now()
	var conn net.Conn
	for conn == nil {
		if ctx.Err() != nil {
			return
		}
		if dead, why := c.engine.exited(); dead {
			s.set(i, func(r *ctResult) { r.Status, r.Detail = ctDown, "the Iran end stopped: "+why })
			return
		}
		if time.Since(start) > wait {
			s.set(i, func(r *ctResult) {
				r.Status, r.Detail = ctDown, fmt.Sprintf("never carried traffic in %s", wait)
				switch {
				case c.Kind == "direct" && c.Tr == "icmp":
					r.Detail += " — ICMP looks blocked or throttled on this path"
				case c.Kind == "direct" && (c.Tr == "pck" || c.Tr == "sni"):
					r.Detail += " — these TCP-shaped packets look blocked on this path"
				case c.Kind == "direct" || strings.HasPrefix(c.Tr, "spoof"):
					r.Detail += " — UDP looks blocked or throttled on this path"
				}
			})
			return
		}
		if cn, err := s.dial(ctx, c); err == nil {
			if ctEcho(cn) == nil {
				conn = cn
				break
			}
			cn.Close()
		}
		ctSleep(ctx, time.Second)
	}
	connect := time.Since(start).Seconds()
	s.set(i, func(r *ctResult) { r.Connect = connect })

	// Staying up: an echo a second over the same connection, and a new one
	// only when that one is lost — exactly what a user's connection would see.
	var firstLoss time.Duration
	soakStart := time.Now()
	for n := 0; n < ctSoak && ctx.Err() == nil; n++ {
		ctSleep(ctx, time.Until(soakStart.Add(time.Duration(n)*ctEchoEvery)))
		if ctx.Err() != nil {
			break
		}
		s.set(i, func(r *ctResult) { r.Tried++ })
		if conn == nil {
			cn, err := s.dial(ctx, c)
			if err != nil {
				if firstLoss == 0 {
					firstLoss = time.Since(soakStart) + time.Millisecond
				}
				continue
			}
			conn = cn
		}
		t0 := time.Now()
		if err := ctEcho(conn); err != nil {
			conn.Close()
			conn = nil
			if firstLoss == 0 {
				firstLoss = time.Since(soakStart) + time.Millisecond
			}
			continue
		}
		took := time.Since(t0)
		c.rtts = append(c.rtts, took)
		q := ctQuality(c.rtts)
		s.set(i, func(r *ctResult) {
			r.OK++
			r.RTTms, r.JitterMs, r.WorstMs = ms(q.avg), ms(q.jitter), ms(q.max)
		})
	}
	if conn != nil {
		conn.Close()
	}
	s.set(i, func(r *ctResult) {
		switch {
		case ctx.Err() != nil:
			r.Status, r.Detail = ctUnstable, "stopped before the test completed"
			if r.OK == 0 {
				r.Status = ctDown
			}
		case r.OK == ctSoak && r.Tried == ctSoak:
			r.Status, r.Phase = ctOK, "queued"
		case r.OK == 0:
			r.Status = ctDown
			r.Detail = fmt.Sprintf("came up, then carried nothing (lost after %.0fs)", firstLoss.Seconds())
		default:
			r.Status = ctUnstable
			r.Detail = fmt.Sprintf("%d of %d echoes came back; first loss after %.0fs", r.OK, r.Tried, firstLoss.Seconds())
		}
	})
}

// spoofProbe runs the IP-spoofing check both ways from the one forged source.
func (s *ctIran) spoofProbe(ctx context.Context, si int, kharejRoot bool, kharejIP string, kharejPort int) {
	i2k, k2i := si, si+1
	if !kharejRoot {
		for _, i := range []int{i2k, k2i} {
			s.set(i, func(r *ctResult) { r.Status, r.Detail = ctSkipped, "needs root on Linux (the kharej)" })
		}
		return
	}
	s.set(i2k, func(r *ctResult) { r.Status = ctTesting })
	s.set(k2i, func(r *ctResult) { r.Status = ctTesting })

	// Iran → kharej: forge, then wait for the kharej to say how many arrived.
	if kharejPort == 0 {
		s.set(i2k, func(r *ctResult) { r.Status, r.Detail = ctSkipped, "the kharej has no receiver" })
	} else if sender, err := buildSender(nil, ctSpoofSource, ""); err != nil {
		s.set(i2k, func(r *ctResult) { r.Status, r.Detail = ctSkipped, err.Error() })
	} else {
		tb := make([]byte, 6)
		rand.Read(tb)
		tag := ctSpoofTag + "i2k-" + hex.EncodeToString(tb)
		s.mu.Lock()
		s.spoofTag = tag
		s.mu.Unlock()
		dst := &net.UDPAddr{IP: net.ParseIP(kharejIP), Port: kharejPort}
		for n := 0; n < ctSpoofN && ctx.Err() == nil; n++ {
			sender.sendTo([]byte(tag), dst)
			s.set(i2k, func(r *ctResult) { r.Tried++ })
			ctSleep(ctx, 50*time.Millisecond)
		}
		sender.Close()
		deadline := time.Now().Add(10 * ctPollEvery)
		for time.Now().Before(deadline) && ctx.Err() == nil {
			ctSleep(ctx, ctPollEvery)
		}
		s.mu.Lock()
		seen := s.spoofSeenK
		s.mu.Unlock()
		s.set(i2k, func(r *ctResult) { ctSpoofVerdict(r, seen, "") })
	}

	// kharej → Iran: the kharej forges as soon as it joins; count what came.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		s.mu.Lock()
		seen := s.spoofSeenI
		s.mu.Unlock()
		if seen >= ctSpoofN {
			break
		}
		ctSleep(ctx, 500*time.Millisecond)
	}
	s.mu.Lock()
	seen, from := s.spoofSeenI, s.spoofFromI
	s.mu.Unlock()
	s.set(k2i, func(r *ctResult) { r.Tried = ctSpoofN; ctSpoofVerdict(r, seen, from) })
}

func ctSpoofVerdict(r *ctResult, seen int, rewrittenFrom string) {
	if seen > ctSpoofN {
		seen = ctSpoofN
	}
	r.OK = seen
	switch {
	case seen == 0 && rewrittenFrom != "":
		r.Status, r.Detail = ctDown, "arrived, but from "+rewrittenFrom+" — a NAT rewrote the forged source"
	case seen == 0:
		r.Status, r.Detail = ctDown, "the forged source was dropped (provider BCP38 filtering, or rp_filter on the receiver)"
	case seen < ctSpoofN:
		r.Status, r.Detail = ctUnstable, fmt.Sprintf("%d of %d forged probes arrived", seen, ctSpoofN)
	default:
		r.Status = ctOK
	}
}

// ---- speed: 4 streams each way, only receiver-verified bytes count ----

const ctSpeedStreams = 4

func ctSpeed(ctx context.Context, dial func() (net.Conn, error)) (down, up float64, err error) {
	if down, err = ctSpeedDir(ctx, dial, 'D'); err != nil {
		return 0, 0, fmt.Errorf("download: %w", err)
	}
	if up, err = ctSpeedDir(ctx, dial, 'U'); err != nil {
		return down, 0, fmt.Errorf("upload: %w", err)
	}
	return down, up, nil
}

func ctSpeedDir(ctx context.Context, dial func() (net.Conn, error), dir byte) (float64, error) {
	conns := make([]net.Conn, 0, ctSpeedStreams)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < ctSpeedStreams; i++ {
		c, err := dial()
		if err != nil {
			return 0, err
		}
		conns = append(conns, c)
		if _, err := c.Write([]byte(ctSpeedMagic + string(dir))); err != nil {
			return 0, err
		}
	}
	counters := make([]uint64, ctSpeedStreams)
	var mu sync.Mutex
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Add(1)
		go func(i int, c net.Conn) {
			defer wg.Done()
			c.SetDeadline(time.Now().Add(ctSpeedWarm + ctSpeedDur + 10*time.Second))
			if dir == 'D' {
				buf := make([]byte, 64<<10)
				for {
					n, err := c.Read(buf)
					mu.Lock()
					counters[i] += uint64(n)
					mu.Unlock()
					if err != nil {
						return
					}
				}
			}
			// upload: write until stopped; the kharej's running totals are the measure
			go func() {
				var b [8]byte
				for {
					if _, err := io.ReadFull(c, b[:]); err != nil {
						return
					}
					mu.Lock()
					counters[i] = binary.BigEndian.Uint64(b[:])
					mu.Unlock()
				}
			}()
			buf := make([]byte, 32<<10)
			rand.Read(buf)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := c.Write(buf); err != nil {
					return
				}
			}
		}(i, c)
	}
	total := func() uint64 {
		mu.Lock()
		defer mu.Unlock()
		var t uint64
		for _, v := range counters {
			t += v
		}
		return t
	}
	ctSleep(ctx, ctSpeedWarm)
	b0, t0 := total(), time.Now()
	ctSleep(ctx, ctSpeedDur)
	b1, t1 := total(), time.Now()
	close(stop)
	for _, c := range conns {
		c.Close()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if b1 <= b0 {
		return 0, errors.New("no data crossed")
	}
	return float64(b1-b0) * 8 / t1.Sub(t0).Seconds() / 1e6, nil
}

// ---- quality and the recommendation ----

type ctQ struct{ avg, jitter, max time.Duration }

func ctQuality(rtts []time.Duration) ctQ {
	var q ctQ
	if len(rtts) == 0 {
		return q
	}
	var sum time.Duration
	for _, d := range rtts {
		sum += d
		if d > q.max {
			q.max = d
		}
	}
	q.avg = sum / time.Duration(len(rtts))
	var dev time.Duration
	for _, d := range rtts {
		if d > q.avg {
			dev += d - q.avg
		} else {
			dev += q.avg - d
		}
	}
	q.jitter = dev / time.Duration(len(rtts))
	return q
}

func ms(d time.Duration) int { return int(d.Milliseconds()) }

// ctComputeBest picks the tunnel to recommend — the fastest that carried
// everything, else the one that carried most — and derives settings from it.
func ctComputeBest(rows []ctResult, cases []*ctCase) *ctBest {
	best := -1
	for i := range cases {
		r := rows[i]
		if r.Status == ctSkipped || r.Tried == 0 || r.OK == 0 {
			continue
		}
		if best < 0 {
			best = i
			continue
		}
		cur := rows[best]
		switch {
		case r.Status == ctOK && cur.Status != ctOK:
			best = i
		case r.Status == ctOK && cur.Status == ctOK && r.Down+r.Up > cur.Down+cur.Up:
			best = i
		case r.Status != ctOK && cur.Status != ctOK && r.OK > cur.OK:
			best = i
		}
	}
	b := &ctBest{Heartbeat: 20, KeepaliveSeconds: 75}
	if best < 0 {
		return b
	}
	r := rows[best]
	q := ctQuality(cases[best].rtts)
	if r.Status == ctOK {
		b.Kind, b.Transport, b.Down, b.Up = r.Kind, r.Transport, r.Down, r.Up
	}
	b.RTTms, b.JitterMs, b.WorstMs = ms(q.avg), ms(q.jitter), ms(q.max)
	if r.Tried > 0 {
		b.LossPct = math.Round(float64(r.Tried-r.OK)/float64(r.Tried)*1000) / 10
	}
	// What one connection needs in flight to fill the pipe: speed × round trip.
	if speed := math.Max(b.Down, b.Up); speed > 0 && b.RTTms > 0 {
		b.BDPKB = int(speed * 1e6 / 8 * float64(b.RTTms) / 1000 / 1024)
		// a mux stream window of twice that, never below the default
		w := 2 * b.BDPKB
		if w < 512 {
			w = 512
		}
		if w > 65536 {
			w = 65536
		}
		b.MuxWindowKB = w
	}
	// Liveness: notice a dead peer quickly on a lossy route, and never declare
	// a slow but live one dead.
	switch {
	case b.LossPct > 0:
		b.Heartbeat = 10
	case b.WorstMs > 1500:
		b.Heartbeat = 30
	}
	if b.WorstMs > 1000 || b.LossPct > 0 {
		b.KeepaliveSeconds = 30
	}
	return b
}

// ---- Iran: the whole flow ----

// ctSignalContext is cancelled by the first Ctrl+C / SIGTERM / SIGHUP (SIGHUP:
// a dropped SSH session or a closed terminal must still clean up). A second
// one quits at once: the engines still go, since they die with this process
// (Pdeathsig), and the next test reaps anything else left behind.
func ctSignalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
		case <-done:
			return
		}
		fmt.Fprintln(os.Stderr, "\nStopping the test… (Ctrl+C again to quit at once)")
		cancel()
		select {
		case <-sig:
			fmt.Fprintln(os.Stderr, "Quit.")
			os.Exit(130)
		case <-done:
		}
	}()
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			signal.Stop(sig)
			close(done)
			cancel()
		})
	}
}

// runConnTestIran is `pol -conntest`: start, print the link, test, report.
func runConnTestIran(host string, direct, spoof bool) error {
	if host == "" {
		host = ctPublicIP()
	}
	if host == "" {
		return errors.New("could not tell this server's address; pass it with -conntest-host")
	}
	// catch Ctrl+C / SIGHUP before any engine starts, so stopping during
	// startup still runs the cleanup below
	ctx, stop := ctSignalContext()
	defer stop()
	ctStage("1", "Preparing test tunnels", "Starting a real pol engine for every transport on free ports.")
	ctQuietHotplug()
	if n := ctReapStale(); n > 0 {
		fmt.Printf("   Stopped %d engine(s) left behind by an earlier test.\n", n)
	}
	s, err := startCTIran(ctIranOptions{Host: host, Direct: direct, Spoof: spoof})
	if err != nil {
		return err
	}
	defer s.close()

	fmt.Println()
	ctStage("2", "Connect the kharej", "On the kharej server run Connection Test → Kharej and paste this link:")
	fmt.Println()
	fmt.Println("    " + ctBold(s.link.String()))
	fmt.Println()
	fmt.Printf("    or:  pol -conntest-join %s\n\n", s.link.String())
	if ctIsPrivate(host) {
		fmt.Printf("  ! %s looks like a private address; if the kharej cannot reach it, rerun with -conntest-host PUBLIC_IP\n\n", host)
	}
	fmt.Println("  Leave this open while you connect the other server. Ctrl+C stops the test.")
	fmt.Println()
	board := newCTBoard(os.Stdout, "Iran ⇄ kharej")
	rows := s.run(ctx, board.set)
	s.mu.Lock()
	best := s.best
	s.mu.Unlock()
	board.finish(rows, best)
	stopped := ctx.Err() != nil
	switch {
	case s.kharejLeft():
		fmt.Println("The kharej stopped this test.")
	case stopped:
		fmt.Println("Stopped.")
	}
	s.waitFetched(20*time.Second, stopped || s.kharejLeft(), ctx.Done())
	return nil
}

func ctIsPrivate(h string) bool {
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback())
}

// ---- kharej ----

// ctAsk sends one authenticated question to the coordinator.
func ctAsk(ctx context.Context, l ctLink, line string) (string, error) {
	d := net.Dialer{Timeout: 8 * time.Second}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(l.Host, strconv.Itoa(l.Port)))
	if err != nil {
		return "", err
	}
	defer c.Close()
	deadline := time.Now().Add(15 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	c.SetDeadline(deadline)
	// a cancelled ctx (Ctrl+C) must not leave us blocked in a read for 15s
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Now()) })
	defer stop()
	rd := bufio.NewReader(io.LimitReader(c, 4<<20))
	hello, err := rd.ReadString('\n')
	if err != nil {
		return "", err
	}
	f := strings.Fields(hello)
	if len(f) != 2 || f[0] != "POLCT1" {
		return "", errors.New("not a pol connection-test coordinator (version mismatch?)")
	}
	fmt.Fprintf(c, "%s %s\n", line, ctMAC(l.Secret, f[1], line))
	ans, err := rd.ReadString('\n')
	if err != nil {
		if err == io.EOF && ans == "" {
			return "", errors.New("the Iran server refused the link (wrong or expired test)")
		}
		return "", err
	}
	return strings.TrimSpace(ans), nil
}

// ctKharej holds what the kharej started.
type ctKharej struct {
	dir     string
	engines []*ctEngine
	lns     []net.Listener
	spoofC  *net.UDPConn
	mu      sync.Mutex
	seen    map[string]int
}

func (k *ctKharej) close() {
	ctStopAll(k.engines)
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, l := range k.lns {
		l.Close()
	}
	if k.spoofC != nil {
		k.spoofC.Close()
	}
	os.RemoveAll(k.dir)
}

func (k *ctKharej) spoofReceiver() {
	buf := make([]byte, 256)
	for {
		n, from, err := k.spoofC.ReadFromUDP(buf)
		if err != nil {
			return
		}
		tag := string(buf[:n])
		if !strings.HasPrefix(tag, ctSpoofTag+"i2k") || from.IP.String() != ctSpoofSource {
			continue
		}
		k.mu.Lock()
		k.seen[tag]++
		k.mu.Unlock()
	}
}

// runConnTestKharej is `pol -conntest-join LINK`.
func runConnTestKharej(raw string) error {
	l, err := parseCTLink(raw)
	if err != nil {
		return err
	}
	ctx, stop := ctSignalContext()
	defer stop()
	ctStage("1", "Connecting to Iran", "Fetching the test settings and starting this side's tunnels.")
	ctQuietHotplug()
	if n := ctReapStale(); n > 0 {
		fmt.Printf("   Stopped %d engine(s) left behind by an earlier test.\n", n)
	}
	_, _, err = ctKharejRun(ctx, l, newCTBoard(os.Stdout, l.Host+" ⇄ this server"))
	if ctx.Err() != nil {
		// stopped here (Ctrl+C): tell Iran, so it stops now instead of probing
		// dead tunnels for minutes; best effort, never longer than a moment
		lctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ctAsk(lctx, l, "LEAVE")
		cancel()
		fmt.Println("Stopped.")
		return nil // a requested stop is not a failure (the menu would say so)
	}
	return err
}

func ctKharejRun(ctx context.Context, l ctLink, board *ctBoard) ([]ctResult, *ctBest, error) {
	ans, err := ctAsk(ctx, l, "CONFIG")
	if err != nil {
		return nil, nil, fmt.Errorf("cannot reach the Iran server's test at %s:%d: %w", l.Host, l.Port, err)
	}
	var cfg ctConfig
	if err := json.Unmarshal([]byte(ans), &cfg); err != nil {
		return nil, nil, fmt.Errorf("bad answer from the Iran server: %w", err)
	}
	if cfg.Soak > 0 {
		ctSoak = cfg.Soak
	}
	dir, err := os.MkdirTemp("", "pol-conntest-")
	if err != nil {
		return nil, nil, err
	}
	k := &ctKharej{dir: dir, seen: map[string]int{}}
	defer k.close()

	var failed []string
	if ln, err := ctListenEcho(fmt.Sprintf("127.0.0.1:%d", cfg.Echo)); err == nil {
		k.lns = append(k.lns, ln)
	} else {
		return nil, nil, fmt.Errorf("echo service on port %d: %w", cfg.Echo, err)
	}
	root := ctCanDirect()
	for _, c := range cfg.Cases {
		tok := ctToken(l.Secret, c.Kind, c.Tr)
		var conf string
		switch {
		case c.Kind == "reverse":
			conf = ctClientConfig(c.Tr, tok, net.JoinHostPort(l.Host, strconv.Itoa(c.Port)))
		case c.Kind == "direct" && c.L3 != nil && root:
			// echo on the tunnel address only, once the engine has configured it
			go func(addr string) {
				for i := 0; i < 240 && ctx.Err() == nil; i++ {
					if ln, err := ctListenEcho(addr); err == nil {
						k.mu.Lock()
						k.lns = append(k.lns, ln)
						k.mu.Unlock()
						return
					}
					ctSleep(ctx, 500*time.Millisecond)
				}
			}(net.JoinHostPort(c.L3.Kharej, strconv.Itoa(c.L3.Echo)))
			conf = ctDirectConfig("client", "remote_addr", net.JoinHostPort(l.Host, strconv.Itoa(c.Port)), tok,
				c.L3.Kharej, c.L3.Iran, c.Tr, c.Tun)
		default:
			continue
		}
		e, err := startCTEngine(dir, c.Kind+"-"+c.Tr, conf)
		if err != nil {
			failed = append(failed, c.Kind+"/"+c.Tr)
			continue
		}
		k.engines = append(k.engines, e)
	}
	spoofPort := 0
	if cfg.SpoofSrc != "" && ctCanSpoof() {
		if k.spoofC, err = net.ListenUDP("udp", &net.UDPAddr{}); err == nil {
			spoofPort = k.spoofC.LocalAddr().(*net.UDPAddr).Port
			go k.spoofReceiver()
		}
	}
	join := fmt.Sprintf("JOIN root=%s spoof=%d", boolStr(root), spoofPort)
	if len(failed) > 0 {
		join += " err=" + strings.Join(failed, ",")
	}
	if _, err := ctAsk(ctx, l, join); err != nil {
		return nil, nil, fmt.Errorf("joining the test: %w", err)
	}
	// forge towards Iran (kharej → Iran spoofing row)
	if spoofPort != 0 && cfg.SpoofI != 0 {
		go func() {
			sender, err := buildSender(nil, cfg.SpoofSrc, "")
			if err != nil {
				return
			}
			defer sender.Close()
			dst := &net.UDPAddr{IP: net.ParseIP(l.Host), Port: cfg.SpoofI}
			if dst.IP == nil {
				if a, err := net.ResolveUDPAddr("udp", net.JoinHostPort(l.Host, strconv.Itoa(cfg.SpoofI))); err == nil {
					dst = a
				}
			}
			tb := make([]byte, 6)
			rand.Read(tb)
			tag := []byte(ctSpoofTag + "k2i-" + hex.EncodeToString(tb))
			for i := 0; i < ctSpoofN; i++ {
				sender.sendTo(tag, dst)
				time.Sleep(50 * time.Millisecond)
			}
		}()
	}
	fmt.Println()
	until := time.Unix(cfg.Until, 0)
	var last ctStatus
	lastOK := time.Now()
	var refusedSince time.Time
	tag := ""
	for {
		if ctx.Err() != nil {
			board.abandon()
			return last.Rows, last.Best, errors.New("stopped")
		}
		if time.Now().After(until) {
			board.abandon()
			return last.Rows, last.Best, errors.New("the test ran past its schedule; stopped")
		}
		q := "STATUS"
		if tag != "" {
			k.mu.Lock()
			q += fmt.Sprintf(" tag=%s seen=%d", tag, k.seen[tag])
			k.mu.Unlock()
		}
		ans, err := ctAsk(ctx, l, q)
		if err != nil {
			// refused = the Iran test process is gone (e.g. quit with a second
			// Ctrl+C before it could say so): stop soon, not after the 90s
			// meant for a flaky path
			if errors.Is(err, syscall.ECONNREFUSED) {
				if refusedSince.IsZero() {
					refusedSince = time.Now()
				}
				if time.Since(refusedSince) > 5*time.Second {
					board.abandon()
					return last.Rows, last.Best, errors.New("the Iran server's test has ended (its coordinator is gone)")
				}
			} else {
				refusedSince = time.Time{}
			}
			if time.Since(lastOK) > 90*time.Second {
				board.abandon()
				return last.Rows, last.Best, fmt.Errorf("lost the Iran server's coordinator: %w", err)
			}
			ctSleep(ctx, ctPollEvery)
			continue
		}
		lastOK, refusedSince = time.Now(), time.Time{}
		var st ctStatus
		if json.Unmarshal([]byte(ans), &st) == nil {
			last = st
			tag = st.SpoofTag
			board.set(st.Rows)
			if st.Done {
				board.finish(st.Rows, st.Best)
				if st.Stopped {
					fmt.Println("The Iran server stopped this test.")
				}
				return st.Rows, st.Best, nil
			}
		}
		ctSleep(ctx, ctPollEvery)
	}
}

// ---- menu glue ----

func ctStage(n, title, detail string) {
	fmt.Printf("%s  %s\n   %s\n", ctBold("["+n+"]"), ctBold(title), detail)
}
