package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config mirrors the Backhaul-style TOML layout: one [server] or one [client] section.
type Config struct {
	Server *ServerConfig
	Client *ClientConfig
	Direct *DirectConfig
}

type Common struct {
	Transport    string // tcp | tcpmux | ws | wsmux | wss | wssmux
	Token        string
	Keepalive    time.Duration
	Nodelay      bool
	Heartbeat    time.Duration
	MuxFrameSize int
	MuxWindow    int
	WebPort      int
	LogLevel     string
	Path         string // websocket path
	TLSCert      string
	TLSKey       string
	TLSSNI       string
	TLSInsecure  bool
	ChannelSize  int
	DialTimeout  time.Duration
	UDPIdle      time.Duration
	Encryption   bool // wrap the transport in AES-256-GCM after an X25519 handshake
}

type ServerConfig struct {
	Common
	BindAddr    string
	AcceptUDP   bool
	Ports       []string
	PeerAddr    string // spoof: the client's real ip:port to send replies to
	SpoofSource string // spoof: forge this source IP on outgoing packets (Linux, root)
}

type ClientConfig struct {
	Common
	RemoteAddr     string
	RemoteAddrs    []string // extra backup server addresses; client fails over between them
	EdgeIP         string
	ConnectionPool int
	RetryInterval  time.Duration
	SpoofSource    string // spoof: forge this source IP on outgoing packets (Linux, root)
	ProxyProtocol  bool   // send PROXY protocol v2 to the backend (real visitor IP)
}

// allRemotes is the ordered list of server addresses to try (primary first).
func (c *ClientConfig) allRemotes() []string {
	var out []string
	if c.RemoteAddr != "" {
		out = append(out, c.RemoteAddr)
	}
	out = append(out, c.RemoteAddrs...)
	return out
}

func defaultCommon() Common {
	return Common{
		Transport:    "tcp",
		Keepalive:    75 * time.Second,
		Nodelay:      true,
		Heartbeat:    20 * time.Second,
		MuxFrameSize: 32 * 1024,
		MuxWindow:    512 * 1024,
		LogLevel:     "info",
		Path:         "/ws",
		TLSInsecure:  true,
		ChannelSize:  2048,
		DialTimeout:  10 * time.Second,
		UDPIdle:      60 * time.Second,
	}
}

// ---- minimal TOML subset parser: [section], key = "str" | int | bool | ["a","b"] ----

type tomlTable map[string]map[string]any

func parseTOML(path string) (tomlTable, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := tomlTable{}
	section := ""
	out[section] = map[string]any{}
	sc := bufio.NewScanner(f)
	lineNo := 0
	pending := "" // accumulates multi-line arrays
	pendingKey := ""
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(stripComment(sc.Text()))
		if pendingKey != "" {
			pending += " " + line
			if !bracketsBalanced(pending) {
				continue
			}
			v, err := parseValue(pending)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", lineNo, err)
			}
			out[section][pendingKey] = v
			pendingKey, pending = "", ""
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if out[section] == nil {
				out[section] = map[string]any{}
			}
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", lineNo)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if strings.HasPrefix(val, "[") && !bracketsBalanced(val) {
			pendingKey, pending = key, val
			continue
		}
		v, err := parseValue(val)
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", lineNo, err)
		}
		out[section][key] = v
	}
	if pendingKey != "" {
		return nil, fmt.Errorf("unterminated array for key %q", pendingKey)
	}
	return out, sc.Err()
}

func stripComment(s string) string {
	inStr := false
	for i, c := range s {
		switch c {
		case '"':
			inStr = !inStr
		case '#':
			if !inStr {
				return s[:i]
			}
		}
	}
	return s
}

func bracketsBalanced(s string) bool {
	depth, inStr := 0, false
	for _, c := range s {
		switch {
		case c == '"':
			inStr = !inStr
		case c == '[' && !inStr:
			depth++
		case c == ']' && !inStr:
			depth--
		}
	}
	return depth == 0
}

func parseValue(v string) (any, error) {
	v = strings.TrimSpace(v)
	switch {
	case strings.HasPrefix(v, "\""):
		s, err := strconv.Unquote(v)
		if err != nil {
			return nil, fmt.Errorf("bad string %s", v)
		}
		return s, nil
	case v == "true":
		return true, nil
	case v == "false":
		return false, nil
	case strings.HasPrefix(v, "["):
		inner := strings.TrimSpace(v[1 : len(v)-1])
		var items []string
		for inner != "" {
			inner = strings.TrimLeft(inner, " \t,")
			if inner == "" {
				break
			}
			if inner[0] != '"' {
				return nil, fmt.Errorf("arrays may contain only strings")
			}
			end := strings.Index(inner[1:], "\"")
			if end < 0 {
				return nil, fmt.Errorf("unterminated string in array")
			}
			items = append(items, inner[1:end+1])
			inner = inner[end+2:]
		}
		return items, nil
	default:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("unsupported value %q", v)
		}
		return n, nil
	}
}

// ---- typed accessors ----

type section map[string]any

func (s section) str(k string, d string) string {
	if v, ok := s[k].(string); ok {
		return v
	}
	return d
}
func (s section) num(k string, d int) int {
	if v, ok := s[k].(int64); ok {
		return int(v)
	}
	return d
}
func (s section) boolean(k string, d bool) bool {
	if v, ok := s[k].(bool); ok {
		return v
	}
	return d
}
func (s section) secs(k string, d time.Duration) time.Duration {
	if v, ok := s[k].(int64); ok {
		return time.Duration(v) * time.Second
	}
	return d
}

func loadCommon(s section) Common {
	c := defaultCommon()
	c.Transport = strings.ToLower(s.str("transport", c.Transport))
	c.Token = s.str("token", "")
	c.Keepalive = s.secs("keepalive_period", c.Keepalive)
	c.Nodelay = s.boolean("nodelay", c.Nodelay)
	c.Heartbeat = s.secs("heartbeat", c.Heartbeat)
	c.MuxFrameSize = s.num("mux_framesize", c.MuxFrameSize)
	c.MuxWindow = s.num("mux_window", c.MuxWindow)
	c.WebPort = s.num("web_port", 0)
	c.LogLevel = s.str("log_level", c.LogLevel)
	c.Path = s.str("path", c.Path)
	c.TLSCert = s.str("tls_cert", "")
	c.TLSKey = s.str("tls_key", "")
	c.TLSSNI = s.str("tls_sni", "")
	c.TLSInsecure = s.boolean("tls_insecure", c.TLSInsecure)
	c.ChannelSize = s.num("channel_size", c.ChannelSize)
	c.DialTimeout = s.secs("dial_timeout", c.DialTimeout)
	c.UDPIdle = s.secs("udp_idle_timeout", c.UDPIdle)
	c.Encryption = s.boolean("encryption", false)
	if c.MuxFrameSize < 1024 || c.MuxFrameSize > 65535 {
		c.MuxFrameSize = 32 * 1024
	}
	if c.MuxWindow < c.MuxFrameSize*2 {
		c.MuxWindow = c.MuxFrameSize * 2
	}
	if c.Heartbeat < time.Second {
		c.Heartbeat = time.Second
	}
	return c
}

func LoadConfig(path string) (*Config, error) {
	t, err := parseTOML(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if s, ok := t["server"]; ok {
		sec := section(s)
		sc := &ServerConfig{Common: loadCommon(sec)}
		sc.BindAddr = sec.str("bind_addr", "0.0.0.0:3080")
		sc.AcceptUDP = sec.boolean("accept_udp", false)
		sc.PeerAddr = sec.str("peer_addr", "")
		sc.SpoofSource = sec.str("spoof_source", "")
		if p, ok := sec["ports"].([]string); ok {
			sc.Ports = p
		}
		cfg.Server = sc
	}
	if s, ok := t["client"]; ok {
		sec := section(s)
		cc := &ClientConfig{Common: loadCommon(sec)}
		cc.RemoteAddr = sec.str("remote_addr", "")
		if arr, ok := sec["remote_addrs"].([]string); ok {
			cc.RemoteAddrs = arr
		}
		cc.EdgeIP = sec.str("edge_ip", "")
		cc.SpoofSource = sec.str("spoof_source", "")
		cc.ProxyProtocol = sec.boolean("proxy_protocol", false)
		cc.ConnectionPool = sec.num("connection_pool", 8)
		cc.RetryInterval = sec.secs("retry_interval", 3*time.Second)
		if cc.ConnectionPool < 1 {
			cc.ConnectionPool = 1
		}
		if len(cc.allRemotes()) == 0 {
			return nil, fmt.Errorf("client needs remote_addr (or remote_addrs)")
		}
		cfg.Client = cc
	}
	if s, ok := t["direct"]; ok {
		sec := section(s)
		d := &DirectConfig{
			Role:       strings.ToLower(sec.str("role", "")),
			BindAddr:   sec.str("bind_addr", "0.0.0.0:3090"),
			RemoteAddr: sec.str("remote_addr", ""),
			Token:      sec.str("token", ""),
			TunName:    sec.str("tun_name", "pol0"),
			LocalIP:    sec.str("local_ip", ""),
			PeerIP:     sec.str("peer_ip", ""),
			MTU:        sec.num("mtu", 1400),

			Carrier:     strings.ToLower(sec.str("carrier", "udp")),
			SpoofSource: sec.str("spoof_source", ""),
			SpoofPeerIP: sec.str("spoof_peer_ip", ""),
			SNIDomain:   sec.str("sni_domain", ""),
			Paths:       sec.num("paths", 1),
			AutoMTU:     sec.boolean("auto_mtu", true),
		}
		switch d.Carrier {
		case "udp", "icmp", "pck":
			// no carrier-specific required field
		case "spoof":
			if net.ParseIP(d.SpoofSource).To4() == nil {
				return nil, fmt.Errorf("direct carrier \"spoof\" needs spoof_source = an IPv4 address to forge")
			}
		case "sni":
			if d.SNIDomain == "" {
				return nil, fmt.Errorf("direct carrier \"sni\" needs sni_domain = a domain to name in the TLS ClientHello (one your route already reaches)")
			}
		case "tcp", "tcpmux", "ws", "wsmux", "wss", "wssmux", "spoofmux", "kcp", "quic":
			return nil, fmt.Errorf("direct.carrier %q: reliable/stream carriers are refused on purpose (IP packets inside a reliable stream collapse under loss); use udp, spoof, pck, sni or icmp", d.Carrier)
		default:
			return nil, fmt.Errorf("direct.carrier must be one of udp, spoof, pck, sni, icmp; got %q", d.Carrier)
		}
		if d.SpoofSource != "" && d.Carrier != "spoof" {
			return nil, fmt.Errorf("direct.spoof_source only applies to carrier = \"spoof\"")
		}
		if d.SNIDomain != "" && d.Carrier != "sni" {
			return nil, fmt.Errorf("direct.sni_domain only applies to carrier = \"sni\"")
		}
		if d.SpoofPeerIP != "" && net.ParseIP(d.SpoofPeerIP).To4() == nil {
			return nil, fmt.Errorf("direct.spoof_peer_ip %q is not an IPv4 address", d.SpoofPeerIP)
		}
		if d.Paths < 1 || d.Paths > directMaxPaths {
			return nil, fmt.Errorf("direct.paths must be 1..%d", directMaxPaths)
		}
		if d.MTU < 576 || d.MTU > 65535-directOverhead {
			return nil, fmt.Errorf("direct.mtu must be 576..%d", 65535-directOverhead)
		}
		if d.Role != "server" && d.Role != "client" {
			return nil, fmt.Errorf("direct.role must be \"server\" or \"client\"")
		}
		if d.Token == "" {
			return nil, fmt.Errorf("direct.token is required")
		}
		if d.LocalIP == "" || d.PeerIP == "" {
			return nil, fmt.Errorf("direct needs local_ip and peer_ip (point-to-point tunnel addresses)")
		}
		if d.Role == "client" && d.RemoteAddr == "" {
			return nil, fmt.Errorf("direct client needs remote_addr")
		}
		portOf := d.BindAddr
		if d.Role == "client" {
			portOf = d.RemoteAddr
		}
		if _, ps, err := net.SplitHostPort(portOf); err == nil {
			if p, err := strconv.Atoi(ps); err == nil && p+d.Paths-1 > 65535 {
				return nil, fmt.Errorf("direct: paths = %d needs ports %d..%d, past 65535", d.Paths, p, p+d.Paths-1)
			}
		}
		cfg.Direct = d
	}
	if cfg.Server == nil && cfg.Client == nil && cfg.Direct == nil {
		return nil, fmt.Errorf("config needs a [server], [client] or [direct] section")
	}
	for _, c := range []*Common{commonOf(cfg.Server), commonOf2(cfg.Client)} {
		if c == nil {
			continue
		}
		if c.Token == "" {
			return nil, fmt.Errorf("token is required (generate one with: pol -gen-token)")
		}
		if !validTransport(c.Transport) {
			return nil, fmt.Errorf("unknown transport %q", c.Transport)
		}
	}
	return cfg, nil
}

func commonOf(s *ServerConfig) *Common {
	if s == nil {
		return nil
	}
	return &s.Common
}
func commonOf2(c *ClientConfig) *Common {
	if c == nil {
		return nil
	}
	return &c.Common
}

func validTransport(t string) bool {
	switch t {
	case "tcp", "tcpmux", "ws", "wsmux", "wss", "wssmux", "spoof", "spoofmux":
		return true
	}
	return false
}

func isMux(t string) bool { return strings.HasSuffix(t, "mux") }
