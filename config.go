package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config mirrors the Backhaul-style TOML layout: one [server] or one [client] section.
type Config struct {
	Server *ServerConfig
	Client *ClientConfig
}

type Common struct {
	Transport     string // tcp | tcpmux | ws | wsmux | wss | wssmux
	Token         string
	Keepalive     time.Duration
	Nodelay       bool
	Heartbeat     time.Duration
	MuxFrameSize  int
	MuxWindow     int
	WebPort       int
	LogLevel      string
	Path          string // websocket path
	TLSCert       string
	TLSKey        string
	TLSSNI        string
	TLSInsecure   bool
	ChannelSize   int
	DialTimeout   time.Duration
	UDPIdle       time.Duration
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
	EdgeIP         string
	ConnectionPool int
	RetryInterval  time.Duration
	SpoofSource    string // spoof: forge this source IP on outgoing packets (Linux, root)
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
		cc.EdgeIP = sec.str("edge_ip", "")
		cc.SpoofSource = sec.str("spoof_source", "")
		cc.ConnectionPool = sec.num("connection_pool", 8)
		cc.RetryInterval = sec.secs("retry_interval", 3*time.Second)
		if cc.ConnectionPool < 1 {
			cc.ConnectionPool = 1
		}
		if cc.RemoteAddr == "" {
			return nil, fmt.Errorf("client.remote_addr is required")
		}
		cfg.Client = cc
	}
	if cfg.Server == nil && cfg.Client == nil {
		return nil, fmt.Errorf("config needs a [server] or [client] section")
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
