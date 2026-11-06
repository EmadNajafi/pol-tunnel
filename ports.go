package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// PortMap is one listener on the server and the address the client should dial.
type PortMap struct {
	Listen string // "ip:port" bound on the server (Iran side)
	Target string // "host:port" dialed by the client (kharej side)
}

const maxRange = 20000

// ParsePorts understands Backhaul's syntax:
//
//	"443"                      listen :443        -> 127.0.0.1:443
//	"4000=5000"                listen :4000       -> 127.0.0.1:5000
//	"443-600"                  listen :443..600   -> same ports
//	"443-600:5201"             listen :443..600   -> 127.0.0.1:5201
//	"443-600=1.1.1.1:5201"     listen :443..600   -> 1.1.1.1:5201
//	"127.0.0.2:443=5201"       listen 127.0.0.2:443 -> 127.0.0.1:5201
//	"443=1.1.1.1:5201", "127.0.0.2:443=1.1.1.1:5201"
func ParsePorts(entries []string) ([]PortMap, error) {
	var out []PortMap
	seen := map[string]bool{}
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		maps, err := parsePortEntry(e)
		if err != nil {
			return nil, fmt.Errorf("ports entry %q: %v", raw, err)
		}
		for _, m := range maps {
			if seen[m.Listen] {
				return nil, fmt.Errorf("listen address %s used twice", m.Listen)
			}
			seen[m.Listen] = true
			out = append(out, m)
		}
	}
	return out, nil
}

func parsePortEntry(e string) ([]PortMap, error) {
	var lhs, rhs string
	if i := strings.Index(e, "="); i >= 0 {
		lhs, rhs = e[:i], e[i+1:]
	} else if i := strings.LastIndex(e, ":"); i >= 0 && isPortOrRange(e[:i]) {
		// "443-600:5201" form: range followed by a target port
		lhs, rhs = e[:i], e[i+1:]
	} else {
		lhs = e
	}

	bindIP, lo, hi, err := parseListenSide(lhs)
	if err != nil {
		return nil, err
	}

	targetHost, targetPort := "127.0.0.1", 0 // 0 means "same as listen port"
	if rhs != "" {
		if p, err := strconv.Atoi(rhs); err == nil {
			targetPort = p
		} else {
			h, ps, err := net.SplitHostPort(rhs)
			if err != nil {
				return nil, fmt.Errorf("bad target %q", rhs)
			}
			p, err := strconv.Atoi(ps)
			if err != nil {
				return nil, fmt.Errorf("bad target port %q", ps)
			}
			targetHost, targetPort = h, p
		}
		if targetPort < 1 || targetPort > 65535 {
			return nil, fmt.Errorf("target port out of range")
		}
	}

	var out []PortMap
	for p := lo; p <= hi; p++ {
		tp := targetPort
		if tp == 0 {
			tp = p
		}
		out = append(out, PortMap{
			Listen: net.JoinHostPort(bindIP, strconv.Itoa(p)),
			Target: net.JoinHostPort(targetHost, strconv.Itoa(tp)),
		})
	}
	return out, nil
}

func isPortOrRange(s string) bool {
	_, _, err := parseRange(s)
	return err == nil
}

func parseListenSide(s string) (ip string, lo, hi int, err error) {
	ip = "0.0.0.0"
	portPart := s
	if i := strings.LastIndex(s, ":"); i >= 0 {
		ip = strings.Trim(s[:i], "[]")
		portPart = s[i+1:]
		if net.ParseIP(ip) == nil {
			return "", 0, 0, fmt.Errorf("bad bind ip %q", ip)
		}
	}
	lo, hi, err = parseRange(portPart)
	return
}

func parseRange(s string) (int, int, error) {
	parts := strings.SplitN(s, "-", 2)
	lo, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("bad port %q", parts[0])
	}
	hi := lo
	if len(parts) == 2 {
		if hi, err = strconv.Atoi(strings.TrimSpace(parts[1])); err != nil {
			return 0, 0, fmt.Errorf("bad port %q", parts[1])
		}
	}
	if lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("port range %d-%d invalid", lo, hi)
	}
	if hi-lo >= maxRange {
		return 0, 0, fmt.Errorf("port range larger than %d", maxRange)
	}
	return lo, hi, nil
}
