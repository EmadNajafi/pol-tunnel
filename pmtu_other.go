//go:build !linux

package main

import "net"

// setPMTUProbe is a no-op off Linux (direct mode itself is Linux-only; this
// keeps the engine buildable and testable elsewhere).
func setPMTUProbe(c *net.UDPConn, on bool) error { return nil }
