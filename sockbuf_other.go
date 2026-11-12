//go:build !linux

package main

import "net"

// bigBuffers gives a UDP socket send and receive buffers of size bytes.
func bigBuffers(c *net.UDPConn, size int) {
	c.SetReadBuffer(size)
	c.SetWriteBuffer(size)
}
