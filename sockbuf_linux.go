//go:build linux

package main

import (
	"net"
	"syscall"
)

// Linux caps SO_RCVBUF / SO_SNDBUF at net.core.rmem_max / wmem_max, about
// 200 KB by default: a few hundred packets, which a burst overruns at once.
// The *FORCE variants let root go past the cap, so the tunnel gets the
// buffer it asked for without the operator having to tune sysctls.
const (
	soSndBufForce = 32
	soRcvBufForce = 33
)

func forceSockBuf(fd int, size int) {
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, size)
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soRcvBufForce, size) // fails quietly when not root
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soSndBufForce, size)
}

// bigBuffers gives a UDP socket send and receive buffers of size bytes.
func bigBuffers(c *net.UDPConn, size int) {
	c.SetReadBuffer(size)
	c.SetWriteBuffer(size)
	if rc, err := c.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) { forceSockBuf(int(fd), size) })
	}
}
