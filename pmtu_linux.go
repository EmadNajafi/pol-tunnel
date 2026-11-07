//go:build linux

package main

import (
	"net"
	"sync"
	"syscall"
)

const ipPMTUDiscProbe = 3 // IP_PMTUDISC_PROBE: set DF, ignore the cached path MTU, never fragment

// savedPMTU remembers each socket's original IP_MTU_DISCOVER mode, so turning
// probe mode off restores whatever the system default was.
var savedPMTU sync.Map // *net.UDPConn -> int

// setPMTUProbe switches a UDP socket into (or back out of) path-MTU probe mode.
func setPMTUProbe(c *net.UDPConn, on bool) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = rc.Control(func(fd uintptr) {
		if on {
			if _, ok := savedPMTU.Load(c); !ok {
				if v, err := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER); err == nil {
					savedPMTU.Store(c, v)
				}
			}
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, ipPMTUDiscProbe)
			return
		}
		if v, ok := savedPMTU.LoadAndDelete(c); ok {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, v.(int))
		}
	})
	if err != nil {
		return err
	}
	return serr
}
