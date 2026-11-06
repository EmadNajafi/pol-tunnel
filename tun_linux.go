//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

// tunDevice is a Linux TUN interface carrying raw IPv4/IPv6 packets (IFF_TUN,
// IFF_NO_PI = no 4-byte packet-info prefix). Needs root / CAP_NET_ADMIN.
type tunDevice struct {
	f    *os.File
	name string
}

const (
	cIFF_TUN   = 0x0001
	cIFF_NO_PI = 0x1000
	cTUNSETIFF = 0x400454ca
)

type ifReq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

func openTUN(name string) (*tunDevice, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun (need root): %w", err)
	}
	var req ifReq
	copy(req.name[:15], name)
	req.flags = cIFF_TUN | cIFF_NO_PI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), cTUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF: %v", errno)
	}
	got := string(req.name[:])
	if i := indexZero(req.name[:]); i >= 0 {
		got = string(req.name[:i])
	}
	return &tunDevice{f: f, name: got}, nil
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

func (t *tunDevice) Read(p []byte) (int, error)  { return t.f.Read(p) }
func (t *tunDevice) Write(p []byte) (int, error) { return t.f.Write(p) }
func (t *tunDevice) Close() error                { return t.f.Close() }

// configure brings the interface up with a point-to-point address and MTU,
// using the `ip` tool. It adds only this /32 peer route, never a default route,
// so it cannot disturb the host's existing networking.
func (t *tunDevice) configure(localIP, peerIP string, mtu int) error {
	steps := [][]string{
		{"ip", "addr", "add", localIP + "/32", "peer", peerIP, "dev", t.name},
		{"ip", "link", "set", "dev", t.name, "mtu", fmt.Sprint(mtu)},
		{"ip", "link", "set", "dev", t.name, "up"},
	}
	for _, s := range steps {
		if out, err := exec.Command(s[0], s[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %v (%s)", s, err, out)
		}
	}
	return nil
}
