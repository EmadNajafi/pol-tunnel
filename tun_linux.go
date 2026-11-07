//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

// tunDevice is a Linux TUN interface carrying raw IPv4/IPv6 packets (IFF_TUN,
// IFF_NO_PI = no 4-byte packet-info prefix). Needs root / CAP_NET_ADMIN.
//
// It holds a raw blocking file descriptor and reads/writes it with syscalls,
// deliberately NOT through an *os.File. An *os.File registers the fd with the
// Go runtime's network poller, and for /dev/net/tun that registration can fail
// with "not pollable" — intermittently, and notably right after the same
// interface was torn down and immediately reopened (a crash-restart on the same
// tun_name). A blocking raw fd has no poller to fail. Close unblocks a pending
// Read (the syscall returns EBADF).
type tunDevice struct {
	fd   int
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

// openTUN opens /dev/net/tun and attaches interface `name`. On a crash-restart
// the kernel may still be tearing down the old interface, so a transient EBUSY
// is retried briefly rather than failing the whole engine.
func openTUN(name string) (*tunDevice, error) {
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		t, err := openTUNOnce(name)
		if err == nil {
			return t, nil
		}
		lastErr = err
		if errno, ok := err.(syscall.Errno); ok && (errno == syscall.EBUSY || errno == syscall.EINTR) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("open tun %q: %w", name, lastErr)
}

func openTUNOnce(name string) (*tunDevice, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun (need root): %w", err)
	}
	var req ifReq
	copy(req.name[:15], name)
	req.flags = cIFF_TUN | cIFF_NO_PI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), cTUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		syscall.Close(fd)
		return nil, errno // a syscall.Errno, so openTUN can see EBUSY/EINTR
	}
	got := string(req.name[:])
	if i := indexZero(req.name[:]); i >= 0 {
		got = string(req.name[:i])
	}
	return &tunDevice{fd: fd, name: got}, nil
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

func (t *tunDevice) Read(p []byte) (int, error) {
	for {
		n, err := syscall.Read(t.fd, p)
		if err == syscall.EINTR {
			continue
		}
		return n, err
	}
}

func (t *tunDevice) Write(p []byte) (int, error) {
	for {
		n, err := syscall.Write(t.fd, p)
		if err == syscall.EINTR {
			continue
		}
		return n, err
	}
}

func (t *tunDevice) Close() error { return syscall.Close(t.fd) }

// setMTU changes the interface MTU (direct mode's auto MTU).
func (t *tunDevice) setMTU(mtu int) error {
	if out, err := exec.Command("ip", "link", "set", "dev", t.name, "mtu", fmt.Sprint(mtu)).CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set mtu %d: %v (%s)", mtu, err, out)
	}
	return nil
}

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
