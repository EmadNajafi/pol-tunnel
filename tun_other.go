//go:build !linux

package main

import "errors"

// Direct (L3) mode uses a TUN device, which this build only supports on Linux.
type tunDevice struct{ name string }

func openTUN(name string) (*tunDevice, error) {
	return nil, errors.New("direct (L3) mode needs a TUN device and is only implemented on Linux (run on Ubuntu as root)")
}

func (t *tunDevice) Read(p []byte) (int, error)                      { return 0, errNoTUN }
func (t *tunDevice) Write(p []byte) (int, error)                     { return 0, errNoTUN }
func (t *tunDevice) Close() error                                    { return nil }
func (t *tunDevice) configure(localIP, peerIP string, mtu int) error { return errNoTUN }

var errNoTUN = errors.New("direct mode: TUN not supported on this platform")
