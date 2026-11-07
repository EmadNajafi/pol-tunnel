//go:build !linux

package main

import (
	"fmt"
	"net"
)

// newRawPaths: the pck, sni and icmp carriers build raw packets and need a raw
// socket, so they run only on Linux as root. Elsewhere pol still compiles and
// the udp carrier works.
func newRawPaths(cfg *DirectConfig) ([]*directPath, []*net.UDPAddr, func(), error) {
	return nil, nil, nil, fmt.Errorf("direct carrier %q needs a raw socket and is only implemented on Linux (run on Ubuntu as root); use carrier = \"udp\"", cfg.Carrier)
}
