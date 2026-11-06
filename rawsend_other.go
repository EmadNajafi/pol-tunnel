//go:build !linux

package main

import (
	"errors"
	"net"
)

// buildSender on non-Linux platforms supports only the plain (non-spoofing) path.
func buildSender(sock *net.UDPConn, spoofSrc, refAddr string) (packetSender, error) {
	if spoofSrc == "" {
		return plainSender{sock}, nil
	}
	return nil, errors.New("spoof_source: IP source spoofing needs a raw socket and is only implemented on Linux (run on Ubuntu as root)")
}
