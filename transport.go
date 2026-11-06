package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

func tuneTCP(c net.Conn, cm *Common) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(cm.Nodelay)
		if cm.Keepalive > 0 {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(cm.Keepalive)
		}
	}
}

// ---- server side ----

type TransportListener interface {
	Accept() (net.Conn, error)
	Close() error
}

type tcpListener struct {
	net.Listener
	cm *Common
}

func (l *tcpListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		tuneTCP(c, l.cm)
	}
	return c, err
}

type wsListener struct {
	ln   net.Listener
	srv  *http.Server
	out  chan net.Conn
	done chan struct{}
}

func (l *wsListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.out:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *wsListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return l.srv.Close()
}

type tuningListener struct {
	net.Listener
	cm *Common
}

func (l tuningListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		tuneTCP(c, l.cm)
	}
	return c, err
}

func Listen(cfg *ServerConfig) (TransportListener, error) {
	if strings.HasPrefix(cfg.Transport, "spoof") {
		return listenSpoof(cfg)
	}
	raw, err := net.Listen("tcp", cfg.BindAddr)
	if err != nil {
		return nil, err
	}
	t := cfg.Transport
	if t == "tcp" || t == "tcpmux" {
		return &tcpListener{raw, &cfg.Common}, nil
	}
	var ln net.Listener = tuningListener{raw, &cfg.Common}
	if strings.HasPrefix(t, "wss") {
		tc, err := serverTLS(&cfg.Common)
		if err != nil {
			raw.Close()
			return nil, err
		}
		ln = tls.NewListener(ln, tc)
	}
	wl := &wsListener{ln: ln, out: make(chan net.Conn, 64), done: make(chan struct{})}
	wl.srv = &http.Server{
		Handler:           wsServerHandler(cfg.Path, wl.out),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          nil,
	}
	go wl.srv.Serve(ln)
	return wl, nil
}

func serverTLS(cm *Common) (*tls.Config, error) {
	if cm.TLSCert != "" && cm.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cm.TLSCert, cm.TLSKey)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}
	logf("warn", "no tls_cert/tls_key given: using an in-memory self-signed certificate")
	cert, err := selfSigned()
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// ---- client side ----

type Dialer func(ctx context.Context) (net.Conn, error)

func NewDialer(cfg *ClientConfig) Dialer {
	if strings.HasPrefix(cfg.Transport, "spoof") {
		return newSpoofDialer(cfg)
	}
	addrs := cfg.allRemotes()
	cm := &cfg.Common
	var idx atomic.Uint32
	return func(ctx context.Context) (net.Conn, error) {
		// Rotate the address on every attempt, so a dead server is skipped on the
		// next retry and backups are tried deterministically (round-robin across
		// however many are healthy).
		remote := addrs[int(idx.Add(1)-1)%len(addrs)]
		c, err := dialOne(ctx, cm, remote, cfg.EdgeIP)
		if err != nil {
			if len(addrs) > 1 {
				logf("debug", "dial %s failed, will try the next address: %v", remote, err)
			}
			return nil, err
		}
		return c, nil
	}
}

// dialOne connects once to a single server address, applying the transport
// (tcp / ws / wss) and edge-IP / SNI handling.
func dialOne(ctx context.Context, cm *Common, remote, edgeIP string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	dialAddr := remote
	if edgeIP != "" { // connect to a CDN edge, keep Host/SNI of the real domain
		_, port, _ := net.SplitHostPort(remote)
		dialAddr = net.JoinHostPort(edgeIP, port)
	}
	d := net.Dialer{Timeout: cm.DialTimeout}
	c, err := d.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return nil, err
	}
	tuneTCP(c, cm)
	t := cm.Transport
	if t == "tcp" || t == "tcpmux" {
		return c, nil
	}
	c.SetDeadline(time.Now().Add(cm.DialTimeout))
	if strings.HasPrefix(t, "wss") {
		sni := cm.TLSSNI
		if sni == "" {
			sni = host
		}
		tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: cm.TLSInsecure, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		c = tc
	}
	hostHeader := remote
	if cm.TLSSNI != "" {
		hostHeader = cm.TLSSNI
	}
	wc, err := wsClientUpgrade(c, hostHeader, cm.Path)
	if err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return wc, nil
}

var errNoConn = errors.New("no tunnel connection available")
