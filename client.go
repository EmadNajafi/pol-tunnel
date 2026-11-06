package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// Client is the kharej side: it dials out to the server, keeps a warm pool of
// data conns (or a few mux sessions), and forwards whatever the server sends
// to the target address named in each open header.
type Client struct {
	cfg   *ClientConfig
	dial  Dialer
	stats *Stats
}

func NewClient(cfg *ClientConfig) *Client {
	return &Client{cfg: cfg, dial: NewDialer(cfg), stats: NewStats()}
}

func (c *Client) Run() error {
	c.stats.Info = func() map[string]any {
		return map[string]any{"transport": c.cfg.Transport, "remote": c.cfg.RemoteAddr}
	}
	c.stats.Serve(c.cfg.WebPort)
	if isMux(c.cfg.Transport) {
		for i := 0; i < c.cfg.ConnectionPool; i++ {
			go c.muxLoop(i)
		}
		select {}
	}
	c.controlLoop()
	return nil
}

func (c *Client) connect(ctx context.Context, kind byte) (net.Conn, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := clientHandshake(conn, c.cfg.Token, kind); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// ---- mux mode ----

func (c *Client) muxLoop(i int) {
	for {
		conn, err := c.connect(context.Background(), connMux)
		if err != nil {
			logf("warn", "mux #%d: %v (retry in %v)", i, err, c.cfg.RetryInterval)
			time.Sleep(c.cfg.RetryInterval)
			continue
		}
		sess := NewSession(conn, c.cfg.MuxFrameSize, c.cfg.MuxWindow, c.cfg.Heartbeat)
		logf("info", "mux #%d connected to %s", i, c.cfg.RemoteAddr)
		for {
			st, err := sess.Accept()
			if err != nil {
				break
			}
			go c.handle(st, st.openProto, st.openAddr)
		}
		sess.Close()
		logf("warn", "mux #%d disconnected", i)
		time.Sleep(c.cfg.RetryInterval)
	}
}

// ---- pooled mode (tcp / ws / wss) ----

func (c *Client) controlLoop() {
	for {
		ctx, cancel := context.WithCancel(context.Background())
		ctl, err := c.connect(ctx, connControl)
		if err != nil {
			cancel()
			logf("warn", "control: %v (retry in %v)", err, c.cfg.RetryInterval)
			time.Sleep(c.cfg.RetryInterval)
			continue
		}
		hb := c.cfg.Heartbeat
		ctl.SetReadDeadline(time.Now().Add(15 * time.Second))
		msg := make([]byte, 3)
		if _, err := io.ReadFull(ctl, msg); err == nil && msg[0] == ctlConfig {
			if v := binary.BigEndian.Uint16(msg[1:]); v > 0 {
				hb = time.Duration(v) * time.Second
			}
		}
		logf("info", "connected to %s (pool=%d, heartbeat=%v)", c.cfg.RemoteAddr, c.cfg.ConnectionPool, hb)

		for i := 0; i < c.cfg.ConnectionPool; i++ {
			go c.dataWorker(ctx, hb, true)
		}
		b := make([]byte, 1)
	loop:
		for {
			ctl.SetReadDeadline(time.Now().Add(3 * hb))
			if _, err := io.ReadFull(ctl, b); err != nil {
				break
			}
			switch b[0] {
			case ctlHeartbeat:
				ctl.SetWriteDeadline(time.Now().Add(10 * time.Second))
				ctl.Write([]byte{ctlHeartbeat})
			case ctlNeed:
				nb := make([]byte, 2)
				if _, err := io.ReadFull(ctl, nb); err != nil {
					break loop
				}
				n := int(binary.BigEndian.Uint16(nb))
				if n > 64 {
					n = 64
				}
				for i := 0; i < n; i++ {
					go c.dataWorker(ctx, hb, false)
				}
			}
		}
		cancel()
		ctl.Close()
		logf("warn", "control channel lost, reconnecting in %v", c.cfg.RetryInterval)
		time.Sleep(c.cfg.RetryInterval)
	}
}

// dataWorker holds one idle data conn in the server's pool. Persistent workers
// redial as soon as their conn is used or dies; one-shot workers serve one visitor.
func (c *Client) dataWorker(ctx context.Context, hb time.Duration, persistent bool) {
	for ctx.Err() == nil {
		conn, err := c.connect(ctx, connData)
		if err != nil {
			if !persistent {
				return
			}
			logf("debug", "data conn: %v", err)
			select {
			case <-time.After(c.cfg.RetryInterval):
			case <-ctx.Done():
			}
			continue
		}
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		proto, addr, err := waitHeader(conn, hb)
		if !stop() || err != nil { // ctx cancelled or conn died while idle
			conn.Close()
			if !persistent {
				return
			}
			continue
		}
		go c.handle(conn, proto, addr)
		if !persistent {
			return
		}
	}
}

func waitHeader(conn net.Conn, hb time.Duration) (byte, string, error) {
	defer conn.SetReadDeadline(time.Time{})
	b := make([]byte, 1)
	for {
		conn.SetReadDeadline(time.Now().Add(3 * hb))
		if _, err := io.ReadFull(conn, b); err != nil {
			return 0, "", err
		}
		if b[0] != protoPing {
			break
		}
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	proto := b[0]
	if _, err := io.ReadFull(conn, b); err != nil {
		return 0, "", err
	}
	a := make([]byte, b[0])
	if _, err := io.ReadFull(conn, a); err != nil {
		return 0, "", err
	}
	return proto, string(a), nil
}

// ---- forwarding to the real service ----

func (c *Client) handle(t io.ReadWriteCloser, proto byte, addr string) {
	switch proto {
	case protoTCP:
		dst, err := net.DialTimeout("tcp", addr, c.cfg.DialTimeout)
		if err != nil {
			logf("warn", "dial %s: %v", addr, err)
			t.Close()
			return
		}
		tuneTCP(dst, &c.cfg.Common)
		pipe(t, dst, c.stats.Get(addr+"/tcp"))
	case protoUDP:
		c.handleUDP(t, addr)
	default:
		t.Close()
	}
}

func (c *Client) handleUDP(t io.ReadWriteCloser, addr string) {
	uc, err := net.Dial("udp", addr)
	if err != nil {
		logf("warn", "dial udp %s: %v", addr, err)
		t.Close()
		return
	}
	st := c.stats.Get(addr + "/udp")
	st.Active.Add(1)
	st.Total.Add(1)
	defer st.Active.Add(-1)
	go func() { // service -> tunnel
		buf := make([]byte, 65535)
		for {
			uc.SetReadDeadline(time.Now().Add(c.cfg.UDPIdle))
			n, err := uc.Read(buf)
			if err != nil || writeDatagram(t, buf[:n]) != nil {
				t.Close()
				uc.Close()
				return
			}
			st.BytesOut.Add(int64(n))
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, err := readDatagram(t, buf)
		if err != nil {
			break
		}
		st.BytesIn.Add(int64(n))
		uc.Write(buf[:n])
	}
	t.Close()
	uc.Close()
}
