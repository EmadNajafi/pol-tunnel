package main

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// Exercises the direct-mode handshake + AEAD end to end in memory, both
// directions, plus the tamper / wrong-token rejections.
func TestDirectHandshakeAEAD(t *testing.T) {
	const token = "shared-secret-token"

	// initiator (client)
	ephI, err := genEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	initMsg := makeInit(token, ephI.PublicKey().Bytes(), time.Now())

	// responder (server) handles INIT
	initPub, err := parseInit(token, initMsg, time.Now())
	if err != nil {
		t.Fatalf("parseInit: %v", err)
	}
	ephR, err := genEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	respMsg := makeResp(token, initPub, ephR.PublicKey().Bytes())
	ssR, err := sharedSecret(ephR, initPub)
	if err != nil {
		t.Fatal(err)
	}
	keysR, err := deriveKeys(token, ssR, false)
	if err != nil {
		t.Fatal(err)
	}

	// initiator handles RESP
	respPub, err := parseResp(token, ephI.PublicKey().Bytes(), respMsg)
	if err != nil {
		t.Fatalf("parseResp: %v", err)
	}
	ssI, err := sharedSecret(ephI, respPub)
	if err != nil {
		t.Fatal(err)
	}
	keysI, err := deriveKeys(token, ssI, true)
	if err != nil {
		t.Fatal(err)
	}

	// both sides must have derived the same two keys
	if !bytes.Equal(ssI, ssR) {
		t.Fatal("shared secrets differ")
	}

	// data both directions through the AEAD
	for i := 0; i < 1000; i++ {
		msg := make([]byte, 1+i%1400)
		rand.Read(msg)
		// initiator -> responder
		got, err := keysR.recv.open(keysI.send.seal(msg))
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("i->r packet %d: err=%v equal=%v", i, err, bytes.Equal(got, msg))
		}
		// responder -> initiator
		got, err = keysI.recv.open(keysR.send.seal(msg))
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("r->i packet %d: err=%v", i, err)
		}
	}

	// wrong token must fail authentication
	if _, err := parseInit("wrong", initMsg, time.Now()); err == nil {
		t.Error("INIT accepted with wrong token")
	}
	if _, err := parseResp("wrong", ephI.PublicKey().Bytes(), respMsg); err == nil {
		t.Error("RESP accepted with wrong token")
	}

	// a tampered ciphertext must fail the AEAD tag
	sealed := keysI.send.seal([]byte("hello"))
	sealed[len(sealed)-1] ^= 0xff
	if _, err := keysR.recv.open(sealed); err == nil {
		t.Error("tampered ciphertext accepted")
	}
}

func TestDirectInitTimestamp(t *testing.T) {
	const token = "tok"
	eph, _ := genEphemeral()
	now := time.Now()
	old := makeInit(token, eph.PublicKey().Bytes(), now.Add(-10*time.Minute))
	if _, err := parseInit(token, old, now); err == nil {
		t.Error("stale INIT accepted")
	}
	future := makeInit(token, eph.PublicKey().Bytes(), now.Add(10*time.Minute))
	if _, err := parseInit(token, future, now); err == nil {
		t.Error("future INIT accepted")
	}
	// tampering with the timestamp must break the MAC
	m := makeInit(token, eph.PublicKey().Bytes(), now)
	m[8] ^= 1
	if _, err := parseInit(token, m, now); err == nil {
		t.Error("INIT with altered timestamp accepted")
	}
}

func newTestDirect(t *testing.T, role string) *directEngine {
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sock.Close() })
	e, err := newDirectEngine(&DirectConfig{Role: role, Token: "tok"}, nil, []*net.UDPConn{sock}, make([]*net.UDPAddr, 1))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// readResp reads the RESP the server sent to the client's socket.
func readResp(t *testing.T, c *directEngine) []byte {
	buf := make([]byte, 2048)
	c.paths[0].sock.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := c.paths[0].sock.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no RESP: %v", err)
	}
	return buf[:n]
}

// readData reads one DATA packet from e's socket and returns its sealed body.
func readData(t *testing.T, e *directEngine) ([]byte, *net.UDPAddr) {
	buf := make([]byte, 2048)
	e.paths[0].sock.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, src, err := e.paths[0].sock.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no DATA: %v", err)
	}
	if buf[0] != dirDATA {
		t.Fatalf("expected DATA, got type %d", buf[0])
	}
	return append([]byte(nil), buf[1:n]...), src
}

// A replayed INIT must neither reset the session nor redirect it.
func TestDirectInitReplay(t *testing.T) {
	srv := newTestDirect(t, "server")
	cli := newTestDirect(t, "client")
	atk := newTestDirect(t, "client")
	cli.peers[0] = srv.paths[0].sock.LocalAddr().(*net.UDPAddr)
	cliAddr := cli.paths[0].sock.LocalAddr().(*net.UDPAddr)
	atkAddr := atk.paths[0].sock.LocalAddr().(*net.UDPAddr)

	eph, _ := genEphemeral()
	cli.clientEph = eph
	initMsg := makeInit("tok", eph.PublicKey().Bytes(), time.Now())

	srv.handleInit(initMsg, cliAddr, srv.paths[0])
	resp := readResp(t, cli)
	cli.handleResp(resp) // sends a keepalive under the new keys
	sealed, src := readData(t, srv)
	if _, ok := srv.handleData(sealed, src, 0); !ok {
		t.Fatal("server rejected the client's first DATA")
	}
	if !srv.up || srv.keys == nil {
		t.Fatal("server did not promote the handshake keys")
	}
	active := srv.keys

	// retransmission of the same INIT: same RESP again, keys unchanged
	srv.handleInit(initMsg, cliAddr, srv.paths[0])
	if again := readResp(t, cli); !bytes.Equal(again, resp) {
		t.Error("retransmitted INIT got a different RESP")
	}
	if srv.keys != active {
		t.Error("retransmitted INIT changed the keys")
	}

	// a newer INIT from the same client, then the old one replayed by an attacker
	eph2, _ := genEphemeral()
	srv.handleInit(makeInit("tok", eph2.PublicKey().Bytes(), time.Now()), cliAddr, srv.paths[0])
	readResp(t, cli)
	srv.handleInit(initMsg, atkAddr, srv.paths[0])
	atk.paths[0].sock.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := atk.paths[0].sock.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Error("replayed INIT was answered")
	}
	if srv.keys != active {
		t.Error("INIT replay/new INIT changed the active keys before any DATA")
	}
	if srv.peers[0].String() != cliAddr.String() {
		t.Errorf("peer address hijacked: %v", srv.peers[0])
	}

	// replaying an old DATA packet from the attacker's address is rejected too
	if _, ok := srv.handleData(sealed, atkAddr, 0); ok {
		t.Error("replayed DATA accepted")
	}
	if srv.peers[0].String() != cliAddr.String() {
		t.Errorf("peer address hijacked by DATA replay: %v", srv.peers[0])
	}
}
