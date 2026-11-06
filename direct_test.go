package main

import (
	"bytes"
	"crypto/rand"
	"testing"
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
	initMsg := makeInit(token, ephI.PublicKey().Bytes())

	// responder (server) handles INIT
	initPub, err := parseInit(token, initMsg)
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
	if _, err := parseInit("wrong", initMsg); err == nil {
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
