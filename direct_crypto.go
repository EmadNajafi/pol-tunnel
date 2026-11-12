package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"time"
)

// Direct-mode cryptography: a Noise-like handshake giving forward secrecy plus
// pre-shared-token authentication, then AES-256-GCM AEAD per packet.
//
// Handshake (over UDP, the initiator retransmits INIT until it gets RESP):
//
//	I -> R : 0x01 | ts[8] | ephI[32] | HMAC(token, "pol-direct-init" | ts | ephI)
//	R -> I : 0x02 | ephR[32] | HMAC(token, "pol-direct-resp" | ephI | ephR)
//
// Both derive ss = X25519(ownEph, peerEph), then
//	prk  = HKDF-Extract(salt=token, ikm=ss)
//	kI2R = HKDF-Expand(prk, "pol-direct i2r", 32)
//	kR2I = HKDF-Expand(prk, "pol-direct r2i", 32)
// The initiator seals with kI2R / opens with kR2I; the responder is opposite.
// A MITM without the token cannot forge the HMACs, so it cannot complete it.
// The responder rejects INITs whose timestamp is outside initMaxSkew and
// remembers recently seen ephI keys, so a captured INIT cannot be replayed to
// reset the session; it also keeps the old keys until the first DATA packet
// sealed with the new ones arrives.

const (
	dirINIT byte = 1
	dirRESP byte = 2
	dirDATA byte = 3

	x25519Len = 32
	gcmNonce  = 12
	gcmTag    = 16
)

// ---- HKDF (RFC 5869) over HMAC-SHA256, stdlib only ----

func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	var out, t []byte
	h := hmac.New(sha256.New, prk)
	for i := byte(1); len(out) < length; i++ {
		h.Reset()
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

func dmac(token string, parts ...[]byte) []byte {
	h := hmac.New(sha256.New, []byte(token))
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// ---- session keys ----

type directKeys struct {
	send *aeadCounter
	recv *aeadCounter
}

func deriveKeys(token string, ss []byte, initiator bool) (*directKeys, error) {
	prk := hkdfExtract([]byte(token), ss)
	kI2R := hkdfExpand(prk, []byte("pol-direct i2r"), 32)
	kR2I := hkdfExpand(prk, []byte("pol-direct r2i"), 32)
	mkAEAD := func(key []byte) (*aeadCounter, error) {
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		g, err := cipher.NewGCM(blk)
		if err != nil {
			return nil, err
		}
		return &aeadCounter{aead: g}, nil
	}
	i2r, err := mkAEAD(kI2R)
	if err != nil {
		return nil, err
	}
	r2i, err := mkAEAD(kR2I)
	if err != nil {
		return nil, err
	}
	if initiator {
		return &directKeys{send: i2r, recv: r2i}, nil
	}
	return &directKeys{send: r2i, recv: i2r}, nil
}

// aeadCounter wraps a GCM AEAD with a 96-bit monotonic sender nonce. Each
// direction has its own key, so each counter can start at 0 without collision.
type aeadCounter struct {
	aead    cipher.AEAD
	counter atomic.Uint64 // seal may be called from several goroutines (data + keepalive)
}

// seal encrypts p, returning nonce[12] | ciphertext.
func (a *aeadCounter) seal(p []byte) []byte {
	return a.sealAppend(make([]byte, 0, gcmNonce+len(p)+gcmTag), p)
}

// sealAppend appends nonce[12] | ciphertext for p to dst (no allocation when
// dst has room: the per-packet paths reuse their buffers).
func (a *aeadCounter) sealAppend(dst, p []byte) []byte {
	var nonce [gcmNonce]byte
	binary.BigEndian.PutUint64(nonce[4:], a.counter.Add(1))
	dst = append(dst, nonce[:]...)
	return a.aead.Seal(dst, nonce[:], p, nil)
}

// open decrypts nonce[12] | ciphertext.
func (a *aeadCounter) open(buf []byte) ([]byte, error) {
	return a.openAppend(nil, buf)
}

// openAppend decrypts nonce[12] | ciphertext, appending the plaintext to dst.
func (a *aeadCounter) openAppend(dst, buf []byte) ([]byte, error) {
	if len(buf) < gcmNonce+gcmTag {
		return nil, errors.New("direct: short packet")
	}
	return a.aead.Open(dst, buf[:gcmNonce], buf[gcmNonce:], nil)
}

// ---- handshake messages ----

func genEphemeral() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// initMaxSkew bounds how old (or how far in the future) an INIT timestamp may
// be. Together with the responder's memory of recently seen INIT keys this
// stops a captured INIT from being replayed later to reset the session.
const initMaxSkew = 120 * time.Second

const initLen = 1 + 8 + x25519Len + sha256.Size

func makeInit(token string, ephPub []byte, now time.Time) []byte {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(now.Unix()))
	b := make([]byte, 0, initLen)
	b = append(b, dirINIT)
	b = append(b, ts[:]...)
	b = append(b, ephPub...)
	b = append(b, dmac(token, []byte("pol-direct-init"), ts[:], ephPub)...)
	return b
}

func makeResp(token string, initPub, ephPub []byte) []byte {
	b := make([]byte, 0, 1+x25519Len+sha256.Size)
	b = append(b, dirRESP)
	b = append(b, ephPub...)
	b = append(b, dmac(token, []byte("pol-direct-resp"), initPub, ephPub)...)
	return b
}

var errBadHandshake = errors.New("direct: handshake authentication failed")

var errStaleInit = errors.New("direct: INIT timestamp outside the allowed window (replay or clock skew)")

// parseInit authenticates an INIT and checks its timestamp is within
// initMaxSkew of now. It returns the initiator's ephemeral public key.
func parseInit(token string, msg []byte, now time.Time) (ephPub []byte, err error) {
	if len(msg) != initLen || msg[0] != dirINIT {
		return nil, errBadHandshake
	}
	ts := msg[1:9]
	ephPub = msg[9 : 9+x25519Len]
	want := dmac(token, []byte("pol-direct-init"), ts, ephPub)
	if !hmac.Equal(msg[9+x25519Len:], want) {
		return nil, errBadHandshake
	}
	sent := time.Unix(int64(binary.BigEndian.Uint64(ts)), 0)
	if d := now.Sub(sent); d > initMaxSkew || d < -initMaxSkew {
		return nil, errStaleInit
	}
	return ephPub, nil
}

func parseResp(token string, initPub, msg []byte) (ephPub []byte, err error) {
	if len(msg) != 1+x25519Len+sha256.Size || msg[0] != dirRESP {
		return nil, errBadHandshake
	}
	ephPub = msg[1 : 1+x25519Len]
	want := dmac(token, []byte("pol-direct-resp"), initPub, ephPub)
	if !hmac.Equal(msg[1+x25519Len:], want) {
		return nil, errBadHandshake
	}
	return ephPub, nil
}

func sharedSecret(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	pk, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pk)
}
