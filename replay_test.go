package main

import (
	"math/rand/v2"
	"testing"
)

func TestReplayWindow(t *testing.T) {
	var w replayWindow
	// 0 always rejected
	if w.check(0) {
		t.Fatal("0 accepted")
	}
	// strictly increasing: all accepted
	for i := uint64(1); i <= 5000; i++ {
		if !w.check(i) {
			t.Fatalf("fresh %d rejected", i)
		}
	}
	// every one of those is now a replay
	for i := uint64(1); i <= 5000; i++ {
		if w.check(i) {
			t.Fatalf("replay %d accepted", i)
		}
	}
	// in-window reorder: a gap then fill it
	w = replayWindow{}
	w.check(100)
	if !w.check(50) { // within 1024 of 100, unseen
		t.Fatal("in-window reorder rejected")
	}
	if w.check(50) { // now a replay
		t.Fatal("reorder replay accepted")
	}
	if !w.check(90) || w.check(90) {
		t.Fatal("90 handling wrong")
	}
	// too old (beyond the window) rejected
	w = replayWindow{}
	w.check(5000)
	if w.check(5000 - replayBits) {
		t.Fatal("too-old accepted")
	}
	if !w.check(5000 - replayBits + 1) {
		t.Fatal("edge-of-window rejected")
	}
	// randomized: no accepted value ever accepted twice
	w = replayWindow{}
	seen := map[uint64]bool{}
	seq := uint64(1)
	rnd := rand.New(rand.NewPCG(7, 11))
	for i := 0; i < 200000; i++ {
		// jump forward sometimes, sometimes revisit a recent one
		if rnd.IntN(4) == 0 && seq > 10 {
			s := seq - uint64(rnd.IntN(10))
			ok := w.check(s)
			if ok && seen[s] {
				t.Fatalf("double-accept %d", s)
			}
			if ok {
				seen[s] = true
			}
		} else {
			seq += 1 + uint64(rnd.IntN(3))
			if !w.check(seq) {
				t.Fatalf("fresh advancing %d rejected", seq)
			}
			seen[seq] = true
		}
	}
}
