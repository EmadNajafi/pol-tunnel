package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// The engines a connection test starts are separate pol processes. Under
// `go test` that binary is the test binary, so it runs main() when asked to.
func TestMain(m *testing.M) {
	if os.Getenv("POL_CT_ENGINE") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

func TestCTLinkRoundTrip(t *testing.T) {
	for _, host := range []string{"203.0.113.7", "iran.example.com", "2001:db8::5"} {
		l := ctLink{Host: host, Port: 23456, Secret: bytes.Repeat([]byte{7}, ctSecretLen)}
		pasted := "here it is: " + l.String() + " (copy all)"
		got, err := parseCTLink(pasted)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if got.Host != host || got.Port != l.Port || !bytes.Equal(got.Secret, l.Secret) {
			t.Errorf("%s: round trip gave %+v", host, got)
		}
	}
	if _, err := parseCTLink("pol://t.AAAA"); err == nil {
		t.Error("cut-short link accepted")
	}
	if _, err := parseCTLink("hello"); err == nil {
		t.Error("non-link accepted")
	}
}

func TestCTCoordinatorRejectsWrongSecret(t *testing.T) {
	ctJoinWait, ctStartGrace = 5*time.Second, 100*time.Millisecond
	s, err := startCTIran(ctIranOptions{Host: "127.0.0.1", Reverse: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	bad := s.link
	bad.Secret = bytes.Repeat([]byte{1}, ctSecretLen)
	if _, err := ctAsk(context.Background(), bad, "CONFIG"); err == nil {
		t.Error("coordinator answered a wrong secret")
	}
	if ans, err := ctAsk(context.Background(), s.link, "CONFIG"); err != nil || !strings.HasPrefix(ans, "{") {
		t.Errorf("coordinator did not answer the right secret: %q %v", ans, err)
	}
}

func TestCTBest(t *testing.T) {
	cases := []*ctCase{{Kind: "reverse", Tr: "tcp"}, {Kind: "reverse", Tr: "tcpmux"}, {Kind: "reverse", Tr: "ws"}}
	for _, c := range cases {
		for i := 0; i < 10; i++ {
			c.rtts = append(c.rtts, time.Duration(90+i)*time.Millisecond)
		}
	}
	rows := []ctResult{
		{Kind: "reverse", Transport: "tcp", Status: ctOK, OK: 10, Tried: 10, Down: 40, Up: 30},
		{Kind: "reverse", Transport: "tcpmux", Status: ctOK, OK: 10, Tried: 10, Down: 80, Up: 60},
		{Kind: "reverse", Transport: "ws", Status: ctUnstable, OK: 4, Tried: 10},
	}
	b := ctComputeBest(rows, cases)
	if b.Transport != "tcpmux" {
		t.Errorf("best = %q, want the fastest steady one (tcpmux)", b.Transport)
	}
	if b.LossPct != 0 || b.RTTms < 90 || b.MuxWindowKB < 512 {
		t.Errorf("unexpected settings %+v", b)
	}
	out := ctVerdict(rows) + ctBestTable(b)
	for _, want := range []string{"Works steadily", "TCP MUX", "UNSTABLE", "BEST SETTINGS", `"tcpmux"`} {
		if !strings.Contains(out, want) {
			t.Errorf("verdict lacks %q:\n%s", want, out)
		}
	}
}

// The whole test on one machine: Iran and kharej sides, real engines for every
// reverse transport, short timers.
func TestConnectionTestLocal(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real engines")
	}
	t.Setenv("POL_CT_ENGINE", "1")
	ctJoinWait, ctConnectWait, ctSoak = 30*time.Second, 20*time.Second, 4
	ctSpeedWarm, ctSpeedDur, ctPollEvery, ctStartGrace = 300*time.Millisecond, 700*time.Millisecond, 300*time.Millisecond, 1500*time.Millisecond

	s, err := startCTIran(ctIranOptions{Host: "127.0.0.1", Direct: false, Spoof: false})
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	type kres struct {
		rows []ctResult
		best *ctBest
		err  error
	}
	kdone := make(chan kres, 1)
	var kout bytes.Buffer
	go func() {
		r, b, err := ctKharejRun(ctx, s.link, newCTBoard(&kout, "kharej"))
		kdone <- kres{r, b, err}
	}()
	var iout bytes.Buffer
	board := newCTBoard(&iout, "iran")
	rows := s.run(ctx, board.set)
	board.finish(rows, s.best)
	k := <-kdone
	if k.err != nil {
		t.Fatalf("kharej: %v\n%s", k.err, kout.String())
	}
	t.Log("\n" + iout.String())

	for _, r := range rows {
		switch r.Kind {
		case "reverse":
			if r.Status != ctOK {
				t.Errorf("%s: %s (%s)", r.Transport, r.Status, r.Detail)
			}
			if r.Status == ctOK && (r.Down <= 0 || r.Up <= 0) {
				t.Errorf("%s: no speed measured (%s)", r.Transport, r.Detail)
			}
		default:
			if r.Status != ctSkipped {
				t.Errorf("%s %s: %s, want skipped (not selected)", r.Kind, r.Transport, r.Status)
			}
		}
	}
	if s.best == nil || s.best.Transport == "" {
		t.Errorf("no recommendation: %+v", s.best)
	}
	if len(k.rows) != len(rows) || k.best == nil || k.best.Transport != s.best.Transport {
		t.Errorf("the kharej got a different verdict: %+v", k.best)
	}
	if !strings.Contains(kout.String(), "BEST SETTINGS") {
		t.Errorf("the kharej did not print the verdict:\n%s", kout.String())
	}
	// nothing left behind
	if _, err := os.Stat(s.dir); err == nil {
		s.close()
		if _, err := os.Stat(s.dir); err == nil {
			t.Error("temp dir left behind")
		}
	}
	fmt.Fprint(os.Stderr, "")
}
