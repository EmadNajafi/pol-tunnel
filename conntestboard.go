package main

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
)

// The Connection Test's table, drawn while the test runs. Each tunnel is one
// row: STATUS reads TESTING while echoes go out, ECHOES counts them and the bar
// fills with them (progress from the test itself, not an animation). On a
// terminal the table is redrawn in place; otherwise a row is printed only when
// its status changes. When the test ends the table is set out once more as the
// verdict — grouped OK, UNSTABLE, DOWN, SKIPPED, each bar filled by the echoes
// that came back — followed by the tunnels that carried everything, with their
// round trip and speed, the notes, and the best settings.

const ctBarSegments = 8

var ctNames = map[string]string{
	"tcp": "TCP", "tcpmux": "TCP MUX", "ws": "WS", "wsmux": "WS MUX", "wss": "WSS", "wssmux": "WSS MUX",
	"spoof": "SPOOF (UDP)", "spoofmux": "SPOOF MUX",
	"udp": "L3 / UDP", "pck": "L3 / TCP (pck)", "sni": "L3 / TCP (sni)", "icmp": "L3 / ICMP",
	"iran→kharej": "Iran→Kharej", "kharej→iran": "Kharej→Iran",
}

func ctName(tr string) string {
	if n, ok := ctNames[tr]; ok {
		return n
	}
	return strings.ToUpper(tr)
}

func ctKind(k string) string {
	switch k {
	case "spoof":
		return "IP Spoof"
	case "":
		return ""
	}
	return strings.ToUpper(k[:1]) + k[1:]
}

func ctBar(share float64) string {
	share = math.Max(0, math.Min(1, share))
	filled := int(math.Round(share * ctBarSegments))
	return fmt.Sprintf("%s%s %3d%%", strings.Repeat("▰", filled), strings.Repeat("▱", ctBarSegments-filled), int(math.Round(share*100)))
}

func ctMark(status string) string {
	switch status {
	case ctOK:
		return "🟢"
	case ctDown:
		return "🔴"
	case ctSkipped, ctWaiting:
		return "⚪"
	default:
		return "🟡"
	}
}

func ctStatusLabel(r ctResult) string {
	switch r.Phase {
	case "speed":
		return "SPEED"
	case "queued":
		return "QUEUED"
	}
	return strings.ToUpper(r.Status)
}

// every mark takes two columns; the rest of the RESULT column is spaces
const ctRowFormat = "%s       %-9s %-14s %-9s %-7s %s"

var ctHeader = fmt.Sprintf("%-8s %-9s %-14s %-9s %-7s %s", "RESULT", "KIND", "NAME", "STATUS", "ECHOES", "PROGRESS")

func ctRow(r ctResult) string {
	total := r.Total
	if total <= 0 {
		total = 1
	}
	done := r.OK
	if r.Status == ctTesting {
		done = r.Tried
	}
	echoes, bar := fmt.Sprintf("%d/%d", done, total), ctBar(float64(done)/float64(total))
	if r.Status == ctSkipped || r.Status == ctWaiting {
		echoes, bar = "-", ""
	}
	return fmt.Sprintf(ctRowFormat, ctMark(r.Status), ctKind(r.Kind), ctName(r.Transport), ctStatusLabel(r), echoes, bar)
}

func ctRule() string { return strings.Repeat("─", 64) }

func ctGroups(rows []ctResult) [][]ctResult {
	order := []string{ctOK, ctUnstable, ctDown, ctSkipped}
	var out [][]ctResult
	for _, st := range order {
		var g []ctResult
		for _, r := range rows {
			if r.Status == st {
				g = append(g, r)
			}
		}
		if len(g) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// ctVerdict is the final table as text.
func ctVerdict(rows []ctResult) string {
	var b strings.Builder
	b.WriteString(ctHeader + "\n")
	for _, g := range ctGroups(rows) {
		b.WriteString("\n")
		for _, r := range g {
			b.WriteString(ctRow(r) + "\n")
		}
	}
	b.WriteString("\n" + ctRule() + "\n\nWorks steadily:\n\n")
	steady := 0
	for _, r := range rows {
		if r.Status != ctOK {
			continue
		}
		steady++
		rtt, speed := "-", "-"
		if r.Kind != "spoof" {
			if r.RTTms > 0 {
				rtt = fmt.Sprintf("%dms", r.RTTms)
			} else {
				rtt = "<1ms"
			}
		}
		if r.Down > 0 || r.Up > 0 {
			speed = fmt.Sprintf("↓ %.1f / ↑ %.1f Mbps (%d streams)", r.Down, r.Up, ctSpeedStreams)
		}
		fmt.Fprintf(&b, "%s %-24s %-7s %s\n", ctMark(ctOK), ctKind(r.Kind)+" "+ctName(r.Transport), rtt, speed)
	}
	if steady == 0 {
		b.WriteString("Nothing carried traffic steadily between these two servers. See the notes\n" +
			"for setup errors; otherwise the path itself is blocking these tunnels.\n")
	}
	var notes []string
	for _, r := range rows {
		if r.Detail != "" {
			notes = append(notes, fmt.Sprintf("%s %s %s: %s", ctMark(r.Status), ctKind(r.Kind), ctName(r.Transport), r.Detail))
		}
	}
	if len(notes) > 0 {
		b.WriteString("\nNotes:\n\n" + strings.Join(notes, "\n") + "\n")
	}
	return b.String()
}

// ctBestTable is the recommendation, as the second table.
func ctBestTable(b *ctBest) string {
	if b == nil {
		return ""
	}
	var s strings.Builder
	row := func(setting, value, measured string) { fmt.Fprintf(&s, "%-16s %-22s %s\n", setting, value, measured) }
	s.WriteString("BEST SETTINGS\n" + ctRule() + "\n\n")
	row("SETTING", "VALUE", "MEASURED")
	s.WriteString("\n")
	link := fmt.Sprintf("%dms ±%dms, %.1f%% loss", b.RTTms, b.JitterMs, b.LossPct)
	if b.Transport != "" {
		row("transport", ctTransportSetting(b), fmt.Sprintf("↓ %.1f / ↑ %.1f Mbps, %s", b.Down, b.Up, link))
	} else {
		row("transport", "-", "nothing carried traffic steadily")
	}
	// one profile instead of a raw window: the smallest whose per-stream mux
	// window covers what the path needs (throughput is never suggested here —
	// it trades latency for bulk speed, which is the operator's call)
	switch {
	case b.MuxWindowKB > 16384: // more than turbo's windows grow to
		row("performance", `"aggressive"`, fmt.Sprintf("%d KB in flight (speed × round trip); uses more RAM", b.BDPKB))
	case b.MuxWindowKB > 4096: // more than balance's windows grow to
		row("performance", `"turbo"`, fmt.Sprintf("%d KB in flight (speed × round trip)", b.BDPKB))
	case b.Down > 0 || b.Up > 0:
		row("performance", `"balance"`, "its windows grow far enough for this path by themselves")
	default:
		row("performance", `"balance"`, "no speed measured")
	}
	row("heartbeat", fmt.Sprint(b.Heartbeat), fmt.Sprintf("worst round trip %dms ±%dms", b.WorstMs, b.JitterMs))
	row("keepalive_period", fmt.Sprint(b.KeepaliveSeconds), fmt.Sprintf("%.1f%% loss", b.LossPct))
	row("encryption", "true", "recommended unless the transport is wss/wssmux")
	s.WriteString("\n" + ctRule() + "\n")
	return s.String()
}

func ctTransportSetting(b *ctBest) string {
	if b.Kind == "direct" {
		return fmt.Sprintf("[direct] mode, carrier %q", b.Transport)
	}
	return fmt.Sprintf("%q", b.Transport)
}

// ---- the live board ----

type ctBoard struct {
	out   io.Writer
	title string
	tty   bool

	mu    sync.Mutex
	drawn int      // lines drawn last time (tty)
	last  []string // last status per row (non-tty)
	done  bool
}

func newCTBoard(out io.Writer, title string) *ctBoard {
	return &ctBoard{out: out, title: title, tty: ctIsTerminal(out)}
}

func ctIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0 && os.Getenv("TERM") != "dumb"
}

func ctBold(s string) string {
	if !ctIsTerminal(os.Stdout) {
		return s
	}
	return "\x1b[1m" + s + "\x1b[0m"
}

// set redraws the table with rows.
func (b *ctBoard) set(rows []ctResult) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.done || len(rows) == 0 {
		return
	}
	if !b.tty {
		if b.last == nil {
			fmt.Fprintf(b.out, "%s\n%s\n", b.title, ctHeader)
			b.last = make([]string, len(rows))
		}
		for i, r := range rows {
			key := ctStatusLabel(r)
			if i < len(b.last) && b.last[i] != key {
				b.last[i] = key
				fmt.Fprintln(b.out, ctRow(r))
			}
		}
		return
	}
	lines := []string{ctBold("Connection Test — " + b.title), ctRule(), ctHeader, ""}
	for _, r := range rows {
		lines = append(lines, ctRow(r))
	}
	lines = append(lines, ctRule())
	var s strings.Builder
	if b.drawn > 0 {
		fmt.Fprintf(&s, "\x1b[%dA", b.drawn)
	}
	for _, l := range lines {
		s.WriteString("\r\x1b[2K" + l + "\n")
	}
	io.WriteString(b.out, s.String())
	b.drawn = len(lines)
}

// finish prints the verdict and the best settings.
func (b *ctBoard) finish(rows []ctResult, best *ctBest) {
	b.mu.Lock()
	b.done = true
	b.mu.Unlock()
	fmt.Fprintln(b.out)
	fmt.Fprintln(b.out, ctBold("VERDICT — "+b.title))
	fmt.Fprintln(b.out, ctRule())
	fmt.Fprint(b.out, ctVerdict(rows))
	fmt.Fprintln(b.out)
	fmt.Fprint(b.out, ctBestTable(best))
}

// abandon stops drawing (the test ended without a verdict).
func (b *ctBoard) abandon() {
	b.mu.Lock()
	b.done = true
	b.mu.Unlock()
}
