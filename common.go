package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ---- logging ----

var levels = map[string]int{"debug": 0, "info": 1, "warn": 2, "error": 3}
var logLevel atomic.Int32 // read from many goroutines; set at startup (and by tests)

func init() { logLevel.Store(1) }

func setLogLevel(l string) {
	if v, ok := levels[l]; ok {
		logLevel.Store(int32(v))
	}
}

func logf(level, format string, args ...any) {
	if int32(levels[level]) >= logLevel.Load() {
		log.Printf("[%s] %s", level, fmt.Sprintf(format, args...))
	}
}

// ---- piping ----

type closeWriter interface{ CloseWrite() error }

var bufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

// pipe copies both ways with proper half-close, then closes both ends.
func pipe(a, b io.ReadWriteCloser, st *Stat) {
	if st != nil {
		st.Active.Add(1)
		st.Total.Add(1)
		defer st.Active.Add(-1)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src io.ReadWriteCloser, counter *atomic.Int64) {
		defer wg.Done()
		bp := bufPool.Get().(*[]byte)
		defer bufPool.Put(bp)
		buf := *bp
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					src.Close()
					dst.Close()
					return
				}
				if counter != nil {
					counter.Add(int64(n))
				}
			}
			if err != nil {
				break
			}
		}
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
			src.Close()
		}
	}
	var in, out *atomic.Int64
	if st != nil {
		in, out = &st.BytesIn, &st.BytesOut
	}
	go cp(b, a, in)  // visitor -> tunnel
	go cp(a, b, out) // tunnel -> visitor
	wg.Wait()
	a.Close()
	b.Close()
}

// ---- stats / web panel ----

type Stat struct {
	Name     string
	BytesIn  atomic.Int64
	BytesOut atomic.Int64
	Active   atomic.Int64
	Total    atomic.Int64
}

type Stats struct {
	mu    sync.Mutex
	m     map[string]*Stat
	start time.Time
	Info  func() map[string]any
}

func NewStats() *Stats { return &Stats{m: map[string]*Stat{}, start: time.Now()} }

func (s *Stats) Get(name string) *Stat {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.m[name]
	if st == nil {
		st = &Stat{Name: name}
		s.m[name] = st
	}
	return st
}

type statJSON struct {
	Name     string `json:"name"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
	Active   int64  `json:"active"`
	Total    int64  `json:"total"`
}

func (s *Stats) snapshot() []statJSON {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]statJSON, 0, len(s.m))
	for _, st := range s.m {
		out = append(out, statJSON{st.Name, st.BytesIn.Load(), st.BytesOut.Load(), st.Active.Load(), st.Total.Load()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Serve exposes /stats (JSON) and / (auto-refreshing table) on 127.0.0.1:port.
func (s *Stats) Serve(port int) {
	if port <= 0 {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		ports := s.snapshot()
		var in, out, active int64
		for _, p := range ports {
			in, out, active = in+p.BytesIn, out+p.BytesOut, active+p.Active
		}
		// totals too, so a status line needs no JSON arithmetic
		body := map[string]any{"uptime_sec": int(time.Since(s.start).Seconds()), "ports": ports,
			"bytes_in": in, "bytes_out": out, "active": active}
		if s.Info != nil {
			for k, v := range s.Info() {
				body[k] = v
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><meta http-equiv="refresh" content="2"><title>pol</title>
<style>body{font:14px system-ui;margin:24px}td,th{padding:4px 12px;text-align:right}th:first-child,td:first-child{text-align:left}</style>`)
		fmt.Fprintf(w, "<h3>pol tunnel — up %s</h3>", time.Since(s.start).Round(time.Second))
		if s.Info != nil {
			for k, v := range s.Info() {
				fmt.Fprintf(w, "<div>%s: %v</div>", html.EscapeString(k), html.EscapeString(fmt.Sprint(v)))
			}
		}
		fmt.Fprint(w, "<table><tr><th>port</th><th>in</th><th>out</th><th>active</th><th>total</th></tr>")
		for _, st := range s.snapshot() {
			fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td></tr>",
				html.EscapeString(st.Name), human(st.BytesIn), human(st.BytesOut), st.Active, st.Total)
		}
		fmt.Fprint(w, "</table>")
	})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	logf("info", "web panel on http://%s", addr)
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			logf("error", "web panel: %v", err)
		}
	}()
}

func human(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for m := n / u; m >= u; m /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
