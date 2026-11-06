package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
)

const version = "0.2.0"

func main() {
	cfgPath := flag.String("c", "config.toml", "path to config file")
	genToken := flag.Bool("gen-token", false, "print a random 64-char token and exit")
	showVer := flag.Bool("version", false, "print version and exit")
	probeListen := flag.String("probe-listen", "", "link test: listen on this addr (run on one server)")
	probe := flag.String("probe", "", "link test: measure the path to this HOST:PORT (run on the other server)")
	spoofSrc := flag.String("spoof-src", "192.0.2.123", "forged source IP used by the -probe spoof test")
	testAgent := flag.String("test-agent", "", "live tunnel test: run the agent on this addr (the tunnel-host server)")
	testRun := flag.String("test-run", "", "live tunnel test: run every tunnel against the agent at HOST:PORT (other server)")
	testKey := flag.String("test-key", "", "live tunnel test: the key printed by -test-agent (asked for if omitted)")
	flag.Parse()

	if *showVer {
		fmt.Println("pol", version)
		return
	}
	if *genToken {
		b := make([]byte, 32)
		rand.Read(b)
		fmt.Println(hex.EncodeToString(b))
		return
	}
	if *probeListen != "" {
		if err := runProbeListen(*probeListen); err != nil {
			log.Fatalf("probe-listen: %v", err)
		}
		return
	}
	if *probe != "" {
		if err := runProbe(*probe, *spoofSrc); err != nil {
			log.Fatalf("probe: %v", err)
		}
		return
	}
	if *testAgent != "" {
		if err := runTestAgent(*testAgent); err != nil {
			log.Fatalf("test-agent: %v", err)
		}
		return
	}
	if *testRun != "" {
		if err := runTestRun(*testRun, *testKey); err != nil {
			log.Fatalf("test-run: %v", err)
		}
		return
	}

	log.SetFlags(log.LstdFlags)
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}

	errc := make(chan error, 2)
	if cfg.Server != nil {
		setLogLevel(cfg.Server.LogLevel)
		srv, err := NewServer(cfg.Server)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(1)
		}
		go func() { errc <- srv.Run() }()
	}
	if cfg.Client != nil {
		setLogLevel(cfg.Client.LogLevel)
		go func() { errc <- NewClient(cfg.Client).Run() }()
	}
	if cfg.Direct != nil {
		go func() { errc <- RunDirect(cfg.Direct) }()
	}
	if err := <-errc; err != nil {
		log.Fatalf("fatal: %v", err)
	}
}
