package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
)

const version = "0.4.1"

func main() {
	cfgPath := flag.String("c", "config.toml", "path to config file")
	genToken := flag.Bool("gen-token", false, "print a random 64-char token and exit")
	showVer := flag.Bool("version", false, "print version and exit")
	checkCfg := flag.Bool("check", false, "check the config file (-c) and exit: 0 = valid")
	probeListen := flag.String("probe-listen", "", "link test: listen on this addr (run on one server)")
	probe := flag.String("probe", "", "link test: measure the path to this HOST:PORT (run on the other server)")
	spoofSrc := flag.String("spoof-src", "192.0.2.123", "forged source IP used by the -probe spoof test")
	connTest := flag.Bool("conntest", false, "connection test, Iran side: start every tunnel and print a link for the kharej")
	connTestHost := flag.String("conntest-host", "", "connection test: this server's public address for the link (auto-detected)")
	connTestDirect := flag.Bool("conntest-direct", true, "connection test: include the direct (L3) tunnel (root + Linux on both)")
	connTestSpoof := flag.Bool("conntest-spoof", true, "connection test: include the IP-spoofing check (root + Linux on both)")
	connTestJoin := flag.String("conntest-join", "", "connection test, kharej side: join the test with the link Iran printed")
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
	if *connTest {
		if err := runConnTestIran(*connTestHost, *connTestDirect, *connTestSpoof); err != nil {
			log.Fatalf("connection test: %v", err)
		}
		return
	}
	if *connTestJoin != "" {
		if err := runConnTestKharej(*connTestJoin); err != nil {
			log.Fatalf("connection test: %v", err)
		}
		return
	}

	log.SetFlags(log.LstdFlags)
	cfg, err := LoadConfig(*cfgPath)
	if *checkCfg {
		if err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(1)
		}
		fmt.Println("config ok")
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}

	errc := make(chan error, 2)
	if cfg.Server != nil {
		setLogLevel(cfg.Server.LogLevel)
		applyARQProfile(cfg.Server.Performance)
		srv, err := NewServer(cfg.Server)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(1)
		}
		go func() { errc <- srv.Run() }()
	}
	if cfg.Client != nil {
		setLogLevel(cfg.Client.LogLevel)
		applyARQProfile(cfg.Client.Performance)
		go func() { errc <- NewClient(cfg.Client).Run() }()
	}
	if cfg.Direct != nil {
		if cfg.Server == nil && cfg.Client == nil {
			setLogLevel(cfg.Direct.LogLevel)
		}
		go func() { errc <- RunDirect(cfg.Direct) }()
	}
	if err := <-errc; err != nil {
		log.Fatalf("fatal: %v", err)
	}
}
