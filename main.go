package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
)

const version = "0.1.0"

func main() {
	cfgPath := flag.String("c", "config.toml", "path to config file")
	genToken := flag.Bool("gen-token", false, "print a random 64-char token and exit")
	showVer := flag.Bool("version", false, "print version and exit")
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
