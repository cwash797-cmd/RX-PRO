package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configPath := flag.String("config", "", "private configuration file")
	version := flag.Bool("version", false, "show version")
	flag.Parse()
	if *version {
		fmt.Println("RX-PRO TrustTunnel HTTP2 adapter 0.1-test")
		return
	}
	f, err := os.Open(*configPath)
	if err != nil {
		log.Fatal("TrustTunnel configuration unavailable")
	}
	var cfg Config
	decoder := json.NewDecoder(io.LimitReader(f, 262144))
	err = decoder.Decode(&cfg)
	f.Close()
	if err != nil {
		log.Fatal("Invalid TrustTunnel configuration (details hidden)")
	}
	for _, dns := range cfg.DNSUpstreams {
		if _, err = dnsAddress(dns); err != nil {
			log.Fatal(err)
		}
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("SOCKS listener must be loopback")
	}
	client, err := newClient(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatal("TrustTunnel SOCKS port unavailable")
	}
	defer listener.Close()
	log.Print("TrustTunnel HTTP2 SOCKS listener ready")
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	go func() { <-done; listener.Close(); client.Close() }()
	slots := make(chan struct{}, 256)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); client.serve(conn) }()
		default:
			conn.Close()
		}
	}
}
