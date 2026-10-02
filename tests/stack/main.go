package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	log.SetOutput(io.Discard)
	backend := flag.String("backend", "", "Existing numeric-loopback backend HTTP URL")
	flag.Parse()
	stack, err := newTopology(*backend)
	if err != nil {
		os.Exit(1)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	if json.NewEncoder(os.Stdout).Encode(stack.ready) != nil {
		stack.Close()
		os.Exit(1)
	}
	<-signals
	signal.Stop(signals)
	stack.Close()
}
