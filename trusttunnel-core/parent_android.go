package main

import (
	"os"
	"time"
)

func init() {
	parent := os.Getppid()
	if parent <= 1 {
		os.Exit(1)
	}
	go func() {
		for range time.Tick(time.Second) {
			if os.Getppid() != parent {
				os.Exit(0)
			}
		}
	}()
}
