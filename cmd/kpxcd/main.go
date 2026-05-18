//go:build linux

// kpxcd — KeePassXC headless daemon.
package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/user/kpxcd/internal/daemon"
)

func main() {
	configPath := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	// Initialize logging early so daemon.Run can use slog.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	if err := daemon.Run(*configPath); err != nil {
		slog.Error("daemon failed", "error", err)
		os.Exit(1)
	}
}
