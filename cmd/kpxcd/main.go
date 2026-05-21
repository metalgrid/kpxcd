//go:build linux

// kpxcd — KeePassXC headless daemon.
package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/metalgrid/kpxcd/internal/daemon"
)

func main() {
	configPath := flag.String("config", "", "Path to configuration file")
	verbose := flag.Bool("v", false, "Enable verbose (debug) logging")
	quiet := flag.Bool("q", false, "Only show warnings and errors")
	flag.Parse()

	// Determine log level from flags (overrides config file).
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	} else if *quiet {
		level = slog.LevelWarn
	}

	// Initialize logging early so daemon.Run can use slog.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})))

	if err := daemon.Run(*configPath, level); err != nil {
		slog.Error("daemon failed", "error", err)
		os.Exit(1)
	}
}
