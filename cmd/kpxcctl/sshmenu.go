//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// parseMenuSelection parses "1,3-5" / "a"|"all" into 0-based indices.
func parseMenuSelection(input string, count int) ([]int, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil
	}
	if strings.EqualFold(input, "a") || strings.EqualFold(input, "all") {
		out := make([]int, count)
		for i := range out {
			out[i] = i
		}
		return out, nil
	}
	var out []int
	for _, field := range strings.Split(input, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(field, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || a < 1 || b > count || a > b {
				return nil, fmt.Errorf("invalid range %q", field)
			}
			for i := a; i <= b; i++ {
				out = append(out, i-1)
			}
			continue
		}
		n, err := strconv.Atoi(field)
		if err != nil || n < 1 || n > count {
			return nil, fmt.Errorf("invalid selection %q (1..%d)", field, count)
		}
		out = append(out, n-1)
	}
	return out, nil
}

// selectFromMenu prints a numbered menu and reads a selection. Empty input
// selects nothing.
func selectFromMenu(in io.Reader, prompt string, items []string) ([]int, error) {
	for i, item := range items {
		fmt.Printf("  %d. %s\n", i+1, item)
	}
	fmt.Print(prompt)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return nil, err
	}
	return parseMenuSelection(line, len(items))
}

// scanSSHDir lists candidate private key files in dir (regular files only,
// non-recursive, <= 1 MiB).
func scanSSHDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Size() > 1<<20 {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}
	return files, nil
}

// needsPassphrase reports whether data is an encrypted private key,
// detected directly via ssh.ParseRawPrivateKey (our ParsePrivateKey returns
// a public-only key with a nil error for encrypted OpenSSH keys, which hid
// this before).
func needsPassphrase(data []byte) bool {
	_, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	return errors.As(err, &missing)
}

// writeExportFile writes a private key to outFile as a fresh 0600 file:
// without force it hard-links over the target and fails if it exists; with
// force it renames over it. Never O_TRUNC (would keep the old mode), never
// through a symlink.
func writeExportFile(outFile string, data []byte, force bool) error {
	if fi, err := os.Lstat(outFile); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write through a symlink")
	}
	dir := filepath.Dir(outFile)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(outFile)+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if force {
		return os.Rename(tmpName, outFile)
	}
	// Fail if the target appeared meanwhile (e.g. during the polkit prompt).
	if err := os.Link(tmpName, outFile); err != nil {
		return err
	}
	return nil
}
