//go:build linux

package main

import (
	"os"
	"testing"
)

func TestParseMenuSelection(t *testing.T) {
	cases := []struct {
		in    string
		count int
		want  []int
		fail  bool
	}{
		{"", 3, nil, false},
		{"a", 3, []int{0, 1, 2}, false},
		{"2", 3, []int{1}, false},
		{"1,3", 3, []int{0, 2}, false},
		{"1-3", 3, []int{0, 1, 2}, false},
		{"2-2", 3, []int{1}, false},
		{"4", 3, nil, true},
		{"0", 3, nil, true},
		{"1-9", 3, nil, true},
		{"x", 3, nil, true},
	}
	for _, c := range cases {
		got, err := parseMenuSelection(c.in, c.count)
		if c.fail {
			if err == nil {
				t.Errorf("parseMenuSelection(%q,%d): expected error, got %v", c.in, c.count, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseMenuSelection(%q,%d): unexpected error %v", c.in, c.count, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("parseMenuSelection(%q,%d) = %v, want %v", c.in, c.count, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseMenuSelection(%q,%d) = %v, want %v", c.in, c.count, got, c.want)
			}
		}
	}
}

func TestWriteExportFile(t *testing.T) {
	dir := t.TempDir()
	// fresh file is 0600
	p := dir + "/key"
	if err := writeExportFile(p, []byte("data")); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", fi.Mode().Perm())
	}
	// existing 0644 file is replaced with a 0600 file, not truncated in place
	p2 := dir + "/key2"
	os.WriteFile(p2, []byte("old"), 0o644)
	if err := writeExportFile(p2, []byte("new")); err != nil {
		t.Fatal(err)
	}
	fi2, _ := os.Stat(p2)
	if fi2.Mode().Perm() != 0o600 {
		t.Errorf("after overwrite mode = %o, want 0600", fi2.Mode().Perm())
	}
	b, _ := os.ReadFile(p2)
	if string(b) != "new" {
		t.Errorf("content = %q, want new", b)
	}
	// symlink target is refused
	real := dir + "/real"
	os.WriteFile(real, []byte("x"), 0o600)
	link := dir + "/link"
	os.Symlink(real, link)
	if err := writeExportFile(link, []byte("evil")); err == nil {
		t.Error("expected symlink refusal")
	}
}
