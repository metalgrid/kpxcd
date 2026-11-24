//go:build linux

package main

import (
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
