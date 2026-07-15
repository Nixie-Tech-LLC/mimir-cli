package main

import (
	"reflect"
	"testing"
)

func TestNormMember(t *testing.T) {
	cases := map[string]string{
		"omar@onnixi.com":       "mimir:omar@onnixi.com",
		"mimir:omar@onnixi.com": "mimir:omar@onnixi.com", // already-prefixed isn't double-prefixed
		"  spaced@x.com  ":      "mimir:spaced@x.com",
	}
	for in, want := range cases {
		if got := normMember(in); got != want {
			t.Errorf("normMember(%q) = %q, want %q", in, got, want)
		}
	}
	if got := dispMember("mimir:omar@onnixi.com"); got != "omar@onnixi.com" {
		t.Errorf("dispMember round-trip = %q", got)
	}
}

func TestAddMembers(t *testing.T) {
	cur := []string{"mimir:a@x.com", "mimir:b@x.com"}
	// dedups against existing (raw + normalized) and against each other, preserves order, appends new.
	got := addMembers(cur, []string{"b@x.com", "mimir:b@x.com", "c@x.com", "c@x.com"})
	want := []string{"mimir:a@x.com", "mimir:b@x.com", "mimir:c@x.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("addMembers = %v, want %v", got, want)
	}
	// adding to an empty list normalizes and dedups.
	if got := addMembers(nil, []string{"z@x.com", "z@x.com"}); !reflect.DeepEqual(got, []string{"mimir:z@x.com"}) {
		t.Errorf("addMembers(nil,...) = %v", got)
	}
}

func TestRemoveMembers(t *testing.T) {
	cur := []string{"mimir:a@x.com", "mimir:b@x.com", "mimir:c@x.com"}
	// removal matches regardless of caller prefixing, preserves order of survivors.
	got := removeMembers(cur, []string{"b@x.com", "mimir:c@x.com"})
	want := []string{"mimir:a@x.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("removeMembers = %v, want %v", got, want)
	}
	// removing the last member yields an empty (non-nil) slice, so the merge patch clears the RoleBinding.
	got = removeMembers([]string{"mimir:a@x.com"}, []string{"a@x.com"})
	if len(got) != 0 {
		t.Errorf("removeMembers to empty = %v, want []", got)
	}
}
