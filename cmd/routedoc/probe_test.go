package main

import (
	"os"
	"strings"
	"testing"
)

func TestMilestone1DocumentationNamesSafeProbeBoundary(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, phrase := range []string{"routedoc URL", "redirect", "proxy", "exit status"} {
		if !strings.Contains(strings.ToLower(text), strings.ToLower(phrase)) {
			t.Fatalf("README is missing %q", phrase)
		}
	}
}
