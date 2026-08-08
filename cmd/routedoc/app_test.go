package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIExactCommandBoundary(t *testing.T) {
	for _, args := range [][]string{{"https://example.test"}, {"diagnose", "https://example.test"}, {"render"}, {"version", "--bad"}} {
		var out, err bytes.Buffer
		code := NewApp(args, strings.NewReader("stdin"), &out, &err, nil).Run()
		if code != ExitUsage {
			t.Fatalf("%v returned %d", args, code)
		}
	}
}
func TestCLIVersionJSON(t *testing.T) {
	var out, err bytes.Buffer
	code := NewApp([]string{"version", "--json"}, strings.NewReader(""), &out, &err, nil).Run()
	if code != ExitOK || !strings.Contains(out.String(), `"name":"routedoc"`) {
		t.Fatalf("%d %q %q", code, out.String(), err.String())
	}
}
