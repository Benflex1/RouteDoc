package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixtureCLI(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "reports", "v1", "valid-multibranch-no-global", "report.json")
	data, _ := os.ReadFile(path)
	var out, err bytes.Buffer
	if code := NewApp([]string{"validate", path}, strings.NewReader(""), &out, &err, nil).Run(); code != ExitOK || out.String() != "valid\n" {
		t.Fatalf("validate %d %q %q", code, out.String(), err.String())
	}
	out.Reset()
	err.Reset()
	if code := NewApp([]string{"render", path, "--json"}, strings.NewReader(""), &out, &err, func(string) ([]byte, error) { return data, nil }).Run(); code != ExitOK || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("render %d: %q %q", code, out.String(), err.String())
	}
}

func TestCompatibilityGoldens(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "reports", "v1")
	for _, name := range []string{"newer-minor-ignored-fields", "newer-patch-known-readonly"} {
		path := filepath.Join(root, name, "report.json")
		for _, tc := range []struct {
			args           []string
			stdout, stderr string
		}{
			{[]string{"render", path}, "render.txt", "render.stderr.txt"},
			{[]string{"validate", path}, "validate.txt", "validate.stderr.txt"},
		} {
			wantOut, err := os.ReadFile(filepath.Join(root, name, tc.stdout))
			if err != nil {
				t.Fatal(err)
			}
			wantErr, err := os.ReadFile(filepath.Join(root, name, tc.stderr))
			if err != nil {
				t.Fatal(err)
			}
			var out, stderr bytes.Buffer
			if code := NewApp(tc.args, strings.NewReader(""), &out, &stderr, nil).Run(); code != ExitOK || !bytes.Equal(out.Bytes(), wantOut) || !bytes.Equal(stderr.Bytes(), wantErr) {
				t.Fatalf("%s %v: code=%d stdout=%q stderr=%q", name, tc.args, code, out.Bytes(), stderr.Bytes())
			}
		}
	}
	for _, name := range []string{"newer-minor-ignored-fields", "newer-patch-known-readonly"} {
		path := filepath.Join(root, name, "report.json")
		var out, stderr bytes.Buffer
		if code := NewApp([]string{"validate", path, "--json"}, strings.NewReader(""), &out, &stderr, nil).Run(); code != ExitOK {
			t.Fatalf("%s validate json: %d %q", name, code, stderr.String())
		}
		want, err := os.ReadFile(filepath.Join(root, name, "validate.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), want) {
			t.Fatalf("%s validate JSON mismatch\nwant %q\ngot %q", name, want, out.Bytes())
		}
	}
}
