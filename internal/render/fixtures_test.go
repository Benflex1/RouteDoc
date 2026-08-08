package render

import (
	"bytes"
	"os"
	"path/filepath"
	"routedoc/internal/model"
	"routedoc/internal/schema/v1"
	"testing"
)

func TestGoldenFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "reports", "v1")
	cases := []string{"valid-multibranch-no-global", "ipv4-success-ipv6-refused-partial", "tls-hostname-mismatch-http-skipped", "caddy-active-over-configured-intent", "upstream-refused-wrong-vantage", "listener-absent-complete-scope", "listener-absent-partial-scope", "two-proxy-upstreams-no-global", "operator-asserted-expected-path", "multiclaim-acyclic", "provenance-recoverable-stored", "reevaluation-replacement-before", "reevaluation-replacement-after", "path-summary-only", "sensitive-derived-only"}
	for _, name := range cases {
		data, err := os.ReadFile(filepath.Join(root, name, "report.json"))
		if err != nil {
			t.Fatal(err)
		}
		d, issues := v1.Decode(data, v1.ReadRender)
		if len(issues) != 0 {
			t.Fatalf("%s: %#v", name, issues)
		}
		v, issues := model.ValidatePersistedEvaluatedRun(d.Run)
		if len(issues) != 0 {
			t.Fatalf("%s: %#v", name, issues)
		}
		for _, tc := range []struct {
			file string
			opts Options
		}{{"concise.txt", Options{}}, {"verbose.txt", Options{Verbose: true}}} {
			want, _ := os.ReadFile(filepath.Join(root, name, tc.file))
			var got bytes.Buffer
			if err := Report(&got, v, tc.opts); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("%s %s mismatch\nwant %q\ngot %q", name, tc.file, want, got.Bytes())
			}
		}
	}
}

func TestExplanationGoldens(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "reports", "v1")
	for _, name := range []string{"valid-multibranch-no-global", "ipv4-success-ipv6-refused-partial", "tls-hostname-mismatch-http-skipped", "upstream-refused-wrong-vantage", "listener-absent-complete-scope", "two-proxy-upstreams-no-global"} {
		data, err := os.ReadFile(filepath.Join(root, name, "report.json"))
		if err != nil {
			t.Fatal(err)
		}
		d, issues := v1.Decode(data, v1.ReadExplain)
		if len(issues) != 0 {
			t.Fatalf("%s: %#v", name, issues)
		}
		valid, issues := model.ValidatePersistedEvaluatedRun(d.Run)
		if len(issues) != 0 {
			t.Fatalf("%s: %#v", name, issues)
		}
		want, err := os.ReadFile(filepath.Join(root, name, "explain-finding-000001.txt"))
		if err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		if err := Explain(&got, valid, "finding-000001", Options{}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("%s explanation mismatch\nwant %q\ngot %q", name, want, got.Bytes())
		}
	}
}
