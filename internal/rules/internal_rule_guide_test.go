package rules

import (
	"os"
	"strings"
	"testing"
)

func TestInternalRuleGuideContract(t *testing.T) {
	data, err := os.ReadFile("../../docs/internal-rules.md")
	if err != nil {
		t.Fatal(err)
	}
	guide := string(data)
	for _, required := range []string{
		"tls.certificate_hostname_mismatch/v1",
		"tcp.connection_refused/v1",
		"listener.no_matching_listener_visible/v1",
		"base evidence only",
		"candidate key",
		"same-rule",
		"vantage",
		"this is not a plugin API",
	} {
		if !strings.Contains(guide, required) {
			t.Fatalf("guide is missing %q", required)
		}
	}
}
