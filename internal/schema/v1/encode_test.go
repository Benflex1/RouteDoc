package v1

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"routedoc/internal/model"
)

func TestCanonicalEncode(t *testing.T) {
	b, err := jsonBytes(minimalSchemaInstance())
	if err != nil {
		t.Fatal(err)
	}
	d, issues := Decode(b, ReadValidate)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	v, issues := model.CanonicalizeAndValidateEvaluatedRun(d.Run)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	got, issues := EncodeCanonical(v)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if len(got) == 0 || got[len(got)-1] != '\n' || bytes.Contains(got[:len(got)-1], []byte(" \n")) {
		t.Fatalf("not compact/trailing LF: %q", got)
	}
	if !strings.HasPrefix(string(got), `{"report_schema_version"`) {
		t.Fatalf("wrong member order: %q", got[:min(40, len(got))])
	}
}
func TestCanonicalEncodeStable(t *testing.T) {
	b, _ := jsonBytes(minimalSchemaInstance())
	d, _ := Decode(b, ReadValidate)
	v, issues := model.CanonicalizeAndValidateEvaluatedRun(d.Run)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	a, _ := EncodeCanonical(v)
	c, _ := EncodeCanonical(v)
	if !bytes.Equal(a, c) {
		t.Fatal("non-deterministic bytes")
	}
}
func jsonBytes(v map[string]interface{}) ([]byte, error) { return json.Marshal(v) }
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
