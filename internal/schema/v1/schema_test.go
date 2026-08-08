package v1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	// github.com/santhosh-tekuri/jsonschema/v6 is test-only: the Go standard
	// library has no Draft 2020-12 validator. v6.0.2 is Apache-2.0 and is
	// pinned in go.mod; production packages never import it.
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestSchemaContract(t *testing.T) {
	path := filepath.Join("..", "..", "..", "schema", "report", "v1.0.0", "schema.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err = json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("wrong draft: %v", doc["$schema"])
	}
	c := jsonschema.NewCompiler()
	s, err := c.Compile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(minimalSchemaInstance()); err != nil {
		t.Fatalf("minimal instance does not conform: %v", err)
	}
	checkSchemaAnnotations(t, doc, "#")
}

func checkSchemaAnnotations(t *testing.T, v interface{}, pointer string) {
	t.Helper()
	switch x := v.(type) {
	case map[string]interface{}:
		if typ, ok := x["type"].(string); ok && typ == "object" {
			if x["additionalProperties"] != false {
				t.Errorf("%s object is not closed", pointer)
			}
			if _, ok := x["x-routedoc-member-order"]; !ok {
				t.Errorf("%s missing member order", pointer)
			}
		}
		for k, vv := range x {
			if k == "$defs" || k == "properties" || k == "oneOf" || k == "anyOf" || k == "allOf" || k == "items" || k == "$ref" {
				checkSchemaAnnotations(t, vv, pointer+"/"+k)
			}
		}
	case []interface{}:
		for i, vv := range x {
			checkSchemaAnnotations(t, vv, pointer+"/"+itoa(i))
		}
	}
}
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	return string(rune('0' + i))
}

func minimalSchemaInstance() map[string]interface{} {
	return map[string]interface{}{"report_schema_version": "1.0.0", "producer": map[string]interface{}{"name": "routedoc", "version": "0.0.0", "build": "test"}, "run_id": "run-000001", "target": map[string]interface{}{"scheme": "https", "hostname": "example.test", "effective_port": 443, "path": map[string]interface{}{"present": true, "is_root": true, "segment_count": 0, "trailing_slash": false, "query_present": false}}, "goal": map[string]interface{}{"kind": "HTTP_RESPONSE"}, "requested_scope": map[string]interface{}{"kind": "CLIENT_ONLY"}, "policy": map[string]interface{}{"coherence_window_ns": 1}, "started_at": "2026-08-08T10:00:00Z", "finished_at": "2026-08-08T10:00:01Z", "vantage_points": []interface{}{}, "capabilities": []interface{}{}, "operator_assertions": []interface{}{}, "entities": []interface{}{}, "service_path": map[string]interface{}{"nodes": []interface{}{}, "edges": []interface{}{}, "branches": []interface{}{}}, "check_definitions": []interface{}{}, "check_executions": []interface{}{}, "observations": []interface{}{}, "visibility_assessments": []interface{}{}, "evaluation": map[string]interface{}{"evaluated_at": "2026-08-08T10:00:01Z", "ordered_rule_ids": []interface{}{}}, "claims": []interface{}{}, "findings": []interface{}{}, "limitations": []interface{}{}}
}
