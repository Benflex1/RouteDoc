package v1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestClosedUnionSchemaCases(t *testing.T) {
	path := filepath.Join("..", "..", "..", "schema", "report", "v1.0.0", "schema.json")
	c := jsonschema.NewCompiler()
	schema, err := c.Compile(path)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		valid     func() map[string]interface{}
		mutations []func(map[string]interface{})
	}{
		{name: "entity identity", valid: func() map[string]interface{} {
			r := minimalSchemaInstance()
			r["entities"] = []interface{}{map[string]interface{}{"entity_id": "entity-hostname", "kind": "HOSTNAME", "display_label": "hostname", "identity": map[string]interface{}{"kind": "HOSTNAME", "hostname": "example.test"}}}
			return r
		}, mutations: []func(map[string]interface{}){
			func(r map[string]interface{}) {
				delete(r["entities"].([]interface{})[0].(map[string]interface{})["identity"].(map[string]interface{}), "hostname")
			},
			func(r map[string]interface{}) {
				r["entities"].([]interface{})[0].(map[string]interface{})["identity"].(map[string]interface{})["synthetic_id"] = "proxy-1"
			},
			func(r map[string]interface{}) {
				r["entities"].([]interface{})[0].(map[string]interface{})["identity"].(map[string]interface{})["kind"] = "UNKNOWN"
			},
		}},
		{name: "observation payload", valid: func() map[string]interface{} {
			r := minimalSchemaInstance()
			r["observations"] = []interface{}{map[string]interface{}{"observation_id": "observation-000001", "kind": "TCP_CONNECTION_RESULT", "subject_entity_ids": []interface{}{}, "observed_at": "2026-08-08T10:00:00Z", "payload": map[string]interface{}{"kind": "TCP_CONNECTION_RESULT", "endpoint_entity_id": "entity-endpoint", "result": "ACCEPTED", "duration_ns": 1, "deadline_part_of_expected_condition": false}, "acquisition_method": "SYNTHETIC_FIXTURE", "source_component": "SYNTHETIC_FIXTURE", "sensitivity": "SANITIZED_DERIVED", "limitations": []interface{}{}}}
			return r
		}, mutations: []func(map[string]interface{}){
			func(r map[string]interface{}) {
				delete(r["observations"].([]interface{})[0].(map[string]interface{})["payload"].(map[string]interface{}), "endpoint_entity_id")
			},
			func(r map[string]interface{}) {
				r["observations"].([]interface{})[0].(map[string]interface{})["payload"].(map[string]interface{})["peer_entity_id"] = "entity-peer"
			},
			func(r map[string]interface{}) {
				r["observations"].([]interface{})[0].(map[string]interface{})["payload"].(map[string]interface{})["kind"] = "UNKNOWN"
			},
		}},
		{name: "claim parameters", valid: func() map[string]interface{} {
			r := minimalSchemaInstance()
			r["claims"] = []interface{}{map[string]interface{}{"claim_id": "claim-000001", "statement_code": "TCP_CONNECTION_REFUSED", "level": "INFERRED", "subject_entity_ids": []interface{}{}, "branch_ids": []interface{}{}, "parameters": map[string]interface{}{"kind": "TCP_CONNECTION_REFUSED", "endpoint_entity_id": "entity-endpoint", "vantage_id": "vantage-000001", "observed_at": "2026-08-08T10:00:00Z"}, "supporting_evidence": []interface{}{}, "contradicting_evidence": []interface{}{}, "required_missing_evidence": []interface{}{}, "rule_id": "tcp.connection_refused/v1"}}
			return r
		}, mutations: []func(map[string]interface{}){
			func(r map[string]interface{}) {
				delete(r["claims"].([]interface{})[0].(map[string]interface{})["parameters"].(map[string]interface{}), "endpoint_entity_id")
			},
			func(r map[string]interface{}) {
				r["claims"].([]interface{})[0].(map[string]interface{})["parameters"].(map[string]interface{})["hostname"] = "example.test"
			},
			func(r map[string]interface{}) {
				r["claims"].([]interface{})[0].(map[string]interface{})["parameters"].(map[string]interface{})["kind"] = "UNKNOWN"
			},
		}},
		{name: "vantage identity", valid: func() map[string]interface{} {
			r := minimalSchemaInstance()
			r["vantage_points"] = []interface{}{map[string]interface{}{"vantage_id": "vantage-000001", "kind": "HOST_NAMESPACE", "role": "ORIGIN_HOST", "display_label": "host", "identity": map[string]interface{}{"kind": "HOST_NAMESPACE", "namespace_inode": 7}, "establishment": "DIRECTLY_OBSERVED", "limitations": []interface{}{}}}
			return r
		}, mutations: []func(map[string]interface{}){
			func(r map[string]interface{}) {
				delete(r["vantage_points"].([]interface{})[0].(map[string]interface{})["identity"].(map[string]interface{}), "namespace_inode")
			},
			func(r map[string]interface{}) {
				r["vantage_points"].([]interface{})[0].(map[string]interface{})["identity"].(map[string]interface{})["label"] = "host"
			},
			func(r map[string]interface{}) {
				r["vantage_points"].([]interface{})[0].(map[string]interface{})["identity"].(map[string]interface{})["kind"] = "UNKNOWN"
			},
		}},
		{name: "assertion parameters", valid: func() map[string]interface{} {
			r := minimalSchemaInstance()
			r["operator_assertions"] = []interface{}{map[string]interface{}{"assertion_id": "assertion-000001", "kind": "EXPECTED_PATH_EDGE", "parameters": map[string]interface{}{"kind": "EXPECTED_PATH_EDGE", "from_entity_id": "entity-a", "to_entity_id": "entity-b", "relation": "ROUTES_TO"}, "established_at": "2026-08-08T10:00:00Z", "source": "SYNTHETIC_FIXTURE"}}
			return r
		}, mutations: []func(map[string]interface{}){
			func(r map[string]interface{}) {
				delete(r["operator_assertions"].([]interface{})[0].(map[string]interface{})["parameters"].(map[string]interface{}), "from_entity_id")
			},
			func(r map[string]interface{}) {
				r["operator_assertions"].([]interface{})[0].(map[string]interface{})["parameters"].(map[string]interface{})["status_min"] = 200
			},
			func(r map[string]interface{}) {
				r["operator_assertions"].([]interface{})[0].(map[string]interface{})["parameters"].(map[string]interface{})["kind"] = "UNKNOWN"
			},
		}},
		{name: "missing evidence", valid: func() map[string]interface{} {
			r := minimalSchemaInstance()
			r["claims"] = []interface{}{map[string]interface{}{"claim_id": "claim-000001", "statement_code": "TCP_CONNECTION_REFUSED", "level": "INFERRED", "subject_entity_ids": []interface{}{}, "branch_ids": []interface{}{}, "parameters": map[string]interface{}{"kind": "TCP_CONNECTION_REFUSED", "endpoint_entity_id": "entity-endpoint", "vantage_id": "vantage-000001", "observed_at": "2026-08-08T10:00:00Z"}, "supporting_evidence": []interface{}{}, "contradicting_evidence": []interface{}{}, "required_missing_evidence": []interface{}{map[string]interface{}{"kind": "OBSERVATION_REQUIRED", "observation_kind": "TCP_CONNECTION_RESULT"}}, "rule_id": "tcp.connection_refused/v1"}}
			return r
		}, mutations: []func(map[string]interface{}){
			func(r map[string]interface{}) {
				delete(r["claims"].([]interface{})[0].(map[string]interface{})["required_missing_evidence"].([]interface{})[0].(map[string]interface{}), "observation_kind")
			},
			func(r map[string]interface{}) {
				r["claims"].([]interface{})[0].(map[string]interface{})["required_missing_evidence"].([]interface{})[0].(map[string]interface{})["vantage_id"] = "vantage-000001"
			},
			func(r map[string]interface{}) {
				r["claims"].([]interface{})[0].(map[string]interface{})["required_missing_evidence"].([]interface{})[0].(map[string]interface{})["kind"] = "UNKNOWN"
			},
		}},
		{name: "check inputs", valid: func() map[string]interface{} {
			r := minimalSchemaInstance()
			r["check_definitions"] = []interface{}{map[string]interface{}{"check_id": "check-000001", "kind": "TCP_CONNECTION", "version": "1.0.0", "inputs": map[string]interface{}{"kind": "SUBJECT", "subject_entity_id": "entity-endpoint"}, "dependency_check_ids": []interface{}{}, "required_capability_ids": []interface{}{}, "execution_policy": map[string]interface{}{"deadline_ns": 1, "dependency_failure_reason_code": "", "deadline_is_expected_condition": false}, "expected_condition": map[string]interface{}{"kind": "RESULT", "result": "REFUSED"}}}
			return r
		}, mutations: []func(map[string]interface{}){
			func(r map[string]interface{}) {
				delete(r["check_definitions"].([]interface{})[0].(map[string]interface{})["inputs"].(map[string]interface{}), "subject_entity_id")
			},
			func(r map[string]interface{}) {
				r["check_definitions"].([]interface{})[0].(map[string]interface{})["inputs"].(map[string]interface{})["vantage_id"] = "vantage-000001"
			},
			func(r map[string]interface{}) {
				r["check_definitions"].([]interface{})[0].(map[string]interface{})["inputs"].(map[string]interface{})["kind"] = "UNKNOWN"
			},
		}},
		{name: "expected condition", valid: func() map[string]interface{} {
			r := minimalSchemaInstance()
			r["check_definitions"] = []interface{}{map[string]interface{}{"check_id": "check-000001", "kind": "TCP_CONNECTION", "version": "1.0.0", "inputs": map[string]interface{}{"kind": "SUBJECT", "subject_entity_id": "entity-endpoint"}, "dependency_check_ids": []interface{}{}, "required_capability_ids": []interface{}{}, "execution_policy": map[string]interface{}{"deadline_ns": 1, "dependency_failure_reason_code": "", "deadline_is_expected_condition": false}, "expected_condition": map[string]interface{}{"kind": "RESULT", "result": "REFUSED"}}}
			return r
		}, mutations: []func(map[string]interface{}){
			func(r map[string]interface{}) {
				delete(r["check_definitions"].([]interface{})[0].(map[string]interface{})["expected_condition"].(map[string]interface{}), "result")
			},
			func(r map[string]interface{}) {
				r["check_definitions"].([]interface{})[0].(map[string]interface{})["expected_condition"].(map[string]interface{})["port"] = 443
			},
			func(r map[string]interface{}) {
				r["check_definitions"].([]interface{})[0].(map[string]interface{})["expected_condition"].(map[string]interface{})["kind"] = "UNKNOWN"
			},
		}},
		{name: "limitation scope", valid: func() map[string]interface{} {
			r := minimalSchemaInstance()
			r["limitations"] = []interface{}{map[string]interface{}{"limitation_id": "limitation-000001", "code": "generic", "scope": map[string]interface{}{"kind": "VANTAGE", "vantage_id": "vantage-000001"}}}
			return r
		}, mutations: []func(map[string]interface{}){
			func(r map[string]interface{}) {
				delete(r["limitations"].([]interface{})[0].(map[string]interface{})["scope"].(map[string]interface{}), "vantage_id")
			},
			func(r map[string]interface{}) {
				r["limitations"].([]interface{})[0].(map[string]interface{})["scope"].(map[string]interface{})["observation_id"] = "observation-000001"
			},
			func(r map[string]interface{}) {
				r["limitations"].([]interface{})[0].(map[string]interface{})["scope"].(map[string]interface{})["kind"] = "UNKNOWN"
			},
		}},
		{name: "evidence reference", valid: func() map[string]interface{} {
			r := minimalSchemaInstance()
			r["service_path"] = map[string]interface{}{"nodes": []interface{}{}, "edges": []interface{}{map[string]interface{}{"edge_id": "edge-000001", "from": "entity-a", "to": "entity-b", "relation": "ROUTES_TO", "provenance": "DIRECTLY_OBSERVED", "evidence_refs": []interface{}{map[string]interface{}{"kind": "OBSERVATION", "id": "observation-000001"}}}}, "branches": []interface{}{}}
			return r
		}, mutations: []func(map[string]interface{}){
			func(r map[string]interface{}) {
				delete(r["service_path"].(map[string]interface{})["edges"].([]interface{})[0].(map[string]interface{})["evidence_refs"].([]interface{})[0].(map[string]interface{}), "id")
			},
			func(r map[string]interface{}) {
				r["service_path"].(map[string]interface{})["edges"].([]interface{})[0].(map[string]interface{})["evidence_refs"].([]interface{})[0].(map[string]interface{})["id"] = "claim-000001"
			},
			func(r map[string]interface{}) {
				r["service_path"].(map[string]interface{})["edges"].([]interface{})[0].(map[string]interface{})["evidence_refs"].([]interface{})[0].(map[string]interface{})["kind"] = "UNKNOWN"
			},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := schema.Validate(tc.valid()); err != nil {
				t.Fatalf("valid case rejected: %v", err)
			}
			for i, mutate := range tc.mutations {
				instance := tc.valid()
				mutate(instance)
				if err := schema.Validate(instance); err == nil {
					t.Errorf("mutation %d accepted", i)
				}
			}
		})
	}
}

func TestSchemaSemanticStringConstraints(t *testing.T) {
	path := filepath.Join("..", "..", "..", "schema", "report", "v1.0.0", "schema.json")
	c := jsonschema.NewCompiler()
	schema, err := c.Compile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{name: "entity hostname", mutate: func(r map[string]interface{}) {
			r["entities"] = []interface{}{map[string]interface{}{"entity_id": "entity-hostname", "kind": "HOSTNAME", "display_label": "hostname", "identity": map[string]interface{}{"kind": "HOSTNAME", "hostname": "https://user:password@example.test/path?q=secret"}}}
		}},
		{name: "fingerprint", mutate: func(r map[string]interface{}) {
			r["entities"] = []interface{}{map[string]interface{}{"entity_id": "entity-peer", "kind": "TLS_PEER", "display_label": "peer", "identity": map[string]interface{}{"kind": "TLS_PEER", "fingerprint": "sha256:synthetic"}}}
		}},
		{name: "synthetic identifier", mutate: func(r map[string]interface{}) {
			r["entities"] = []interface{}{map[string]interface{}{"entity_id": "entity-proxy", "kind": "PROXY_INSTANCE", "display_label": "proxy", "identity": map[string]interface{}{"kind": "PROXY_INSTANCE", "synthetic_id": "/raw/private/path"}}}
		}},
		{name: "runtime identifier", mutate: func(r map[string]interface{}) {
			r["entities"] = []interface{}{map[string]interface{}{"entity_id": "entity-container", "kind": "CONTAINER", "display_label": "container", "identity": map[string]interface{}{"kind": "CONTAINER", "runtime_id": "https://user:password@example.test/path", "container_id": "container-1"}}}
		}},
		{name: "reason code", mutate: func(r map[string]interface{}) {
			r["capabilities"] = []interface{}{map[string]interface{}{"capability_id": "capability-000001", "kind": "HTTP_PROBE", "state": "AVAILABLE", "reason_code": "Authorization: Bearer secret"}}
		}},
		{name: "bounded display label", mutate: func(r map[string]interface{}) {
			r["entities"] = []interface{}{map[string]interface{}{"entity_id": "entity-proxy", "kind": "PROXY_INSTANCE", "display_label": strings.Repeat("a", 129), "identity": map[string]interface{}{"kind": "PROXY_INSTANCE", "synthetic_id": "proxy-1"}}}
		}},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			instance := minimalSchemaInstance()
			tc.mutate(instance)
			if err := schema.Validate(instance); err == nil {
				t.Fatalf("semantic source-shaped value accepted")
			}
		})
	}
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
