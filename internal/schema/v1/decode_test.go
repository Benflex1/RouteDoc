package v1

import (
	"encoding/json"
	"testing"
	"time"

	"routedoc/internal/model"
	"routedoc/internal/rules"
)

func TestDecodeMissingAndUnknownFields(t *testing.T) {
	_, issues := Decode([]byte(`{"producer":{}}`), ReadValidate)
	if !hasDecodeCode(issues, model.CodeMissingRequiredField) {
		t.Fatalf("missing version/fields: %#v", issues)
	}
	b := []byte(`{"report_schema_version":"1.0.0","unknown":1}`)
	_, issues = Decode(b, ReadValidate)
	if !hasDecodeCode(issues, model.CodeUnknownField) {
		t.Fatalf("unknown field: %#v", issues)
	}
}
func TestDecodeCompatibilityOperations(t *testing.T) {
	b := []byte(`{"report_schema_version":"1.1.0","future":true}`)
	d, issues := Decode(b, ReadValidate)
	if !hasDecodeCode(issues, model.CodeMissingRequiredField) && d.Version.Major != 1 {
		t.Fatalf("compat decode: %#v", issues)
	}
	_, issues = Decode(b, CanonicalJSON)
	if !hasDecodeCode(issues, model.CodeExactVersionRequired) {
		t.Fatalf("exact required: %#v", issues)
	}
}
func TestDecodeDuplicateMember(t *testing.T) {
	_, issues := Decode([]byte(`{"report_schema_version":"1.0.0","report_schema_version":"1.0.0"}`), ReadValidate)
	if !hasDecodeCode(issues, model.CodeDuplicateField) {
		t.Fatalf("duplicate: %#v", issues)
	}
}

func TestCompatibilityProjectionPreservesProvenanceAndStaysReadOnly(t *testing.T) {
	for _, tc := range []struct {
		version string
		warning bool
	}{
		{version: "1.1.0", warning: true},
		{version: "1.0.1", warning: false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			instance := minimalSchemaInstance()
			instance["report_schema_version"] = tc.version
			if tc.warning {
				instance["future"] = true
			}
			data, err := json.Marshal(instance)
			if err != nil {
				t.Fatal(err)
			}
			d, issues := Decode(data, ReadRender)
			if len(issues) != 0 {
				t.Fatal(issues)
			}
			if d.Version.String() != tc.version || d.Run.Evidence.ReportSchemaVersion.String() != tc.version || d.Exact {
				t.Fatalf("projection provenance lost: %#v", d)
			}
			if tc.warning != (len(d.Warnings) == 1 && d.Warnings[0].Code == model.CodeNewerMinorFieldIgnored && d.Warnings[0].Pointer == "/future") {
				t.Fatalf("warnings: %#v", d.Warnings)
			}
			validated, issues := model.ValidatePersistedEvaluatedRun(d.Run)
			if len(issues) != 0 {
				t.Fatalf("projection should validate as read-only model data: %v", issues)
			}
			if _, issues := EncodeCanonical(validated); !hasDecodeCode(issues, model.CodeExactVersionRequired) {
				t.Fatalf("projection was canonicalized: %v", issues)
			}
			registry, registryIssues := rules.NewRegistry()
			if len(registryIssues) != 0 {
				t.Fatal(registryIssues)
			}
			if _, issues := rules.NewEvaluator(registry).Reevaluate(validated, time.Now().UTC()); !hasDecodeCode(issues, model.CodeExactVersionRequired) {
				t.Fatalf("projection was re-evaluated: %v", issues)
			}
		})
	}
}

func TestDecodeRejectsUnknownFieldsRecursively(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{name: "top level", mutate: func(r map[string]interface{}) { r["unknown_top"] = true }},
		{name: "nested limitation", mutate: func(r map[string]interface{}) {
			r["limitations"] = []interface{}{map[string]interface{}{"limitation_id": "limitation-000001", "code": "generic", "scope": map[string]interface{}{"kind": "RUN", "unknown_scope": true}, "unknown_limitation": true}}
		}},
		{name: "nested identity", mutate: func(r map[string]interface{}) {
			r["entities"] = []interface{}{map[string]interface{}{"entity_id": "entity-hostname", "kind": "HOSTNAME", "display_label": "hostname", "identity": map[string]interface{}{"kind": "HOSTNAME", "hostname": "example.test", "unknown_identity": true}}}
		}},
		{name: "observation payload", mutate: func(r map[string]interface{}) {
			r["observations"] = []interface{}{map[string]interface{}{"observation_id": "observation-000001", "kind": "TCP_CONNECTION_RESULT", "subject_entity_ids": []interface{}{}, "observed_at": "2026-08-08T10:00:00Z", "payload": map[string]interface{}{"kind": "TCP_CONNECTION_RESULT", "endpoint_entity_id": "entity-endpoint", "result": "ACCEPTED", "duration_ns": 1, "deadline_part_of_expected_condition": false, "unknown_payload": true}, "acquisition_method": "SYNTHETIC_FIXTURE", "source_component": "SYNTHETIC_FIXTURE", "sensitivity": "SANITIZED_DERIVED", "limitations": []interface{}{}}}
		}},
		{name: "redirect target", mutate: func(r map[string]interface{}) {
			r["observations"] = []interface{}{map[string]interface{}{"observation_id": "observation-000001", "kind": "HTTP_RESULT", "subject_entity_ids": []interface{}{}, "observed_at": "2026-08-08T10:00:00Z", "payload": map[string]interface{}{"kind": "HTTP_RESULT", "exchange_entity_id": "entity-exchange", "result_kind": "REDIRECT", "status_code": 302, "redirect_target": map[string]interface{}{"scheme": "https", "hostname": "example.test", "effective_port": 443, "path": map[string]interface{}{"present": true, "is_root": true, "segment_count": 0, "trailing_slash": false, "query_present": false, "unknown_path": true}, "unknown_target": true}}, "acquisition_method": "SYNTHETIC_FIXTURE", "source_component": "SYNTHETIC_FIXTURE", "sensitivity": "SANITIZED_DERIVED", "limitations": []interface{}{}}}
		}},
		{name: "visibility scope", mutate: func(r map[string]interface{}) {
			r["visibility_assessments"] = []interface{}{map[string]interface{}{"visibility_id": "visibility-000001", "subject_kind": "LISTENER", "vantage_id": "vantage-000001", "scope": map[string]interface{}{"kind": "LISTENER", "namespace_entity_id": "entity-namespace", "protocol": "TCP", "address_family": "IPV4", "bind_semantics": "WILDCARD", "port_start": 1, "port_end": 65535, "process_ownership_required": false, "unknown_scope": true}, "level": "PARTIAL", "basis_observation_ids": []interface{}{}, "limitations": []interface{}{}, "assessed_at": "2026-08-08T10:00:00Z"}}
		}},
		{name: "claim parameters", mutate: func(r map[string]interface{}) {
			r["claims"] = []interface{}{map[string]interface{}{"claim_id": "claim-000001", "statement_code": "TCP_CONNECTION_REFUSED", "level": "INFERRED", "subject_entity_ids": []interface{}{}, "branch_ids": []interface{}{}, "parameters": map[string]interface{}{"kind": "TCP_CONNECTION_REFUSED", "endpoint_entity_id": "entity-endpoint", "vantage_id": "vantage-000001", "observed_at": "2026-08-08T10:00:00Z", "unknown_parameters": true}, "supporting_evidence": []interface{}{}, "contradicting_evidence": []interface{}{}, "required_missing_evidence": []interface{}{}, "rule_id": "tcp.connection_refused/v1"}}
		}},
		{name: "missing requirement", mutate: func(r map[string]interface{}) {
			r["claims"] = []interface{}{map[string]interface{}{"claim_id": "claim-000001", "statement_code": "TCP_CONNECTION_REFUSED", "level": "INFERRED", "subject_entity_ids": []interface{}{}, "branch_ids": []interface{}{}, "parameters": map[string]interface{}{"kind": "TCP_CONNECTION_REFUSED", "endpoint_entity_id": "entity-endpoint", "vantage_id": "vantage-000001", "observed_at": "2026-08-08T10:00:00Z"}, "supporting_evidence": []interface{}{}, "contradicting_evidence": []interface{}{}, "required_missing_evidence": []interface{}{map[string]interface{}{"kind": "OBSERVATION_REQUIRED", "observation_kind": "TCP_CONNECTION_RESULT", "unknown_requirement": true}}, "rule_id": "tcp.connection_refused/v1"}}
		}},
		{name: "finding path position", mutate: func(r map[string]interface{}) {
			r["findings"] = []interface{}{map[string]interface{}{"finding_id": "finding-000001", "kind": "BLOCKER", "title_code": "TCP_CONNECTION_REFUSED", "level": "INFERRED", "branch_ids": []interface{}{}, "path_positions": []interface{}{map[string]interface{}{"branch_id": "branch-000001", "position": 0, "unknown_position": true}}, "claim_ids": []interface{}{}, "rule_id": "tcp.connection_refused/v1", "limitations": []interface{}{}, "suggested_experiments": []interface{}{}, "selection": "NONE"}}
		}},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			instance := minimalSchemaInstance()
			tc.mutate(instance)
			data, err := json.Marshal(instance)
			if err != nil {
				t.Fatal(err)
			}
			_, issues := Decode(data, ReadValidate)
			if !hasDecodeCode(issues, model.CodeUnknownField) {
				t.Fatalf("nested unknown field accepted: %v", issues)
			}
		})
	}
}

func TestNewerMinorWarningsAreCanonicalPointerOrderedAndKindsRemainHardErrors(t *testing.T) {
	instance := minimalSchemaInstance()
	instance["report_schema_version"] = "1.1.0"
	instance["z_top"] = true
	instance["producer"].(map[string]interface{})["a_future"] = true
	instance["target"].(map[string]interface{})["m_future"] = true
	data, err := json.Marshal(instance)
	if err != nil {
		t.Fatal(err)
	}
	d, issues := Decode(data, ReadValidate)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if len(d.Warnings) != 3 || d.Warnings[0].Pointer != "/producer/a_future" || d.Warnings[1].Pointer != "/target/m_future" || d.Warnings[2].Pointer != "/z_top" {
		t.Fatalf("warnings are not pointer ordered: %#v", d.Warnings)
	}

	instance = minimalSchemaInstance()
	instance["report_schema_version"] = "1.1.0"
	instance["entities"] = []interface{}{map[string]interface{}{"entity_id": "entity-hostname", "kind": "HOSTNAME", "display_label": "hostname", "identity": map[string]interface{}{"kind": "FUTURE_IDENTITY", "hostname": "example.test"}}}
	data, err = json.Marshal(instance)
	if err != nil {
		t.Fatal(err)
	}
	if _, issues = Decode(data, ReadValidate); !hasDecodeCode(issues, model.CodeUnknownUnionKind) {
		t.Fatalf("newer-minor unknown union was ignored: %v", issues)
	}
}

func TestNewerMinorUnknownEnumsAreHardErrors(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{name: "endpoint transport", mutate: func(r map[string]interface{}) {
			r["entities"] = []interface{}{map[string]interface{}{"entity_id": "entity-endpoint", "kind": "SOCKET_ENDPOINT", "display_label": "endpoint", "identity": map[string]interface{}{"kind": "SOCKET_ENDPOINT", "endpoint": map[string]interface{}{"address": "127.0.0.1", "port": 443, "transport": "NOPE"}}}}
		}},
		{name: "assertion expectation kind", mutate: func(r map[string]interface{}) {
			r["operator_assertions"] = []interface{}{map[string]interface{}{"assertion_id": "assertion-000001", "kind": "HTTP_EXPECTATION", "parameters": map[string]interface{}{"kind": "HTTP_EXPECTATION", "expectation_kind": "NOPE"}, "established_at": "2026-08-08T10:00:00Z", "source": "SYNTHETIC_FIXTURE"}}
		}},
		{name: "expected matcher result", mutate: func(r map[string]interface{}) {
			r["check_definitions"] = []interface{}{map[string]interface{}{"check_id": "check-000001", "kind": "TCP_CONNECTION", "version": "1.0.0", "inputs": map[string]interface{}{"kind": "SUBJECT", "subject_entity_id": "entity-endpoint"}, "dependency_check_ids": []interface{}{}, "required_capability_ids": []interface{}{}, "execution_policy": map[string]interface{}{"deadline_ns": 1, "dependency_failure_reason_code": "", "deadline_is_expected_condition": false}, "expected_condition": map[string]interface{}{"kind": "MATCHER_RESULT", "matcher_result": "NOPE"}}}
		}},
		{name: "certificate trust source", mutate: func(r map[string]interface{}) {
			r["observations"] = []interface{}{map[string]interface{}{"observation_id": "observation-000001", "kind": "CERTIFICATE_VERIFICATION_RESULT", "subject_entity_ids": []interface{}{}, "vantage_id": "vantage-000001", "observed_at": "2026-08-08T10:00:00Z", "payload": map[string]interface{}{"kind": "CERTIFICATE_VERIFICATION_RESULT", "peer_entity_id": "entity-peer", "verified_hostname": "example.test", "verification_time": "2026-08-08T10:00:00Z", "trust_source": "NOPE", "result": "VERIFIED"}, "acquisition_method": "SYNTHETIC_FIXTURE", "source_component": "SYNTHETIC_FIXTURE", "sensitivity": "SANITIZED_DERIVED", "limitations": []interface{}{}}}
		}},
		{name: "certificate failure reason", mutate: func(r map[string]interface{}) {
			r["observations"] = []interface{}{map[string]interface{}{"observation_id": "observation-000001", "kind": "CERTIFICATE_VERIFICATION_RESULT", "subject_entity_ids": []interface{}{}, "vantage_id": "vantage-000001", "observed_at": "2026-08-08T10:00:00Z", "payload": map[string]interface{}{"kind": "CERTIFICATE_VERIFICATION_RESULT", "peer_entity_id": "entity-peer", "verified_hostname": "example.test", "verification_time": "2026-08-08T10:00:00Z", "trust_source": "SYSTEM", "result": "VERIFIED", "failure_reason": "NOPE"}, "acquisition_method": "SYNTHETIC_FIXTURE", "source_component": "SYNTHETIC_FIXTURE", "sensitivity": "SANITIZED_DERIVED", "limitations": []interface{}{}}}
		}},
		{name: "TLS peer SAN type", mutate: func(r map[string]interface{}) {
			r["observations"] = []interface{}{map[string]interface{}{"observation_id": "observation-000001", "kind": "TLS_PEER_SUMMARY", "subject_entity_ids": []interface{}{}, "vantage_id": "vantage-000001", "observed_at": "2026-08-08T10:00:00Z", "payload": map[string]interface{}{"kind": "TLS_PEER_SUMMARY", "peer_entity_id": "entity-peer", "certificate_count": 1, "leaf_sha256": "sha256:0000000000000000000000000000000000000000000000000000000000000001", "not_before": "2026-08-08T10:00:00Z", "not_after": "2026-08-08T10:00:00Z", "san_type": "NOPE", "san_count": 0}, "acquisition_method": "SYNTHETIC_FIXTURE", "source_component": "SYNTHETIC_FIXTURE", "sensitivity": "SANITIZED_DERIVED", "limitations": []interface{}{}}}
		}},
		{name: "Docker fact kind", mutate: func(r map[string]interface{}) {
			r["observations"] = []interface{}{map[string]interface{}{"observation_id": "observation-000001", "kind": "DOCKER_RUNTIME_SUMMARY", "subject_entity_ids": []interface{}{}, "vantage_id": "vantage-000001", "observed_at": "2026-08-08T10:00:00Z", "payload": map[string]interface{}{"kind": "DOCKER_RUNTIME_SUMMARY", "fact_kind": "NOPE", "container_entity_id": "entity-container", "runtime_state": "RUNNING"}, "acquisition_method": "SYNTHETIC_FIXTURE", "source_component": "SYNTHETIC_FIXTURE", "sensitivity": "SANITIZED_DERIVED", "limitations": []interface{}{}}}
		}},
		{name: "missing observation kind", mutate: func(r map[string]interface{}) {
			r["claims"] = []interface{}{map[string]interface{}{"claim_id": "claim-000001", "statement_code": "TCP_CONNECTION_REFUSED", "level": "INFERRED", "subject_entity_ids": []interface{}{}, "branch_ids": []interface{}{}, "parameters": map[string]interface{}{"kind": "TCP_CONNECTION_REFUSED", "endpoint_entity_id": "entity-endpoint", "vantage_id": "vantage-000001", "observed_at": "2026-08-08T10:00:00Z"}, "supporting_evidence": []interface{}{}, "contradicting_evidence": []interface{}{}, "required_missing_evidence": []interface{}{map[string]interface{}{"kind": "OBSERVATION_REQUIRED", "observation_kind": "NOPE"}}, "rule_id": "tcp.connection_refused/v1"}}
		}},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			instance := minimalSchemaInstance()
			instance["report_schema_version"] = "1.1.0"
			tc.mutate(instance)
			data, err := json.Marshal(instance)
			if err != nil {
				t.Fatal(err)
			}
			if _, issues := Decode(data, ReadValidate); !hasDecodeCode(issues, model.CodeUnknownEnumValue) {
				t.Fatalf("unknown enum was ignored in newer minor: %v", issues)
			}
		})
	}
}

func TestDecodeRejectsMissingClosedUnionMembers(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{name: "entity identity", mutate: func(r map[string]interface{}) {
			r["entities"] = []interface{}{map[string]interface{}{"entity_id": "entity-hostname", "kind": "HOSTNAME", "display_label": "hostname", "identity": map[string]interface{}{"kind": "HOSTNAME"}}}
		}},
		{name: "observation payload", mutate: func(r map[string]interface{}) {
			r["observations"] = []interface{}{map[string]interface{}{"observation_id": "observation-000001", "kind": "TCP_CONNECTION_RESULT", "subject_entity_ids": []interface{}{}, "observed_at": "2026-08-08T10:00:00Z", "payload": map[string]interface{}{"kind": "TCP_CONNECTION_RESULT", "result": "ACCEPTED", "duration_ns": 1, "deadline_part_of_expected_condition": false}, "acquisition_method": "SYNTHETIC_FIXTURE", "source_component": "SYNTHETIC_FIXTURE", "sensitivity": "SANITIZED_DERIVED", "limitations": []interface{}{}}}
		}},
		{name: "claim parameters", mutate: func(r map[string]interface{}) {
			r["claims"] = []interface{}{map[string]interface{}{"claim_id": "claim-000001", "statement_code": "TCP_CONNECTION_REFUSED", "level": "INFERRED", "subject_entity_ids": []interface{}{}, "branch_ids": []interface{}{}, "parameters": map[string]interface{}{"kind": "TCP_CONNECTION_REFUSED", "vantage_id": "vantage-000001", "observed_at": "2026-08-08T10:00:00Z"}, "supporting_evidence": []interface{}{}, "contradicting_evidence": []interface{}{}, "required_missing_evidence": []interface{}{}, "rule_id": "tcp.connection_refused/v1"}}
		}},
		{name: "missing evidence requirement", mutate: func(r map[string]interface{}) {
			r["claims"] = []interface{}{map[string]interface{}{"claim_id": "claim-000001", "statement_code": "TCP_CONNECTION_REFUSED", "level": "INFERRED", "subject_entity_ids": []interface{}{}, "branch_ids": []interface{}{}, "parameters": map[string]interface{}{"kind": "TCP_CONNECTION_REFUSED", "endpoint_entity_id": "entity-endpoint", "vantage_id": "vantage-000001", "observed_at": "2026-08-08T10:00:00Z"}, "supporting_evidence": []interface{}{}, "contradicting_evidence": []interface{}{}, "required_missing_evidence": []interface{}{map[string]interface{}{"kind": "OBSERVATION_REQUIRED"}}, "rule_id": "tcp.connection_refused/v1"}}
		}},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			instance := minimalSchemaInstance()
			tc.mutate(instance)
			data, err := json.Marshal(instance)
			if err != nil {
				t.Fatal(err)
			}
			if _, issues := Decode(data, ReadValidate); !hasDecodeCode(issues, model.CodeMissingRequiredField) {
				t.Fatalf("missing union member accepted: %v", issues)
			}
		})
	}
}

func hasDecodeCode(v model.ValidationIssues, c model.ValidationCode) bool {
	for _, i := range v {
		if i.Code == c {
			return true
		}
	}
	return false
}
