package v1

import (
	"bytes"
	"encoding/json"
	"testing"

	"routedoc/internal/model"
)

func TestTLSTransportResultAcceptsResultDependentPeerEvidence(t *testing.T) {
	tests := []struct {
		name   string
		result string
		peer   bool
	}{
		{name: "failed before certificate", result: "FAILED"},
		{name: "timed out before certificate", result: "TIMED_OUT"},
		{name: "plaintext-style failed transport", result: "FAILED"},
		{name: "completed with certificate peer", result: "COMPLETED", peer: true},
		{name: "completed without certificate peer", result: "COMPLETED"},
		{name: "failed after certificate", result: "FAILED", peer: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := tlsTransportReport("entity-endpoint", "entity-peer", tc.result, tc.peer)
			validated := decodeAndValidateTLSTransport(t, report)
			encoded, issues := EncodeCanonical(validated)
			if len(issues) != 0 {
				t.Fatalf("canonical encode rejected valid transport: %#v", issues)
			}
			if !bytes.Contains(encoded, []byte(`"endpoint_entity_id":"entity-endpoint"`)) {
				t.Fatalf("canonical transport omitted endpoint: %s", encoded)
			}
		})
	}
}

func TestTLSTransportResultCanonicalOrderOmitsAbsentPeer(t *testing.T) {
	validated := decodeAndValidateTLSTransport(t, tlsTransportReport("entity-endpoint", "entity-peer", "TIMED_OUT", false))
	encoded, issues := EncodeCanonical(validated)
	if len(issues) != 0 {
		t.Fatalf("canonical encode rejected valid transport: %#v", issues)
	}
	want := `"kind":"TLS_TRANSPORT_RESULT","endpoint_entity_id":"entity-endpoint","result":"TIMED_OUT","protocol_version":"UNKNOWN","cipher_suite":"UNKNOWN","negotiated_alpn":"UNKNOWN","sni_sent":"example.test","duration_ns":1`
	if !bytes.Contains(encoded, []byte(want)) {
		t.Fatalf("transport member order changed or optional peer was not omitted: %s", encoded)
	}
	if bytes.Contains(encoded, []byte(`"peer_entity_id"`)) {
		t.Fatalf("absent peer was fabricated in canonical output: %s", encoded)
	}
}

func TestTLSTransportResultRejectsTypedReferenceErrors(t *testing.T) {
	tests := []struct {
		name       string
		endpointID string
		peerID     string
		entities   []interface{}
		want       map[string]model.ValidationCode
	}{
		{
			name:       "missing endpoint",
			endpointID: "entity-missing-endpoint",
			peerID:     "entity-peer",
			entities:   tlsEntities(true),
			want:       map[string]model.ValidationCode{"/observations/0/payload/endpoint_entity_id": model.CodeReferenceMissing},
		},
		{
			name:       "endpoint points to TLS peer",
			endpointID: "entity-peer",
			peerID:     "entity-peer",
			entities:   tlsEntities(true),
			want:       map[string]model.ValidationCode{"/observations/0/payload/endpoint_entity_id": model.CodeReferenceKindMismatch},
		},
		{
			name:       "peer points to socket endpoint",
			endpointID: "entity-endpoint",
			peerID:     "entity-endpoint",
			entities:   tlsEntities(false),
			want:       map[string]model.ValidationCode{"/observations/0/payload/peer_entity_id": model.CodeReferenceKindMismatch},
		},
		{
			name:       "both references nonexistent",
			endpointID: "entity-missing-endpoint",
			peerID:     "entity-missing-peer",
			entities:   []interface{}{},
			want: map[string]model.ValidationCode{
				"/observations/0/payload/endpoint_entity_id": model.CodeReferenceMissing,
				"/observations/0/payload/peer_entity_id":     model.CodeReferenceMissing,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := tlsTransportReport(tc.endpointID, tc.peerID, "FAILED", true)
			report["entities"] = tc.entities
			_, issues := Decode(tlsJSON(t, report), ReadValidate)
			if len(issues) != 0 {
				t.Fatalf("decode failed before semantic validation: %#v", issues)
			}
			d, _ := Decode(tlsJSON(t, report), ReadValidate)
			_, issues = model.ValidatePersistedEvaluatedRun(d.Run)
			for pointer, code := range tc.want {
				if !hasIssueAt(issues, pointer, code) {
					t.Fatalf("wanted %s at %s: %#v", code, pointer, issues)
				}
			}
		})
	}
}

func TestTLSTransportResultRejectsExactUnknownAndCrossCaseFields(t *testing.T) {
	report := tlsTransportReport("entity-endpoint", "entity-peer", "COMPLETED", true)
	payload := report["observations"].([]interface{})[0].(map[string]interface{})["payload"].(map[string]interface{})
	payload["PeerEntityID"] = "entity-peer"
	_, issues := Decode(tlsJSON(t, report), ReadValidate)
	if !hasIssueCode(issues, model.CodeUnknownField) {
		t.Fatalf("case-variant field accepted: %#v", issues)
	}

	report = tlsTransportReport("entity-endpoint", "entity-peer", "COMPLETED", true)
	payload = report["observations"].([]interface{})[0].(map[string]interface{})["payload"].(map[string]interface{})
	payload["transport_extra"] = true
	_, issues = Decode(tlsJSON(t, report), ReadValidate)
	if !hasIssueCode(issues, model.CodeUnknownField) {
		t.Fatalf("cross-case field accepted: %#v", issues)
	}
}

func decodeAndValidateTLSTransport(t *testing.T, report map[string]interface{}) model.ValidatedEvaluatedRun {
	t.Helper()
	d, issues := Decode(tlsJSON(t, report), ReadValidate)
	if len(issues) != 0 {
		t.Fatalf("decode failed: %#v", issues)
	}
	validated, issues := model.ValidatePersistedEvaluatedRun(d.Run)
	if len(issues) != 0 {
		t.Fatalf("TLS transport rejected: %#v", issues)
	}
	return validated
}

func tlsJSON(t *testing.T, report map[string]interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func tlsTransportReport(endpointID, peerID, result string, withPeer bool) map[string]interface{} {
	report := minimalSchemaInstance()
	report["entities"] = tlsEntities(withPeer)
	payload := map[string]interface{}{
		"kind":               "TLS_TRANSPORT_RESULT",
		"endpoint_entity_id": endpointID,
		"result":             result,
		"protocol_version":   "UNKNOWN",
		"cipher_suite":       "UNKNOWN",
		"negotiated_alpn":    "UNKNOWN",
		"sni_sent":           "example.test",
		"duration_ns":        1,
	}
	if withPeer {
		payload["peer_entity_id"] = peerID
	}
	report["observations"] = []interface{}{map[string]interface{}{
		"observation_id":     "observation-000001",
		"kind":               "TLS_TRANSPORT_RESULT",
		"subject_entity_ids": []interface{}{endpointID},
		"vantage_id":         "vantage-000001",
		"observed_at":        "2026-08-08T10:00:00Z",
		"payload":            payload,
		"acquisition_method": "SYNTHETIC_FIXTURE",
		"source_component":   "SYNTHETIC_FIXTURE",
		"sensitivity":        "SANITIZED_DERIVED",
		"limitations":        []interface{}{},
	}}
	report["vantage_points"] = []interface{}{map[string]interface{}{
		"vantage_id": "vantage-000001", "kind": "CLIENT_NETWORK", "role": "CLIENT", "display_label": "client",
		"identity": map[string]interface{}{"kind": "CLIENT_NETWORK", "label": "client"}, "establishment": "DIRECTLY_OBSERVED", "limitations": []interface{}{},
	}}
	return report
}

func tlsEntities(withPeer bool) []interface{} {
	entities := []interface{}{map[string]interface{}{
		"entity_id": "entity-endpoint", "kind": "SOCKET_ENDPOINT", "display_label": "endpoint",
		"identity": map[string]interface{}{"kind": "SOCKET_ENDPOINT", "endpoint": map[string]interface{}{"address": "192.0.2.10", "port": 443, "transport": "TCP"}},
	}}
	if withPeer {
		entities = append(entities, map[string]interface{}{
			"entity_id": "entity-peer", "kind": "TLS_PEER", "display_label": "TLS peer",
			"identity": map[string]interface{}{"kind": "TLS_PEER", "fingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000001"},
		})
	}
	return entities
}

func hasIssueAt(issues model.ValidationIssues, pointer string, code model.ValidationCode) bool {
	for _, issue := range issues {
		if issue.Pointer == pointer && issue.Code == code {
			return true
		}
	}
	return false
}

func hasIssueCode(issues model.ValidationIssues, code model.ValidationCode) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
