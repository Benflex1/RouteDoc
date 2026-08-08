package v1

import (
	"encoding/json"
	"strconv"
)

// wireShape is the production structural description used by the decoder's
// recursive object scanner. It intentionally contains no schema-validator
// dependency. Union cases select their complete member set from the decoded
// kind, so a field from another case cannot be mistaken for a future minor
// extension.
var wireShape = map[string]map[string]bool{
	"":                              {"report_schema_version": true, "producer": true, "run_id": true, "target": true, "goal": true, "requested_scope": true, "policy": true, "started_at": true, "finished_at": true, "vantage_points": true, "capabilities": true, "operator_assertions": true, "entities": true, "service_path": true, "check_definitions": true, "check_executions": true, "observations": true, "visibility_assessments": true, "evaluation": true, "claims": true, "findings": true, "limitations": true},
	"/producer":                     {"name": true, "version": true, "build": true},
	"/target":                       {"scheme": true, "hostname": true, "effective_port": true, "path": true},
	"/target/path":                  {"present": true, "is_root": true, "segment_count": true, "trailing_slash": true, "query_present": true},
	"/entities/*/identity/endpoint": {"address": true, "port": true, "transport": true},
	"/observations/*/payload/redirect_target/path": {"present": true, "is_root": true, "segment_count": true, "trailing_slash": true, "query_present": true},
	"/goal":                                                  {"kind": true, "expectation_assertion_id": true},
	"/requested_scope":                                       {"kind": true},
	"/policy":                                                {"coherence_window_ns": true},
	"/limitation":                                            {"limitation_id": true, "code": true, "scope": true},
	"/limitations/*":                                         {"limitation_id": true, "code": true, "scope": true},
	"/limitation/scope":                                      {"kind": true, "vantage_id": true, "observation_id": true, "visibility_id": true, "finding_id": true},
	"/limitations/*/scope":                                   {"kind": true, "vantage_id": true, "observation_id": true, "visibility_id": true, "finding_id": true},
	"/vantage_points/*/limitations/*":                        {"limitation_id": true, "code": true, "scope": true},
	"/vantage_points/*/limitations/*/scope":                  {"kind": true, "vantage_id": true, "observation_id": true, "visibility_id": true, "finding_id": true},
	"/observations/*/limitations/*":                          {"limitation_id": true, "code": true, "scope": true},
	"/observations/*/limitations/*/scope":                    {"kind": true, "vantage_id": true, "observation_id": true, "visibility_id": true, "finding_id": true},
	"/visibility_assessments/*/limitations/*":                {"limitation_id": true, "code": true, "scope": true},
	"/visibility_assessments/*/limitations/*/scope":          {"kind": true, "vantage_id": true, "observation_id": true, "visibility_id": true, "finding_id": true},
	"/findings/*/limitations/*":                              {"limitation_id": true, "code": true, "scope": true},
	"/findings/*/limitations/*/scope":                        {"kind": true, "vantage_id": true, "observation_id": true, "visibility_id": true, "finding_id": true},
	"/vantage_points/*":                                      {"vantage_id": true, "kind": true, "role": true, "display_label": true, "identity": true, "parent_vantage_id": true, "establishment": true, "limitations": true},
	"/capabilities/*":                                        {"capability_id": true, "kind": true, "state": true, "reason_code": true},
	"/operator_assertions/*":                                 {"assertion_id": true, "kind": true, "parameters": true, "established_at": true, "source": true},
	"/entities/*":                                            {"entity_id": true, "kind": true, "display_label": true, "identity": true},
	"/service_path":                                          {"nodes": true, "edges": true, "branches": true},
	"/service_path/nodes/*":                                  {"entity_id": true},
	"/service_path/edges/*":                                  {"edge_id": true, "from": true, "to": true, "relation": true, "provenance": true, "evidence_refs": true},
	"/service_path/edges/*/evidence_refs/*":                  {"kind": true, "id": true},
	"/service_path/branches/*":                               {"branch_id": true, "parent_branch_id": true, "ordered_edge_ids": true, "goal": true},
	"/check_definitions/*":                                   {"check_id": true, "kind": true, "version": true, "inputs": true, "dependency_check_ids": true, "required_capability_ids": true, "execution_policy": true, "expected_condition": true},
	"/check_definitions/*/execution_policy":                  {"deadline_ns": true, "dependency_failure_reason_code": true, "deadline_is_expected_condition": true},
	"/check_executions/*":                                    {"execution_id": true, "check_id": true, "branch_id": true, "vantage_id": true, "started_at": true, "finished_at": true, "lifecycle": true, "verdict": true, "reason_code": true, "observation_ids": true, "visibility_assessment_ids": true},
	"/observations/*":                                        {"observation_id": true, "kind": true, "subject_entity_ids": true, "vantage_id": true, "observed_at": true, "payload": true, "acquisition_method": true, "source_component": true, "sensitivity": true, "limitations": true},
	"/observations/*/payload/redirect_target":                {"scheme": true, "hostname": true, "effective_port": true, "path": true},
	"/visibility_assessments/*":                              {"visibility_id": true, "subject_kind": true, "vantage_id": true, "scope": true, "level": true, "basis_observation_ids": true, "limitations": true, "assessed_at": true},
	"/visibility_assessments/*/scope":                        {"kind": true, "namespace_entity_id": true, "protocol": true, "address_family": true, "bind_semantics": true, "port_start": true, "port_end": true, "process_ownership_required": true},
	"/claims/*":                                              {"claim_id": true, "statement_code": true, "level": true, "subject_entity_ids": true, "branch_ids": true, "parameters": true, "supporting_evidence": true, "contradicting_evidence": true, "required_missing_evidence": true, "rule_id": true},
	"/claims/*/supporting_evidence/*":                        {"kind": true, "id": true},
	"/claims/*/contradicting_evidence/*":                     {"kind": true, "id": true},
	"/claims/*/required_missing_evidence/*/visibility_scope": {"kind": true, "namespace_entity_id": true, "protocol": true, "address_family": true, "bind_semantics": true, "port_start": true, "port_end": true, "process_ownership_required": true},
	"/findings/*":                                            {"finding_id": true, "kind": true, "title_code": true, "level": true, "branch_ids": true, "path_positions": true, "claim_ids": true, "rule_id": true, "limitations": true, "suggested_experiments": true, "selection": true},
	"/findings/*/path_positions/*":                           {"branch_id": true, "position": true},
	"/evaluation":                                            {"evaluated_at": true, "ordered_rule_ids": true},
}

var wireUnionShape = map[string]map[string]map[string]bool{
	"/vantage_points/*/identity": {
		"CLIENT_NETWORK":      {"kind": true, "label": true},
		"HOST_NAMESPACE":      {"kind": true, "namespace_inode": true},
		"CONTAINER_NAMESPACE": {"kind": true, "daemon_id": true, "container_id": true},
		"UNKNOWN_NAMESPACE":   {"kind": true, "reason_code": true},
	},
	"/operator_assertions/*/parameters": {
		"LOCAL_ORIGIN_PARTICIPATION":          {"kind": true, "url_target_entity_id": true, "host_vantage_id": true},
		"EXPECTED_PATH_EDGE":                  {"kind": true, "from_entity_id": true, "to_entity_id": true, "relation": true},
		"HTTP_EXPECTATION":                    {"kind": true, "expectation_kind": true, "status_min": true, "status_max": true, "header_name": true},
		"CONFIG_SOURCE_SELECTION":             {"kind": true, "component_kind": true, "source_kind": true},
		"PRIVATE_REDIRECT_TRANSITION_ALLOWED": {"kind": true, "from_address_scope": true, "to_address_scope": true},
	},
	"/entities/*/identity": {
		"URL_TARGET":        {"kind": true, "marker": true},
		"HOSTNAME":          {"kind": true, "hostname": true},
		"IP_ADDRESS":        {"kind": true, "address": true},
		"SOCKET_ENDPOINT":   {"kind": true, "endpoint": true},
		"TLS_PEER":          {"kind": true, "fingerprint": true},
		"HTTP_EXCHANGE":     {"kind": true, "ordinal": true},
		"PROXY_INSTANCE":    {"kind": true, "synthetic_id": true},
		"PROXY_ROUTE":       {"kind": true, "synthetic_id": true},
		"UPSTREAM_ENDPOINT": {"kind": true, "endpoint": true},
		"LISTENER":          {"kind": true, "endpoint": true},
		"PROCESS":           {"kind": true, "pid": true},
		"CONTAINER":         {"kind": true, "runtime_id": true, "container_id": true},
		"NETWORK_NAMESPACE": {"kind": true, "namespace_inode": true},
	},
	"/check_definitions/*/inputs": {
		"SUBJECT":        {"kind": true, "subject_entity_id": true},
		"NETWORK":        {"kind": true, "subject_entity_id": true, "vantage_id": true},
		"WITH_ASSERTION": {"kind": true, "subject_entity_id": true, "assertion_id": true},
	},
	"/check_definitions/*/expected_condition": {
		"RESULT":           {"kind": true, "result": true},
		"FAMILY":           {"kind": true, "address_family": true},
		"PORT":             {"kind": true, "port": true},
		"HOSTNAME":         {"kind": true, "hostname": true},
		"STATUS_RANGE":     {"kind": true, "status_min": true, "status_max": true},
		"MATCHER_RESULT":   {"kind": true, "matcher_result": true},
		"CAPABILITY_STATE": {"kind": true, "capability_state": true},
	},
	"/observations/*/payload": {
		"SYSTEM_RESOLUTION_RESULT":        {"kind": true, "hostname_entity_id": true, "address_entity_id": true, "address_family": true, "result": true},
		"TCP_CONNECTION_RESULT":           {"kind": true, "endpoint_entity_id": true, "result": true, "duration_ns": true, "deadline_part_of_expected_condition": true},
		"TLS_TRANSPORT_RESULT":            {"kind": true, "peer_entity_id": true, "result": true, "protocol_version": true, "cipher_suite": true, "negotiated_alpn": true, "sni_sent": true, "alert_code": true, "duration_ns": true},
		"TLS_PEER_SUMMARY":                {"kind": true, "peer_entity_id": true, "certificate_count": true, "leaf_sha256": true, "not_before": true, "not_after": true, "san_type": true, "san_count": true},
		"CERTIFICATE_VERIFICATION_RESULT": {"kind": true, "peer_entity_id": true, "verified_hostname": true, "verification_time": true, "trust_source": true, "result": true, "failure_reason": true},
		"HTTP_RESULT":                     {"kind": true, "exchange_entity_id": true, "result_kind": true, "status_code": true, "redirect_target_entity_id": true, "redirect_target": true},
		"ACTIVE_PROXY_ROUTE_SUMMARY":      {"kind": true, "proxy_route_entity_id": true, "upstream_entity_id": true, "matcher_kind": true, "match_result": true},
		"CONFIGURED_PROXY_ROUTE_SUMMARY":  {"kind": true, "proxy_route_entity_id": true, "upstream_entity_id": true, "matcher_kind": true, "match_result": true},
		"UPSTREAM_SELECTION_SUMMARY":      {"kind": true, "proxy_route_entity_id": true, "upstream_entity_id": true, "result": true},
		"LISTENER_INVENTORY_ENTRY":        {"kind": true, "listener_entity_id": true, "namespace_entity_id": true, "protocol": true, "address_family": true, "bind_semantics": true, "port": true},
		"LISTENER_INVENTORY_RESULT":       {"kind": true, "namespace_entity_id": true, "protocol": true, "address_family": true, "bind_semantics": true, "port_start": true, "port_end": true, "matching_listener_count": true},
		"PROCESS_OWNERSHIP_ENTRY":         {"kind": true, "listener_entity_id": true, "process_entity_id": true, "result": true},
		"DOCKER_RUNTIME_SUMMARY":          {"kind": true, "fact_kind": true, "container_entity_id": true, "namespace_entity_id": true, "endpoint_entity_id": true, "runtime_state": true},
		"CAPABILITY_PERMISSION_RESULT":    {"kind": true, "capability_id": true, "result": true, "reason_code": true},
	},
	"/claims/*/parameters": {
		"TLS_CERTIFICATE_HOSTNAME_MISMATCH": {"kind": true, "peer_entity_id": true, "hostname": true, "verification_time": true, "trust_source": true},
		"TCP_CONNECTION_REFUSED":            {"kind": true, "endpoint_entity_id": true, "vantage_id": true, "observed_at": true},
		"NO_MATCHING_LISTENER_VISIBLE":      {"kind": true, "namespace_entity_id": true, "vantage_id": true, "protocol": true, "address_family": true, "bind_semantics": true, "port": true},
	},
	"/claims/*/required_missing_evidence/*": {
		"OBSERVATION_REQUIRED": {"kind": true, "observation_kind": true},
		"VISIBILITY_REQUIRED":  {"kind": true, "visibility_subject_kind": true, "visibility_scope": true},
		"VANTAGE_REQUIRED":     {"kind": true, "vantage_id": true},
	},
	"/service_path/edges/*/evidence_refs/*": {
		"OBSERVATION": {"kind": true, "id": true},
		"CLAIM":       {"kind": true, "id": true},
		"VISIBILITY":  {"kind": true, "id": true},
		"ASSERTION":   {"kind": true, "id": true},
	},
	"/claims/*/supporting_evidence/*": {
		"OBSERVATION": {"kind": true, "id": true},
		"CLAIM":       {"kind": true, "id": true},
		"VISIBILITY":  {"kind": true, "id": true},
		"ASSERTION":   {"kind": true, "id": true},
	},
	"/claims/*/contradicting_evidence/*": {
		"OBSERVATION": {"kind": true, "id": true},
		"CLAIM":       {"kind": true, "id": true},
		"VISIBILITY":  {"kind": true, "id": true},
		"ASSERTION":   {"kind": true, "id": true},
	},
	"/limitations/*/scope": {
		"RUN": {"kind": true}, "VANTAGE": {"kind": true, "vantage_id": true}, "OBSERVATION": {"kind": true, "observation_id": true}, "VISIBILITY": {"kind": true, "visibility_id": true}, "FINDING": {"kind": true, "finding_id": true},
	},
	"/limitation/scope": {
		"RUN": {"kind": true}, "VANTAGE": {"kind": true, "vantage_id": true}, "OBSERVATION": {"kind": true, "observation_id": true}, "VISIBILITY": {"kind": true, "visibility_id": true}, "FINDING": {"kind": true, "finding_id": true},
	},
	"/vantage_points/*/limitations/*/scope": {
		"RUN": {"kind": true}, "VANTAGE": {"kind": true, "vantage_id": true}, "OBSERVATION": {"kind": true, "observation_id": true}, "VISIBILITY": {"kind": true, "visibility_id": true}, "FINDING": {"kind": true, "finding_id": true},
	},
	"/observations/*/limitations/*/scope": {
		"RUN": {"kind": true}, "VANTAGE": {"kind": true, "vantage_id": true}, "OBSERVATION": {"kind": true, "observation_id": true}, "VISIBILITY": {"kind": true, "visibility_id": true}, "FINDING": {"kind": true, "finding_id": true},
	},
	"/visibility_assessments/*/limitations/*/scope": {
		"RUN": {"kind": true}, "VANTAGE": {"kind": true, "vantage_id": true}, "OBSERVATION": {"kind": true, "observation_id": true}, "VISIBILITY": {"kind": true, "visibility_id": true}, "FINDING": {"kind": true, "finding_id": true},
	},
	"/findings/*/limitations/*/scope": {
		"RUN": {"kind": true}, "VANTAGE": {"kind": true, "vantage_id": true}, "OBSERVATION": {"kind": true, "observation_id": true}, "VISIBILITY": {"kind": true, "visibility_id": true}, "FINDING": {"kind": true, "finding_id": true},
	},
}

// wireUnionRequired is the required-member half of the same closed union
// description. Required members are checked by the decoder as structural
// errors; semantic constraints remain in internal/model.
var wireUnionRequired = map[string]map[string][]string{
	"/vantage_points/*/identity": {
		"CLIENT_NETWORK":      {"kind", "label"},
		"HOST_NAMESPACE":      {"kind", "namespace_inode"},
		"CONTAINER_NAMESPACE": {"kind", "daemon_id", "container_id"},
		"UNKNOWN_NAMESPACE":   {"kind", "reason_code"},
	},
	"/operator_assertions/*/parameters": {
		"LOCAL_ORIGIN_PARTICIPATION":          {"kind", "url_target_entity_id", "host_vantage_id"},
		"EXPECTED_PATH_EDGE":                  {"kind", "from_entity_id", "to_entity_id", "relation"},
		"HTTP_EXPECTATION":                    {"kind", "expectation_kind"},
		"CONFIG_SOURCE_SELECTION":             {"kind", "component_kind", "source_kind"},
		"PRIVATE_REDIRECT_TRANSITION_ALLOWED": {"kind", "from_address_scope", "to_address_scope"},
	},
	"/entities/*/identity": {
		"URL_TARGET":        {"kind", "marker"},
		"HOSTNAME":          {"kind", "hostname"},
		"IP_ADDRESS":        {"kind", "address"},
		"SOCKET_ENDPOINT":   {"kind", "endpoint"},
		"TLS_PEER":          {"kind", "fingerprint"},
		"HTTP_EXCHANGE":     {"kind", "ordinal"},
		"PROXY_INSTANCE":    {"kind", "synthetic_id"},
		"PROXY_ROUTE":       {"kind", "synthetic_id"},
		"UPSTREAM_ENDPOINT": {"kind", "endpoint"},
		"LISTENER":          {"kind", "endpoint"},
		"PROCESS":           {"kind", "pid"},
		"CONTAINER":         {"kind", "runtime_id", "container_id"},
		"NETWORK_NAMESPACE": {"kind", "namespace_inode"},
	},
	"/check_definitions/*/inputs": {
		"SUBJECT":        {"kind", "subject_entity_id"},
		"NETWORK":        {"kind", "subject_entity_id", "vantage_id"},
		"WITH_ASSERTION": {"kind", "subject_entity_id", "assertion_id"},
	},
	"/check_definitions/*/expected_condition": {
		"RESULT":           {"kind", "result"},
		"FAMILY":           {"kind", "address_family"},
		"PORT":             {"kind", "port"},
		"HOSTNAME":         {"kind", "hostname"},
		"STATUS_RANGE":     {"kind", "status_min", "status_max"},
		"MATCHER_RESULT":   {"kind", "matcher_result"},
		"CAPABILITY_STATE": {"kind", "capability_state"},
	},
	"/observations/*/payload": {
		"SYSTEM_RESOLUTION_RESULT":        {"kind", "hostname_entity_id", "address_family", "result"},
		"TCP_CONNECTION_RESULT":           {"kind", "endpoint_entity_id", "result", "duration_ns", "deadline_part_of_expected_condition"},
		"TLS_TRANSPORT_RESULT":            {"kind", "peer_entity_id", "result", "duration_ns"},
		"TLS_PEER_SUMMARY":                {"kind", "peer_entity_id", "certificate_count", "leaf_sha256", "not_before", "not_after", "san_type", "san_count"},
		"CERTIFICATE_VERIFICATION_RESULT": {"kind", "peer_entity_id", "verified_hostname", "verification_time", "trust_source", "result"},
		"HTTP_RESULT":                     {"kind", "exchange_entity_id", "result_kind", "status_code"},
		"ACTIVE_PROXY_ROUTE_SUMMARY":      {"kind", "proxy_route_entity_id", "matcher_kind", "match_result"},
		"CONFIGURED_PROXY_ROUTE_SUMMARY":  {"kind", "proxy_route_entity_id", "matcher_kind", "match_result"},
		"UPSTREAM_SELECTION_SUMMARY":      {"kind", "proxy_route_entity_id", "result"},
		"LISTENER_INVENTORY_ENTRY":        {"kind", "listener_entity_id", "namespace_entity_id", "protocol", "address_family", "bind_semantics", "port"},
		"LISTENER_INVENTORY_RESULT":       {"kind", "namespace_entity_id", "protocol", "address_family", "bind_semantics", "port_start", "port_end", "matching_listener_count"},
		"PROCESS_OWNERSHIP_ENTRY":         {"kind", "listener_entity_id", "result"},
		"DOCKER_RUNTIME_SUMMARY":          {"kind", "fact_kind", "container_entity_id", "runtime_state"},
		"CAPABILITY_PERMISSION_RESULT":    {"kind", "capability_id", "result", "reason_code"},
	},
	"/claims/*/parameters": {
		"TLS_CERTIFICATE_HOSTNAME_MISMATCH": {"kind", "peer_entity_id", "hostname", "verification_time", "trust_source"},
		"TCP_CONNECTION_REFUSED":            {"kind", "endpoint_entity_id", "vantage_id", "observed_at"},
		"NO_MATCHING_LISTENER_VISIBLE":      {"kind", "namespace_entity_id", "vantage_id", "protocol", "address_family", "bind_semantics", "port"},
	},
	"/claims/*/required_missing_evidence/*": {
		"OBSERVATION_REQUIRED": {"kind", "observation_kind"},
		"VISIBILITY_REQUIRED":  {"kind", "visibility_subject_kind", "visibility_scope"},
		"VANTAGE_REQUIRED":     {"kind", "vantage_id"},
	},
	"/service_path/edges/*/evidence_refs/*": {
		"OBSERVATION": {"kind", "id"}, "CLAIM": {"kind", "id"}, "VISIBILITY": {"kind", "id"}, "ASSERTION": {"kind", "id"},
	},
	"/claims/*/supporting_evidence/*": {
		"OBSERVATION": {"kind", "id"}, "CLAIM": {"kind", "id"}, "VISIBILITY": {"kind", "id"}, "ASSERTION": {"kind", "id"},
	},
	"/claims/*/contradicting_evidence/*": {
		"OBSERVATION": {"kind", "id"}, "CLAIM": {"kind", "id"}, "VISIBILITY": {"kind", "id"}, "ASSERTION": {"kind", "id"},
	},
	"/limitations/*/scope": {
		"RUN": {"kind"}, "VANTAGE": {"kind", "vantage_id"}, "OBSERVATION": {"kind", "observation_id"}, "VISIBILITY": {"kind", "visibility_id"}, "FINDING": {"kind", "finding_id"},
	},
	"/limitation/scope": {
		"RUN": {"kind"}, "VANTAGE": {"kind", "vantage_id"}, "OBSERVATION": {"kind", "observation_id"}, "VISIBILITY": {"kind", "visibility_id"}, "FINDING": {"kind", "finding_id"},
	},
	"/vantage_points/*/limitations/*/scope": {
		"RUN": {"kind"}, "VANTAGE": {"kind", "vantage_id"}, "OBSERVATION": {"kind", "observation_id"}, "VISIBILITY": {"kind", "visibility_id"}, "FINDING": {"kind", "finding_id"},
	},
	"/observations/*/limitations/*/scope": {
		"RUN": {"kind"}, "VANTAGE": {"kind", "vantage_id"}, "OBSERVATION": {"kind", "observation_id"}, "VISIBILITY": {"kind", "visibility_id"}, "FINDING": {"kind", "finding_id"},
	},
	"/visibility_assessments/*/limitations/*/scope": {
		"RUN": {"kind"}, "VANTAGE": {"kind", "vantage_id"}, "OBSERVATION": {"kind", "observation_id"}, "VISIBILITY": {"kind", "visibility_id"}, "FINDING": {"kind", "finding_id"},
	},
	"/findings/*/limitations/*/scope": {
		"RUN": {"kind"}, "VANTAGE": {"kind", "vantage_id"}, "OBSERVATION": {"kind", "observation_id"}, "VISIBILITY": {"kind", "visibility_id"}, "FINDING": {"kind", "finding_id"},
	},
}

func wireFields(pointer string, object map[string]json.RawMessage) (map[string]bool, bool) {
	p := normalizePointer(pointer)
	if cases, ok := wireUnionShape[p]; ok {
		raw, exists := object["kind"]
		if !exists {
			return nil, true
		}
		var kind string
		if err := json.Unmarshal(raw, &kind); err != nil {
			return nil, true
		}
		fields, known := cases[kind]
		if !known {
			return nil, true
		}
		return fields, false
	}
	return wireShape[p], false
}

func wireRequiredFields(pointer string, object map[string]json.RawMessage) ([]string, bool) {
	p := normalizePointer(pointer)
	if cases, ok := wireUnionRequired[p]; ok {
		raw, exists := object["kind"]
		if !exists {
			return nil, false
		}
		var kind string
		if err := json.Unmarshal(raw, &kind); err != nil {
			return nil, false
		}
		required, known := cases[kind]
		return required, known
	}
	return nil, false
}

func wireEnumValues(pointer, key string, object map[string]json.RawMessage) []string {
	p := normalizePointer(pointer)
	if key == "kind" {
		if cases, ok := wireUnionShape[p]; ok {
			values := make([]string, 0, len(cases))
			for value := range cases {
				values = append(values, value)
			}
			return values
		}
	}
	values := map[string][]string{
		"/goal/kind":                                                    {"HTTP_RESPONSE", "HTTP_EXPECTATION", "ORIGIN_PATH_DIAGNOSIS"},
		"/requested_scope/kind":                                         {"CLIENT_ONLY", "LOCAL_ORIGIN"},
		"/vantage_points/*/kind":                                        {"CLIENT_NETWORK", "HOST_NAMESPACE", "CONTAINER_NAMESPACE", "UNKNOWN_NAMESPACE"},
		"/vantage_points/*/role":                                        {"CLIENT", "ORIGIN_HOST", "PROXY", "UPSTREAM", "UNSPECIFIED"},
		"/vantage_points/*/establishment":                               {"DIRECTLY_OBSERVED", "OPERATOR_SUPPLIED", "RUNTIME_CORRELATED", "UNKNOWN"},
		"/capabilities/*/kind":                                          {"SYSTEM_RESOLUTION", "TCP_PROBE", "TLS_PROBE", "HTTP_PROBE", "LISTENER_INVENTORY", "PROCESS_OWNERSHIP", "ACTIVE_CADDY", "CONFIGURED_CADDY", "DOCKER"},
		"/capabilities/*/state":                                         {"AVAILABLE", "UNAVAILABLE", "DENIED", "UNKNOWN"},
		"/operator_assertions/*/kind":                                   {"LOCAL_ORIGIN_PARTICIPATION", "EXPECTED_PATH_EDGE", "HTTP_EXPECTATION", "CONFIG_SOURCE_SELECTION", "PRIVATE_REDIRECT_TRANSITION_ALLOWED"},
		"/operator_assertions/*/source":                                 {"COMMAND_LINE", "EXPLICIT_CONFIG", "SYNTHETIC_FIXTURE"},
		"/operator_assertions/*/parameters/expectation_kind":            {"STATUS_RANGE", "HEADER_PRESENT"},
		"/operator_assertions/*/parameters/relation":                    {"RESOLVES_TO", "CONNECTS_TO", "NEGOTIATES_TLS_WITH", "VERIFIES", "REQUESTS_HTTP_FROM", "REDIRECTS_TO", "ROUTES_TO", "SELECTS_UPSTREAM", "LISTENS_ON", "OWNED_BY", "ASSOCIATED_WITH"},
		"/operator_assertions/*/parameters/component_kind":              {"CADDY", "DOCKER"},
		"/operator_assertions/*/parameters/source_kind":                 {"ACTIVE_API", "EXPLICIT_FILE", "ENGINE_ENDPOINT"},
		"/entities/*/kind":                                              {"URL_TARGET", "HOSTNAME", "IP_ADDRESS", "SOCKET_ENDPOINT", "TLS_PEER", "HTTP_EXCHANGE", "PROXY_INSTANCE", "PROXY_ROUTE", "UPSTREAM_ENDPOINT", "LISTENER", "PROCESS", "CONTAINER", "NETWORK_NAMESPACE"},
		"/entities/*/identity/endpoint/transport":                       {"TCP", "UDP"},
		"/service_path/edges/*/relation":                                {"RESOLVES_TO", "CONNECTS_TO", "NEGOTIATES_TLS_WITH", "VERIFIES", "REQUESTS_HTTP_FROM", "REDIRECTS_TO", "ROUTES_TO", "SELECTS_UPSTREAM", "LISTENS_ON", "OWNED_BY", "ASSOCIATED_WITH"},
		"/service_path/edges/*/provenance":                              {"OPERATOR_ASSERTED", "DIRECTLY_OBSERVED", "ACTIVE_RUNTIME_CONFIG", "CONFIGURED_INTENT"},
		"/service_path/branches/*/goal":                                 {"HTTP_RESPONSE", "HTTP_EXPECTATION", "ORIGIN_PATH_DIAGNOSIS"},
		"/check_definitions/*/kind":                                     {"SYSTEM_RESOLUTION", "TCP_CONNECTION", "TLS_TRANSPORT", "TLS_PEER", "CERTIFICATE_VERIFICATION", "HTTP", "ACTIVE_PROXY_ROUTE", "CONFIGURED_PROXY_ROUTE", "UPSTREAM_SELECTION", "LISTENER_INVENTORY", "PROCESS_OWNERSHIP", "DOCKER_RUNTIME", "CAPABILITY_PERMISSION"},
		"/check_executions/*/lifecycle":                                 {"NOT_RUN", "COMPLETED", "UNAVAILABLE", "DENIED", "TIMED_OUT", "ERROR"},
		"/check_executions/*/verdict":                                   {"PASS", "FAIL", "UNKNOWN", "SKIPPED"},
		"/check_definitions/*/expected_condition/matcher_result":        {"MATCHED", "NOT_MATCHED", "UNKNOWN"},
		"/check_definitions/*/expected_condition/capability_state":      {"AVAILABLE", "UNAVAILABLE", "DENIED", "UNKNOWN"},
		"/observations/*/kind":                                          {"SYSTEM_RESOLUTION_RESULT", "TCP_CONNECTION_RESULT", "TLS_TRANSPORT_RESULT", "TLS_PEER_SUMMARY", "CERTIFICATE_VERIFICATION_RESULT", "HTTP_RESULT", "ACTIVE_PROXY_ROUTE_SUMMARY", "CONFIGURED_PROXY_ROUTE_SUMMARY", "UPSTREAM_SELECTION_SUMMARY", "LISTENER_INVENTORY_ENTRY", "LISTENER_INVENTORY_RESULT", "PROCESS_OWNERSHIP_ENTRY", "DOCKER_RUNTIME_SUMMARY", "CAPABILITY_PERMISSION_RESULT"},
		"/observations/*/acquisition_method":                            {"DIRECT_PROBE", "ACTIVE_RUNTIME_API", "CONFIGURED_INTENT_SOURCE", "SYSTEM_INSPECTION", "SYNTHETIC_FIXTURE"},
		"/observations/*/source_component":                              {"SYSTEM_RESOLVER", "TCP_PROBE", "TLS_PROBE", "CERTIFICATE_VERIFIER", "HTTP_PROBE", "CADDY_ADAPTER", "SOCKET_INSPECTOR", "PROCESS_INSPECTOR", "DOCKER_ADAPTER", "SYNTHETIC_FIXTURE"},
		"/observations/*/sensitivity":                                   {"PUBLIC", "SANITIZED_DERIVED"},
		"/visibility_assessments/*/subject_kind":                        {"LISTENER"},
		"/visibility_assessments/*/level":                               {"COMPLETE_FOR_SCOPE", "PARTIAL", "UNKNOWN", "NOT_APPLICABLE"},
		"/claims/*/statement_code":                                      {"TLS_CERTIFICATE_HOSTNAME_MISMATCH", "TCP_CONNECTION_REFUSED", "NO_MATCHING_LISTENER_VISIBLE"},
		"/claims/*/level":                                               {"OBSERVED", "INFERRED", "SUSPECTED"},
		"/findings/*/kind":                                              {"BLOCKER", "EXPECTATION_FAILURE", "PARTIAL_REACHABILITY", "ADVISORY", "LIMITATION"},
		"/findings/*/title_code":                                        {"TLS_CERTIFICATE_HOSTNAME_MISMATCH", "TCP_CONNECTION_REFUSED", "NO_MATCHING_LISTENER_VISIBLE"},
		"/findings/*/level":                                             {"OBSERVED", "INFERRED", "SUSPECTED"},
		"/findings/*/selection":                                         {"GLOBAL_PRIMARY", "BRANCH_PRIMARY", "ADDITIONAL", "NONE"},
		"/limitations/*/code":                                           {"insufficient_privilege", "tls_peer_unverified", "unsupported_capability", "unknown_vantage", "partial_visibility", "skipped_dependency", "generic"},
		"/visibility_assessments/*/scope/kind":                          {"LISTENER"},
		"/claims/*/parameters/trust_source":                             {"SYSTEM", "EXPLICIT", "UNKNOWN"},
		"/claims/*/required_missing_evidence/*/observation_kind":        {"SYSTEM_RESOLUTION_RESULT", "TCP_CONNECTION_RESULT", "TLS_TRANSPORT_RESULT", "TLS_PEER_SUMMARY", "CERTIFICATE_VERIFICATION_RESULT", "HTTP_RESULT", "ACTIVE_PROXY_ROUTE_SUMMARY", "CONFIGURED_PROXY_ROUTE_SUMMARY", "UPSTREAM_SELECTION_SUMMARY", "LISTENER_INVENTORY_ENTRY", "LISTENER_INVENTORY_RESULT", "PROCESS_OWNERSHIP_ENTRY", "DOCKER_RUNTIME_SUMMARY", "CAPABILITY_PERMISSION_RESULT"},
		"/claims/*/required_missing_evidence/*/visibility_subject_kind": {"LISTENER"},
		"/claims/*/required_missing_evidence/*/visibility_scope/kind":   {"LISTENER"},
		"/observations/*/payload/san_type":                              {"DNS", "IP", "OTHER"},
		"/observations/*/payload/trust_source":                          {"SYSTEM", "EXPLICIT", "UNKNOWN"},
		"/observations/*/payload/failure_reason":                        {"VERIFIED", "HOSTNAME_MISMATCH", "EXPIRED", "NOT_YET_VALID", "UNTRUSTED_ISSUER", "INVALID_USAGE", "VERIFIER_UNAVAILABLE"},
		"/observations/*/payload/fact_kind":                             {"CONTAINER_STATE", "NETWORK_MEMBERSHIP", "PUBLISHED_PORT"},
		"/observations/*/payload/runtime_state":                         {"RUNNING", "STOPPED", "UNKNOWN"},
		"/target/scheme":                                                {"http", "https"},
	}
	if values, ok := values[p+"/"+key]; ok {
		return values
	}
	if p == "/observations/*/payload" {
		var kind string
		if raw, ok := object["kind"]; ok && json.Unmarshal(raw, &kind) == nil {
			resultValues := map[string][]string{
				"SYSTEM_RESOLUTION_RESULT":        {"RESOLVED", "NO_RESULT", "FAILED"},
				"TCP_CONNECTION_RESULT":           {"ACCEPTED", "REFUSED", "TIMED_OUT", "FAILED"},
				"TLS_TRANSPORT_RESULT":            {"COMPLETED", "FAILED", "TIMED_OUT"},
				"CERTIFICATE_VERIFICATION_RESULT": {"VERIFIED", "HOSTNAME_MISMATCH", "EXPIRED", "NOT_YET_VALID", "UNTRUSTED_ISSUER", "INVALID_USAGE", "VERIFIER_UNAVAILABLE"},
				"UPSTREAM_SELECTION_SUMMARY":      {"SELECTED", "AMBIGUOUS", "UNAVAILABLE"},
				"PROCESS_OWNERSHIP_ENTRY":         {"OWNED", "UNRESOLVED"},
				"HTTP_RESULT":                     {"RESPONSE", "REDIRECT"},
				"ACTIVE_PROXY_ROUTE_SUMMARY":      {"MATCHED", "NOT_MATCHED", "UNKNOWN"},
				"CONFIGURED_PROXY_ROUTE_SUMMARY":  {"MATCHED", "NOT_MATCHED", "UNKNOWN"},
				"CAPABILITY_PERMISSION_RESULT":    {"AVAILABLE", "UNAVAILABLE", "DENIED", "UNKNOWN"},
			}
			if key == "result" || key == "result_kind" || key == "match_result" {
				return resultValues[kind]
			}
		}
	}
	if key == "protocol" {
		return []string{"TCP", "UDP"}
	}
	if key == "address_family" {
		return []string{"IPV4", "IPV6"}
	}
	if key == "bind_semantics" {
		return []string{"EXACT", "WILDCARD", "LOOPBACK"}
	}
	return nil
}

func pointerValue(pointer string, index int) string {
	return pointer + "/" + strconv.Itoa(index)
}
