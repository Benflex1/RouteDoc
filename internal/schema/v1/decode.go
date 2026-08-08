package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"routedoc/internal/model"
)

func Decode(data []byte, op Operation) (DecodedReport, model.ValidationIssues) {
	var out DecodedReport
	top, scanIssues := scanDocument(data)
	for _, issue := range scanIssues {
		if issue.Code != model.CodeUnknownField && issue.Code != model.CodeNewerMinorFieldIgnored {
			return out, model.ValidationIssues{issue}
		}
	}
	raw, ok := top["report_schema_version"]
	if !ok {
		return out, model.ValidationIssues{{Code: model.CodeMissingRequiredField, Pointer: "/report_schema_version", Message: "report schema version is required"}}
	}
	var versionText string
	if err := json.Unmarshal(raw, &versionText); err != nil {
		return out, model.ValidationIssues{{Code: model.CodeInvalidValue, Pointer: "/report_schema_version", Message: "version must be a string"}}
	}
	v, err := model.ParseSchemaVersion(versionText)
	if err != nil {
		return out, model.ValidationIssues{{Code: model.CodeInvalidValue, Pointer: "/report_schema_version", Message: err.Error()}}
	}
	out.Version = v
	out.Exact = v == (model.SchemaVersion{Major: 1, Minor: 0, Patch: 0})
	if v.Major != 1 {
		return out, model.ValidationIssues{{Code: model.CodeUnsupportedMajor, Pointer: "/report_schema_version", Message: "unsupported schema major"}}
	}
	if !out.Exact && (op == CanonicalJSON || op == Reevaluate) {
		return out, model.ValidationIssues{{Code: model.CodeExactVersionRequired, Pointer: "/report_schema_version", Message: "operation requires exact schema version"}}
	}
	if out.Exact {
		for _, issue := range scanIssues {
			if issue.Code == model.CodeUnknownField {
				return out, model.ValidationIssues{issue}
			}
		}
	}
	for _, required := range []string{"producer", "run_id", "target", "goal", "requested_scope", "policy", "started_at", "finished_at", "vantage_points", "capabilities", "operator_assertions", "entities", "service_path", "check_definitions", "check_executions", "observations", "visibility_assessments", "evaluation", "claims", "findings", "limitations"} {
		if _, ok := top[required]; !ok {
			return out, model.ValidationIssues{{Code: model.CodeMissingRequiredField, Pointer: "/" + required, Message: "required member is missing"}}
		}
	}
	minor := v.Minor > 0
	_, scanWarnings := scanWithMode(data, minor)
	if len(scanWarnings) > 0 {
		if minor {
			out.Warnings = scanWarnings
		} else {
			return out, scanWarnings
		}
	}
	var wr wReport
	if err := json.Unmarshal(data, &wr); err != nil {
		return out, model.ValidationIssues{{Code: model.CodeInvalidJSON, Pointer: "/", Message: err.Error()}}
	}
	var conv model.ValidationIssues
	out.Run, conv = toModel(wr, &conv)
	out.Run.Evidence.ReportSchemaVersion = model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}
	if len(conv) > 0 {
		return out, conv
	}
	if !out.Run.Evidence.Goal.Kind.Valid() {
		return out, model.ValidationIssues{{Code: model.CodeUnknownEnumValue, Pointer: "/goal/kind", Message: "unknown goal enum"}}
	}
	return out, nil
}

func scanDocument(data []byte) (map[string]json.RawMessage, model.ValidationIssues) {
	return scanWithMode(data, false)
}
func scanWithMode(data []byte, newerMinor bool) (map[string]json.RawMessage, model.ValidationIssues) {
	var is model.ValidationIssues
	var root map[string]json.RawMessage
	var err error
	root, err = scanObject(data, "", newerMinor, &is)
	if err != nil {
		is = append(is, model.ValidationIssue{Code: model.CodeInvalidJSON, Pointer: "/", Message: err.Error()})
		return nil, is
	}
	return root, is
}
func scanObject(data []byte, pointer string, newerMinor bool, is *model.ValidationIssues) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	var tok interface{}
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	if tok != json.Delim('{') {
		return nil, fmt.Errorf("object expected")
	}
	out := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := t.(string)
		if !ok {
			return nil, fmt.Errorf("object member must be string")
		}
		raw := json.RawMessage{}
		if err := d.Decode(&raw); err != nil {
			return nil, err
		}
		child := pointer + "/" + escapePointer(key)
		if seen[key] {
			*is = append(*is, model.ValidationIssue{Code: model.CodeDuplicateField, Pointer: child, Message: "duplicate object member"})
		}
		seen[key] = true
		if allowed := allowedFields(pointer, out); allowed != nil && !allowed[key] {
			code := model.CodeUnknownField
			if newerMinor {
				code = model.CodeNewerMinorFieldIgnored
			}
			*is = append(*is, model.ValidationIssue{Code: code, Pointer: child, Message: "unknown member"})
		}
		out[key] = raw
		if err := scanNested(raw, child, newerMinor, is); err != nil {
			return nil, err
		}
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	return out, nil
}
func scanNested(raw json.RawMessage, pointer string, newerMinor bool, is *model.ValidationIssues) error {
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 {
		return fmt.Errorf("empty JSON value")
	}
	switch trim[0] {
	case '{':
		_, err := scanObject(trim, pointer, newerMinor, is)
		return err
	case '[':
		var vals []json.RawMessage
		if err := json.Unmarshal(trim, &vals); err != nil {
			return err
		}
		for i, v := range vals {
			if err := scanNested(v, pointer+"/"+strconv.Itoa(i), newerMinor, is); err != nil {
				return err
			}
		}
	}
	return nil
}
func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
func normalizePointer(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		if _, err := strconv.Atoi(parts[i]); err == nil {
			parts[i] = "*"
		}
	}
	return strings.Join(parts, "/")
}
func allowedFields(pointer string, object map[string]json.RawMessage) map[string]bool {
	p := normalizePointer(pointer)
	sets := map[string][]string{"": {"report_schema_version", "producer", "run_id", "target", "goal", "requested_scope", "policy", "started_at", "finished_at", "vantage_points", "capabilities", "operator_assertions", "entities", "service_path", "check_definitions", "check_executions", "observations", "visibility_assessments", "evaluation", "claims", "findings", "limitations"}, "/producer": {"name", "version", "build"}, "/target": {"scheme", "hostname", "effective_port", "path"}, "/target/path": {"present", "is_root", "segment_count", "trailing_slash", "query_present"}, "/goal": {"kind", "expectation_assertion_id"}, "/requested_scope": {"kind"}, "/policy": {"coherence_window_ns"}, "/limitation": {"limitation_id", "code", "scope"}, "/limitation/scope": {"kind", "vantage_id", "observation_id", "visibility_id", "finding_id"}, "/vantage_points/*": {"vantage_id", "kind", "role", "display_label", "identity", "parent_vantage_id", "establishment", "limitations"}, "/vantage_points/*/identity": {"kind", "label", "namespace_inode", "daemon_id", "container_id", "reason_code"}, "/capabilities/*": {"capability_id", "kind", "state", "reason_code"}, "/operator_assertions/*": {"assertion_id", "kind", "parameters", "established_at", "source"}, "/operator_assertions/*/parameters": {"kind", "url_target_entity_id", "host_vantage_id", "from_entity_id", "to_entity_id", "relation", "expectation_kind", "status_min", "status_max", "header_name", "component_kind", "source_kind", "from_address_scope", "to_address_scope"}, "/entities/*": {"entity_id", "kind", "display_label", "identity"}, "/entities/*/identity": {"kind", "marker", "hostname", "address", "port", "transport", "fingerprint", "ordinal", "synthetic_id", "endpoint", "pid", "runtime_id", "container_id", "namespace_inode"}, "/entities/*/identity/endpoint": {"address", "port", "transport"}, "/service_path": {"nodes", "edges", "branches"}, "/service_path/nodes/*": {"entity_id"}, "/service_path/edges/*": {"edge_id", "from", "to", "relation", "provenance", "evidence_refs"}, "/service_path/edges/*/evidence_refs/*": {"kind", "id"}, "/service_path/branches/*": {"branch_id", "parent_branch_id", "ordered_edge_ids", "goal"}, "/check_definitions/*": {"check_id", "kind", "version", "inputs", "dependency_check_ids", "required_capability_ids", "execution_policy", "expected_condition"}, "/check_definitions/*/inputs": {"kind", "subject_entity_id", "vantage_id", "assertion_id"}, "/check_definitions/*/execution_policy": {"deadline_ns", "dependency_failure_reason_code", "deadline_is_expected_condition"}, "/check_definitions/*/expected_condition": {"kind", "result", "address_family", "port", "hostname", "status_min", "status_max", "matcher_result", "capability_state"}, "/check_executions/*": {"execution_id", "check_id", "branch_id", "vantage_id", "started_at", "finished_at", "lifecycle", "verdict", "reason_code", "observation_ids", "visibility_assessment_ids"}, "/observations/*": {"observation_id", "kind", "subject_entity_ids", "vantage_id", "observed_at", "payload", "acquisition_method", "source_component", "sensitivity", "limitations"}, "/observations/*/payload": {"kind", "hostname_entity_id", "address_entity_id", "address_family", "result", "endpoint_entity_id", "duration_ns", "deadline_part_of_expected_condition", "peer_entity_id", "protocol_version", "cipher_suite", "negotiated_alpn", "sni_sent", "alert_code", "certificate_count", "leaf_sha256", "not_before", "not_after", "san_type", "san_count", "verified_hostname", "verification_time", "trust_source", "failure_reason", "exchange_entity_id", "result_kind", "status_code", "redirect_target_entity_id", "redirect_target", "proxy_route_entity_id", "upstream_entity_id", "matcher_kind", "match_result", "listener_entity_id", "namespace_entity_id", "protocol", "bind_semantics", "port", "process_entity_id", "fact_kind", "container_entity_id", "runtime_state", "capability_id", "reason_code"}, "/observations/*/payload/redirect_target": {"scheme", "hostname", "effective_port", "path"}, "/visibility_assessments/*": {"visibility_id", "subject_kind", "vantage_id", "scope", "level", "basis_observation_ids", "limitations", "assessed_at"}, "/visibility_assessments/*/scope": {"kind", "namespace_entity_id", "protocol", "address_family", "bind_semantics", "port_start", "port_end", "process_ownership_required"}, "/evaluation": {"evaluated_at", "ordered_rule_ids"}, "/claims/*": {"claim_id", "statement_code", "level", "subject_entity_ids", "branch_ids", "parameters", "supporting_evidence", "contradicting_evidence", "required_missing_evidence", "rule_id"}, "/claims/*/parameters": {"kind", "peer_entity_id", "hostname", "verification_time", "trust_source", "endpoint_entity_id", "vantage_id", "observed_at", "namespace_entity_id", "protocol", "address_family", "bind_semantics", "port"}, "/claims/*/supporting_evidence/*": {"kind", "id"}, "/claims/*/contradicting_evidence/*": {"kind", "id"}, "/claims/*/required_missing_evidence/*": {"kind", "observation_kind", "visibility_subject_kind", "visibility_scope", "vantage_id"}, "/findings/*": {"finding_id", "kind", "title_code", "level", "branch_ids", "path_positions", "claim_ids", "rule_id", "limitations", "suggested_experiments", "selection"}, "/findings/*/path_positions/*": {"branch_id", "position"}}
	v := sets[p]
	if v == nil {
		return nil
	}
	m := map[string]bool{}
	for _, x := range v {
		m[x] = true
	}
	return m
}
