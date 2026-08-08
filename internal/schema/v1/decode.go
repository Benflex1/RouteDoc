package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
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
			for _, issue := range scanWarnings {
				if issue.Code != model.CodeNewerMinorFieldIgnored {
					return out, model.ValidationIssues{issue}
				}
			}
			sort.SliceStable(scanWarnings, func(i, j int) bool {
				if scanWarnings[i].Pointer != scanWarnings[j].Pointer {
					return scanWarnings[i].Pointer < scanWarnings[j].Pointer
				}
				return scanWarnings[i].Message < scanWarnings[j].Message
			})
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
	// Keep the claimed version on the projected model. Compatibility decoding
	// is read-only; rewriting it to 1.0.0 would make later model validation
	// indistinguishable from an exact report.
	out.Run.Evidence.ReportSchemaVersion = v
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
	keys := make([]string, 0)
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
		out[key] = raw
		keys = append(keys, key)
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	allowed, unionError := wireFields(pointer, out)
	if unionError {
		if _, ok := out["kind"]; !ok {
			*is = append(*is, model.ValidationIssue{Code: model.CodeMissingRequiredField, Pointer: pointer + "/kind", Message: "union kind is required"})
		} else {
			*is = append(*is, model.ValidationIssue{Code: model.CodeUnknownUnionKind, Pointer: pointer + "/kind", Message: "unknown union kind"})
		}
	}
	if !unionError {
		if required, known := wireRequiredFields(pointer, out); known {
			for _, key := range required {
				if _, exists := out[key]; !exists {
					*is = append(*is, model.ValidationIssue{Code: model.CodeMissingRequiredField, Pointer: pointer + "/" + escapePointer(key), Message: "required member is missing"})
				}
			}
		}
	}
	for _, key := range keys {
		child := pointer + "/" + escapePointer(key)
		if allowed != nil && !allowed[key] {
			code := model.CodeUnknownField
			if newerMinor {
				code = model.CodeNewerMinorFieldIgnored
			}
			*is = append(*is, model.ValidationIssue{Code: code, Pointer: child, Message: "unknown member"})
		}
		if values := wireEnumValues(pointer, key, out); len(values) > 0 && !(key == "kind" && wireUnionShape[normalizePointer(pointer)] != nil) {
			var value string
			if err := json.Unmarshal(out[key], &value); err != nil || !containsWireValue(values, value) {
				message := "unknown enum value"
				if child == "/goal/kind" {
					message = "unknown goal enum"
				}
				*is = append(*is, model.ValidationIssue{Code: model.CodeUnknownEnumValue, Pointer: child, Message: message})
			}
		}
		if err := scanNested(out[key], child, newerMinor, is); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func containsWireValue(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
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
