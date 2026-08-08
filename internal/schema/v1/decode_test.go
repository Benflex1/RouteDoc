package v1

import (
	"testing"

	"routedoc/internal/model"
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
func hasDecodeCode(v model.ValidationIssues, c model.ValidationCode) bool {
	for _, i := range v {
		if i.Code == c {
			return true
		}
	}
	return false
}
