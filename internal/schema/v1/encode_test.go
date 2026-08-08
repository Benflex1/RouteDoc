package v1

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
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

func TestRequiredMissingEvidenceCanonicalJSONStableAcrossInsertionOrders(t *testing.T) {
	path := filepath.Join("..", "..", "..", "testdata", "reports", "v1", "listener-absent-complete-scope", "report.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d, issues := Decode(data, ReadValidate)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	validated, issues := model.ValidatePersistedEvaluatedRun(d.Run)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	vantageA := model.VantageID("vantage-000001")
	vantageB := model.VantageID("vantage-000002")
	observationA := model.ObservationKind(model.ObservationListenerInventory)
	observationB := model.ObservationKind(model.ObservationProcessOwnership)
	scopeA := model.VisibilityScope{Kind: "LISTENER", Listener: &model.ListenerVisibilityScope{NamespaceEntityID: "entity-namespace", Protocol: model.TransportTCP, AddressFamily: model.AddressFamilyIPv4, BindSemantics: model.BindWildcard, PortStart: 443, PortEnd: 443}}
	scopeB := model.VisibilityScope{Kind: "LISTENER", Listener: &model.ListenerVisibilityScope{NamespaceEntityID: "entity-namespace", Protocol: model.TransportTCP, AddressFamily: model.AddressFamilyIPv4, BindSemantics: model.BindWildcard, PortStart: 80, PortEnd: 80, ProcessOwnershipRequired: true}}
	requirements := []model.MissingEvidenceRequirement{
		{Kind: model.MissingVantageRequired, VantageID: &vantageB},
		{Kind: model.MissingObservationRequired, ObservationKind: &observationB},
		{Kind: model.MissingVisibilityRequired, VisibilitySubjectKind: visibilitySubjectPtr(model.VisibilitySubjectListener), VisibilityScope: &scopeB},
		{Kind: model.MissingVantageRequired, VantageID: &vantageA},
		{Kind: model.MissingObservationRequired, ObservationKind: &observationA},
		{Kind: model.MissingVisibilityRequired, VisibilitySubjectKind: visibilitySubjectPtr(model.VisibilitySubjectListener), VisibilityScope: &scopeA},
	}
	var want []byte
	for seed := int64(0); seed < 32; seed++ {
		run := validated.Value()
		run.Claims = append([]model.Claim{}, run.Claims...)
		run.Claims[0].RequiredMissingEvidence = append([]model.MissingEvidenceRequirement{}, requirements...)
		rand.New(rand.NewSource(seed)).Shuffle(len(run.Claims[0].RequiredMissingEvidence), func(i, j int) {
			run.Claims[0].RequiredMissingEvidence[i], run.Claims[0].RequiredMissingEvidence[j] = run.Claims[0].RequiredMissingEvidence[j], run.Claims[0].RequiredMissingEvidence[i]
		})
		canonical, issues := model.CanonicalizeAndValidateEvaluatedRun(run)
		if len(issues) != 0 {
			t.Fatalf("seed %d: %v", seed, issues)
		}
		got, issues := EncodeCanonical(canonical)
		if len(issues) != 0 {
			t.Fatalf("seed %d encode: %v", seed, issues)
		}
		if want == nil {
			want = got
		} else if !bytes.Equal(want, got) {
			t.Fatalf("seed %d changed canonical bytes", seed)
		}
	}
}

func visibilitySubjectPtr(v model.VisibilitySubjectKind) *model.VisibilitySubjectKind { return &v }

func jsonBytes(v map[string]interface{}) ([]byte, error) { return json.Marshal(v) }
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
