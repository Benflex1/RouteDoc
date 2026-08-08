package model

import (
	"testing"
	"time"
)

func minimalEvidence() EvidenceRun {
	t := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	return EvidenceRun{ReportSchemaVersion: SchemaVersion{1, 0, 0}, Producer: Producer{Name: "routedoc", Version: "0.0.0", Build: "test"}, RunID: "run-000001", Target: Target{Scheme: "https", Hostname: "example.test", EffectivePort: 443, Path: PathSummary{Present: true, IsRoot: true}}, Goal: Goal{Kind: GoalHTTPResponse}, RequestedScope: RequestedScope{Kind: ScopeClientOnly}, Policy: Policy{CoherenceWindowNS: int64(time.Minute)}, StartedAt: t, FinishedAt: t.Add(time.Second), VantagePoints: []VantagePoint{}, Capabilities: []Capability{}, OperatorAssertions: []OperatorAssertion{}, Entities: []Entity{}, ServicePath: ServicePath{Nodes: []PathNode{}, Edges: []PathEdge{}, Branches: []Branch{}}, CheckDefinitions: []CheckDefinition{}, CheckExecutions: []CheckExecution{}, Observations: []Observation{}, VisibilityAssessments: []VisibilityAssessment{}, Limitations: []Limitation{}}
}

func TestValidateEvidenceMinimal(t *testing.T) {
	if _, issues := ValidateEvidenceRun(minimalEvidence()); len(issues) != 0 {
		t.Fatalf("minimal evidence invalid: %#v", issues)
	}
}
func TestValidateEvidenceRequiredArrays(t *testing.T) {
	r := minimalEvidence()
	r.Entities = nil
	_, issues := ValidateEvidenceRun(r)
	if !hasCode(issues, CodeMissingRequiredField) {
		t.Fatalf("want missing array: %#v", issues)
	}
}
func TestValidateEvidenceDuplicateIDs(t *testing.T) {
	r := minimalEvidence()
	r.Entities = []Entity{{EntityID: "entity-a", Kind: EntityProxyInstance, DisplayLabel: "a", Identity: EntityIdentity{Kind: EntityProxyInstance, Opaque: &OpaqueEntityIdentity{SyntheticID: "a"}}}, {EntityID: "entity-a", Kind: EntityProxyInstance, DisplayLabel: "b", Identity: EntityIdentity{Kind: EntityProxyInstance, Opaque: &OpaqueEntityIdentity{SyntheticID: "b"}}}}
	_, issues := ValidateEvidenceRun(r)
	if !hasCode(issues, CodeDuplicateID) {
		t.Fatalf("want duplicate: %#v", issues)
	}
}
func TestValidateEvidenceNetworkVantage(t *testing.T) {
	r := minimalEvidence()
	r.Observations = []Observation{{ObservationID: "observation-000001", Kind: ObservationTCPConnection, SubjectEntityIDs: []EntityID{}, ObservedAt: time.Now().UTC(), Payload: ObservationPayload{Kind: ObservationTCPConnection, TCP: &TCPConnectionResult{EndpointEntityID: "entity-e", Result: TCPRefused}}, AcquisitionMethod: AcquisitionSyntheticFixture, SourceComponent: SourceSyntheticFixture, Sensitivity: SensitivitySanitizedDerived, Limitations: []Limitation{}}}
	_, issues := ValidateEvidenceRun(r)
	if !hasCode(issues, CodeVantageRequired) {
		t.Fatalf("want vantage required: %#v", issues)
	}
}
func TestValidateEvidenceExecutionState(t *testing.T) {
	r := minimalEvidence()
	r.CheckExecutions = []CheckExecution{{ExecutionID: "execution-000001", CheckID: "check-000001", Lifecycle: CheckNotRun, Verdict: CheckPass, ObservationIDs: []ObservationID{}, VisibilityAssessmentIDs: []VisibilityID{}}}
	_, issues := ValidateEvidenceRun(r)
	if !hasCode(issues, CodeInvalidExecutionState) {
		t.Fatalf("want execution invalid: %#v", issues)
	}
}
func TestValidateEvidenceProvenanceAndVisibility(t *testing.T) {
	r := minimalEvidence()
	r.ServicePath.Edges = []PathEdge{{EdgeID: "edge-000001", From: "entity-a", To: "entity-b", Relation: RelationRoutesTo, Provenance: ProvenanceOperatorAsserted, EvidenceRefs: []EvidenceRef{ObservationRef("observation-000001")}}}
	_, issues := ValidateEvidenceRun(r)
	if len(issues) == 0 {
		t.Fatal("invalid path accepted")
	}
}
func TestValidateEvidencePathSummary(t *testing.T) {
	r := minimalEvidence()
	r.Target.Path = PathSummary{Present: false, IsRoot: true}
	_, issues := ValidateEvidenceRun(r)
	if len(issues) == 0 {
		t.Fatal("inconsistent path accepted")
	}
}
func hasCode(v ValidationIssues, c ValidationCode) bool {
	for _, i := range v {
		if i.Code == c {
			return true
		}
	}
	return false
}
