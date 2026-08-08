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

func TestValidateEvidencePathResolvesTypedReferences(t *testing.T) {
	r := pathEvidence()
	cases := []struct {
		name string
		ref  EvidenceRef
		want ValidationCode
	}{
		{name: "missing observation", ref: ObservationRef("observation-999999"), want: CodeReferenceMissing},
		{name: "observed edge claim target", ref: ClaimRef("claim-000001"), want: CodeReferenceKindMismatch},
		{name: "mixed observed target", ref: EvidenceRef{Kind: EvidenceKindObservation, ObservationID: ptrObservation("observation-000001"), ClaimID: ptrClaim("claim-000001")}, want: CodeReferenceKindMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r.ServicePath.Edges[0].EvidenceRefs = []EvidenceRef{tc.ref}
			_, issues := ValidateEvidenceRun(r)
			if !hasCode(issues, tc.want) {
				t.Fatalf("wanted %s: %#v", tc.want, issues)
			}
		})
	}

	r = pathEvidence()
	r.ServicePath.Edges[0].Provenance = ProvenanceOperatorAsserted
	r.ServicePath.Edges[0].EvidenceRefs = []EvidenceRef{ObservationRef("observation-000001")}
	_, issues := ValidateEvidenceRun(r)
	if !hasCode(issues, CodeReferenceKindMismatch) {
		t.Fatalf("operator edge accepted observation ref: %#v", issues)
	}

	r = pathEvidence()
	r.ServicePath.Edges[0].Provenance = ProvenanceOperatorAsserted
	r.ServicePath.Edges[0].EvidenceRefs = []EvidenceRef{{Kind: EvidenceKindAssertion, AssertionID: ptrAssertion("assertion-999999")}}
	_, issues = ValidateEvidenceRun(r)
	if !hasCode(issues, CodeReferenceMissing) {
		t.Fatalf("missing operator assertion accepted: %#v", issues)
	}
}

func pathEvidence() EvidenceRun {
	r := minimalEvidence()
	r.Entities = []Entity{
		{EntityID: "entity-a", Kind: EntityProxyInstance, DisplayLabel: "a", Identity: EntityIdentity{Kind: EntityProxyInstance, Opaque: &OpaqueEntityIdentity{SyntheticID: "proxy-a"}}},
		{EntityID: "entity-b", Kind: EntityProxyInstance, DisplayLabel: "b", Identity: EntityIdentity{Kind: EntityProxyInstance, Opaque: &OpaqueEntityIdentity{SyntheticID: "proxy-b"}}},
	}
	r.Observations = []Observation{{ObservationID: "observation-000001", Kind: ObservationCapabilityPermission, SubjectEntityIDs: []EntityID{}, ObservedAt: r.StartedAt, Payload: ObservationPayload{Kind: ObservationCapabilityPermission, Capability: &CapabilityPermissionResult{CapabilityID: "capability-000001", Result: CapabilityAvailable}}, AcquisitionMethod: AcquisitionSyntheticFixture, SourceComponent: SourceSyntheticFixture, Sensitivity: SensitivitySanitizedDerived, Limitations: []Limitation{}}}
	r.ServicePath.Edges = []PathEdge{{EdgeID: "edge-000001", From: "entity-a", To: "entity-b", Relation: RelationRoutesTo, Provenance: ProvenanceDirectlyObserved, EvidenceRefs: []EvidenceRef{ObservationRef("observation-000001")}}}
	return r
}

func ptrObservation(v ObservationID) *ObservationID { return &v }
func ptrClaim(v ClaimID) *ClaimID                   { return &v }
func ptrAssertion(v AssertionID) *AssertionID       { return &v }
func hasCode(v ValidationIssues, c ValidationCode) bool {
	for _, i := range v {
		if i.Code == c {
			return true
		}
	}
	return false
}
