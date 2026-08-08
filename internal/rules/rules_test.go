package rules

import (
	"net/netip"
	"testing"
	"time"

	"routedoc/internal/model"
	"routedoc/internal/rules/ruleapi"
)

type fakeRule struct {
	id         model.RuleID
	candidates []ruleapi.RuleCandidate
	calls      *int
}

func (r fakeRule) ID() model.RuleID { return r.id }
func (r fakeRule) Evaluate(model.ValidatedEvidenceRun) []ruleapi.RuleCandidate {
	if r.calls != nil {
		*r.calls++
	}
	return r.candidates
}

func TestRegistrySortingAndDuplicate(t *testing.T) {
	r, issues := NewRegistry(fakeRule{id: "z.rule/v1"}, fakeRule{id: "a.rule/v1"})
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if got := r.RuleIDs(); got[0] != "a.rule/v1" {
		t.Fatalf("not sorted: %#v", got)
	}
	_, issues = NewRegistry(fakeRule{id: "a.rule/v1"}, fakeRule{id: "a.rule/v1"})
	if !hasCode(issues, model.CodeRegistryDuplicate) {
		t.Fatal(issues)
	}
}
func TestEvaluateDeterministicAllocation(t *testing.T) {
	var calls int
	v := validEvidenceForRules()
	claim := ruleapi.ClaimTemplate{LocalKey: "c", StatementCode: model.StatementTCPConnectionRefused, Level: model.ClaimLevelInferred, Parameters: model.ClaimParameters{Kind: model.StatementTCPConnectionRefused, TCPRefused: &model.TCPRefusedClaimParameters{EndpointEntityID: "entity-endpoint", VantageID: "vantage-000001", ObservedAt: time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)}}, SupportingEvidence: []ruleapi.EvidenceTemplate{{Kind: model.EvidenceKindObservation, ObservationID: "observation-000001"}}}
	finding := ruleapi.FindingTemplate{Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelInferred, ClaimLocalKeys: []string{"c"}, BranchIDs: []model.BranchID{}, PathPositions: []model.PathPosition{}, Limitations: []model.Limitation{}, SuggestedExperiments: []string{}, Selection: model.SelectionNone}
	reg, issues := NewRegistry(fakeRule{id: "test.rule/v1", calls: &calls, candidates: []ruleapi.RuleCandidate{{CandidateKey: "branch-a", Claims: []ruleapi.ClaimTemplate{claim}, Findings: []ruleapi.FindingTemplate{finding}}, {CandidateKey: "branch-b", Claims: []ruleapi.ClaimTemplate{claim}, Findings: []ruleapi.FindingTemplate{finding}}}})
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	e := NewEvaluator(reg)
	got, issues := e.Evaluate(v, time.Date(2026, 8, 8, 11, 0, 0, 0, time.FixedZone("x", 3600)))
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if calls != 1 || len(got.Value().Claims) != 2 || len(got.Value().Findings) != 2 {
		t.Fatalf("evaluation: calls=%d value=%#v", calls, got.Value())
	}
	if got.Value().Evaluation.EvaluatedAt.Location() != time.UTC {
		t.Fatal("clock not normalized")
	}
}
func TestDuplicateCandidateKey(t *testing.T) {
	v := validEvidenceForRules()
	reg, _ := NewRegistry(fakeRule{id: "test.rule/v1", candidates: []ruleapi.RuleCandidate{{CandidateKey: "same"}, {CandidateKey: "same"}}})
	_, issues := NewEvaluator(reg).Evaluate(v, time.Now().UTC())
	if !hasCode(issues, model.CodeDuplicateCandidateKey) {
		t.Fatal(issues)
	}
}
func validEvidenceForRules() model.ValidatedEvidenceRun {
	t := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	r := model.EvidenceRun{ReportSchemaVersion: model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}, Producer: model.Producer{Name: "routedoc", Version: "0", Build: "test"}, RunID: "run-000001", Target: model.Target{Scheme: "https", Hostname: "example.test", EffectivePort: 443, Path: model.PathSummary{Present: true, IsRoot: true}}, Goal: model.Goal{Kind: model.GoalHTTPResponse}, RequestedScope: model.RequestedScope{Kind: model.ScopeClientOnly}, StartedAt: t, FinishedAt: t.Add(time.Second), VantagePoints: []model.VantagePoint{{VantageID: "vantage-000001", Kind: model.VantageKindClientNetwork, Role: model.VantageRoleClient, DisplayLabel: "client", Identity: model.VantageIdentity{Kind: model.VantageKindClientNetwork, ClientNetwork: &model.ClientNetworkIdentity{Label: "client"}}, Establishment: model.VantageDirectlyObserved, Limitations: []model.Limitation{}}}, Capabilities: []model.Capability{}, OperatorAssertions: []model.OperatorAssertion{}, Entities: []model.Entity{{EntityID: "entity-endpoint", Kind: model.EntityUpstreamEndpoint, DisplayLabel: "endpoint", Identity: model.EntityIdentity{Kind: model.EntityUpstreamEndpoint, Endpoint: &model.EndpointIdentity{Address: netip.MustParseAddr("192.0.2.1"), Port: 443, Transport: model.TransportTCP}}}}, ServicePath: model.ServicePath{Nodes: []model.PathNode{}, Edges: []model.PathEdge{}, Branches: []model.Branch{}}, CheckDefinitions: []model.CheckDefinition{}, CheckExecutions: []model.CheckExecution{}, Observations: []model.Observation{{ObservationID: "observation-000001", Kind: model.ObservationCapabilityPermission, SubjectEntityIDs: []model.EntityID{}, ObservedAt: t, Payload: model.ObservationPayload{Kind: model.ObservationCapabilityPermission, Capability: &model.CapabilityPermissionResult{CapabilityID: "capability-000001", Result: model.CapabilityAvailable, ReasonCode: "ok"}}, AcquisitionMethod: model.AcquisitionSyntheticFixture, SourceComponent: model.SourceSyntheticFixture, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}}}, VisibilityAssessments: []model.VisibilityAssessment{}, Limitations: []model.Limitation{}}
	r.Capabilities = []model.Capability{{CapabilityID: "capability-000001", Kind: model.CapabilitySystemResolution, State: model.CapabilityAvailable, ReasonCode: "ok"}}
	v, issues := model.CanonicalizeAndValidateEvidenceRun(r)
	if len(issues) != 0 {
		panic(issues.Err())
	}
	return v
}
func hasCode(v model.ValidationIssues, c model.ValidationCode) bool {
	for _, x := range v {
		if x.Code == c {
			return true
		}
	}
	return false
}
