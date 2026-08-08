package rules

import (
	"testing"
	"time"

	"routedoc/internal/model"
)

func TestReevaluateReplacement(t *testing.T) {
	v := validEvidenceForRules()
	claim := ClaimTemplate{LocalKey: "c", StatementCode: model.StatementTCPConnectionRefused, Level: model.ClaimLevelInferred, Parameters: model.ClaimParameters{Kind: model.StatementTCPConnectionRefused, TCPRefused: &model.TCPRefusedClaimParameters{EndpointEntityID: "entity-endpoint", VantageID: "vantage-000001", ObservedAt: time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)}}, SupportingEvidence: []EvidenceTemplate{{Kind: model.EvidenceKindObservation, ObservationID: "observation-000001"}}}
	finding := FindingTemplate{Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelInferred, BranchIDs: []model.BranchID{}, PathPositions: []model.PathPosition{}, ClaimLocalKeys: []string{"c"}, Limitations: []model.Limitation{}, SuggestedExperiments: []string{}, Selection: model.SelectionNone}
	reg, _ := NewRegistry(fakeRule{id: "test.rule/v1", candidates: []RuleCandidate{{CandidateKey: "one", Claims: []ClaimTemplate{claim}, Findings: []FindingTemplate{finding}}}})
	first, issues := NewEvaluator(reg).Evaluate(v, time.Date(2026, 8, 8, 11, 0, 0, 0, time.UTC))
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	empty, _ := NewRegistry()
	clock := time.Date(2026, 8, 8, 12, 0, 0, 0, time.FixedZone("later", 3600))
	got, issues := NewEvaluator(empty).Reevaluate(first, clock)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	value := got.Value()
	if len(value.Claims) != 0 || len(value.Findings) != 0 || len(value.Evaluation.OrderedRuleIDs) != 0 {
		t.Fatalf("derived state retained: %#v", value)
	}
	if value.Evidence.RunID != model.RunID("run-000001") {
		t.Fatal("base evidence changed")
	}
	if value.Evaluation.EvaluatedAt.Location() != time.UTC || value.Evaluation.EvaluatedAt.Hour() != 11 {
		t.Fatalf("clock: %v", value.Evaluation.EvaluatedAt)
	}
}
func TestReevaluateRestartsGeneratedIDs(t *testing.T) {
	v := validEvidenceForRules()
	reg, _ := NewRegistry()
	e, _ := NewEvaluator(reg).Evaluate(v, time.Now().UTC())
	if len(e.Value().Claims) != 0 {
		t.Fatal()
	}
	if _, issues := NewEvaluator(reg).Reevaluate(e, time.Now().UTC()); len(issues) != 0 {
		t.Fatal(issues)
	}
}
