package model

import "testing"

func emptyEvaluated() EvaluatedRun {
	r := minimalEvidence()
	return EvaluatedRun{Evidence: r, Evaluation: Evaluation{EvaluatedAt: r.FinishedAt, OrderedRuleIDs: []RuleID{"tcp.connection_refused/v1"}}, Claims: []Claim{}, Findings: []Finding{}}
}
func TestValidateEvaluatedEmpty(t *testing.T) {
	if _, issues := ValidatePersistedEvaluatedRun(emptyEvaluated()); len(issues) != 0 {
		t.Fatalf("empty evaluated invalid: %#v", issues)
	}
}
func TestValidateEvaluatedProvenanceAndFindingClaims(t *testing.T) {
	r := emptyEvaluated()
	r.Claims = []Claim{{ClaimID: "claim-000001", StatementCode: StatementTCPConnectionRefused, Level: ClaimLevelInferred, SupportingEvidence: []EvidenceRef{ObservationRef("observation-000001")}}}
	r.Findings = []Finding{{FindingID: "finding-000001", Kind: FindingBlocker, TitleCode: TitleTCPConnectionRefused, Level: ClaimLevelInferred, ClaimIDs: []ClaimID{"claim-000001"}, RuleID: "other.rule/v1", Selection: SelectionNone}}
	_, issues := ValidatePersistedEvaluatedRun(r)
	if !hasCode(issues, CodeClaimRuleRequired) || !hasCode(issues, CodeFindingRuleMismatch) {
		t.Fatalf("want provenance errors: %#v", issues)
	}
}
func TestValidateEvaluatedReferences(t *testing.T) {
	r := emptyEvaluated()
	r.Evaluation.OrderedRuleIDs = []RuleID{"fake.rule/v1"}
	r.Claims = []Claim{{ClaimID: "claim-000001", StatementCode: StatementTCPConnectionRefused, Level: ClaimLevelInferred, SupportingEvidence: []EvidenceRef{ClaimRef("claim-000002")}, RuleID: "fake.rule/v1"}, {ClaimID: "claim-000002", StatementCode: StatementTCPConnectionRefused, Level: ClaimLevelInferred, SupportingEvidence: []EvidenceRef{ClaimRef("claim-000001")}, RuleID: "fake.rule/v1"}}
	r.Findings = []Finding{}
	_, issues := ValidatePersistedEvaluatedRun(r)
	if !hasCode(issues, CodeReferenceForwardClaim) || !hasCode(issues, CodeJustificationCycle) {
		t.Fatalf("want forward/cycle: %#v", issues)
	}
}
func TestValidateEvaluatedSequenceAndOrdering(t *testing.T) {
	r := emptyEvaluated()
	r.Claims = []Claim{{ClaimID: "claim-000002", StatementCode: StatementTCPConnectionRefused, Level: ClaimLevelInferred, SupportingEvidence: []EvidenceRef{ObservationRef("observation-000001")}, RuleID: "tcp.connection_refused/v1"}}
	_, issues := ValidatePersistedEvaluatedRun(r)
	if !hasCode(issues, CodeInvalidGeneratedSequence) {
		t.Fatalf("want sequence: %#v", issues)
	}
	r = emptyEvaluated()
	r.Evidence.VantagePoints = []VantagePoint{{VantageID: "vantage-000002"}, {VantageID: "vantage-000001"}}
	_, issues = ValidatePersistedEvaluatedRun(r)
	if !hasCode(issues, CodeOrderingNoncanonical) {
		t.Fatalf("want ordering: %#v", issues)
	}
}
func TestValidatedEvaluatedWrapper(t *testing.T) {
	v, issues := CanonicalizeAndValidateEvaluatedRun(emptyEvaluated())
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if v.Value().Evaluation.OrderedRuleIDs[0] != "tcp.connection_refused/v1" {
		t.Fatal("wrapper")
	}
}
