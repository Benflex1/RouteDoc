package model

import "testing"

func FuzzJustification(f *testing.F) {
	f.Add(false, false, false)
	f.Add(true, false, false)
	f.Add(false, true, false)
	f.Add(false, false, true)
	f.Fuzz(func(t *testing.T, forward, cycle, crossRule bool) {
		r := emptyEvaluated()
		r.Evaluation.OrderedRuleIDs = []RuleID{"a.rule/v1", "b.rule/v1"}
		r.Claims = []Claim{
			{ClaimID: "claim-000001", StatementCode: StatementTCPConnectionRefused, Level: ClaimLevelInferred, SubjectEntityIDs: []EntityID{}, BranchIDs: []BranchID{}, Parameters: ClaimParameters{Kind: StatementTCPConnectionRefused, TCPRefused: &TCPRefusedClaimParameters{VantageID: "vantage-000001", ObservedAt: r.Evidence.StartedAt}}, SupportingEvidence: []EvidenceRef{ObservationRef("observation-000001")}, ContradictingEvidence: []EvidenceRef{}, RequiredMissingEvidence: []MissingEvidenceRequirement{}, RuleID: "a.rule/v1"},
			{ClaimID: "claim-000002", StatementCode: StatementTCPConnectionRefused, Level: ClaimLevelInferred, SubjectEntityIDs: []EntityID{}, BranchIDs: []BranchID{}, Parameters: ClaimParameters{Kind: StatementTCPConnectionRefused, TCPRefused: &TCPRefusedClaimParameters{VantageID: "vantage-000001", ObservedAt: r.Evidence.StartedAt}}, SupportingEvidence: []EvidenceRef{}, ContradictingEvidence: []EvidenceRef{}, RequiredMissingEvidence: []MissingEvidenceRequirement{}, RuleID: "a.rule/v1"},
			{ClaimID: "claim-000003", StatementCode: StatementTCPConnectionRefused, Level: ClaimLevelInferred, SubjectEntityIDs: []EntityID{}, BranchIDs: []BranchID{}, Parameters: ClaimParameters{Kind: StatementTCPConnectionRefused, TCPRefused: &TCPRefusedClaimParameters{VantageID: "vantage-000001", ObservedAt: r.Evidence.StartedAt}}, SupportingEvidence: []EvidenceRef{}, ContradictingEvidence: []EvidenceRef{}, RequiredMissingEvidence: []MissingEvidenceRequirement{}, RuleID: "b.rule/v1"},
		}
		if cycle {
			r.Claims[0].SupportingEvidence = []EvidenceRef{ClaimRef("claim-000002")}
			r.Claims[1].SupportingEvidence = []EvidenceRef{ClaimRef("claim-000001")}
		} else if forward {
			r.Claims[0].SupportingEvidence = []EvidenceRef{ClaimRef("claim-000002")}
		}
		if crossRule {
			r.Claims[2].SupportingEvidence = []EvidenceRef{ClaimRef("claim-000001")}
		}
		_, issues := ValidatePersistedEvaluatedRun(r)
		if forward && !cycle && !hasCode(issues, CodeReferenceForwardClaim) {
			t.Fatal("forward claim was accepted")
		}
		if cycle && !hasCode(issues, CodeJustificationCycle) {
			t.Fatal("cyclic claim graph was accepted")
		}
		if crossRule && !hasCode(issues, CodeReferenceCrossRuleClaim) {
			t.Fatalf("cross-rule claim was accepted: %#v", issues)
		}
	})
}
