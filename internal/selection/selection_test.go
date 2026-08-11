package selection

import (
	"reflect"
	"testing"
	"time"

	"routedoc/internal/model"
)

func TestBranchSelectionAndSuspectedExclusion(t *testing.T) {
	r := selectionRun()
	r.Findings = []model.Finding{{FindingID: "finding-000001", Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelSuspected, BranchIDs: []model.BranchID{"branch-000001"}, PathPositions: []model.PathPosition{{BranchID: "branch-000001", Position: 0}}, Selection: model.SelectionNone}, {FindingID: "finding-000002", Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelObserved, BranchIDs: []model.BranchID{"branch-000001"}, PathPositions: []model.PathPosition{{BranchID: "branch-000001", Position: 1}}, Selection: model.SelectionGlobalPrimary}}
	out, issues := Apply(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if out.Findings[0].Selection != model.SelectionNone || out.Findings[1].Selection != model.SelectionGlobalPrimary {
		t.Fatalf("selection: %#v", out.Findings)
	}
}
func TestIndependentBranchesNoSyntheticGlobal(t *testing.T) {
	r := selectionRun()
	r.Evidence.ServicePath.Branches = []model.Branch{{BranchID: "branch-000001", OrderedEdgeIDs: []model.EdgeID{"edge-000001"}, Goal: model.GoalHTTPResponse}, {BranchID: "branch-000002", OrderedEdgeIDs: []model.EdgeID{"edge-000002"}, Goal: model.GoalHTTPResponse}}
	r.Findings = []model.Finding{{FindingID: "finding-000001", Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelInferred, BranchIDs: []model.BranchID{"branch-000001"}, PathPositions: []model.PathPosition{{BranchID: "branch-000001", Position: 0}}, Selection: model.SelectionNone}, {FindingID: "finding-000002", Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelInferred, BranchIDs: []model.BranchID{"branch-000002"}, PathPositions: []model.PathPosition{{BranchID: "branch-000002", Position: 0}}, Selection: model.SelectionNone}}
	out, issues := Apply(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	for _, f := range out.Findings {
		if f.Selection != model.SelectionBranchPrimary {
			t.Fatalf("want branch primary: %#v", out.Findings)
		}
	}
}
func TestLeafCoverageAfterSplitIsNotGlobal(t *testing.T) {
	r := selectionRun()
	r.Evidence.ServicePath.Branches = []model.Branch{{BranchID: "branch-000001", OrderedEdgeIDs: []model.EdgeID{"edge-000001"}, Goal: model.GoalHTTPResponse}, {BranchID: "branch-000002", OrderedEdgeIDs: []model.EdgeID{"edge-000002"}, Goal: model.GoalHTTPResponse}}
	r.Findings = []model.Finding{{FindingID: "finding-000001", Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelInferred, BranchIDs: []model.BranchID{"branch-000001", "branch-000002"}, PathPositions: []model.PathPosition{{BranchID: "branch-000001", Position: 0}, {BranchID: "branch-000002", Position: 0}}, Selection: model.SelectionNone}}
	out, issues := Apply(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if out.Findings[0].Selection == model.SelectionGlobalPrimary {
		t.Fatalf("leaf-only coverage was globalized: %#v", out.Findings)
	}
}

func TestPreSplitFindingMayBecomeGlobal(t *testing.T) {
	r := selectionRun()
	r.Evidence.ServicePath.Branches = []model.Branch{
		{BranchID: "branch-000001", OrderedEdgeIDs: []model.EdgeID{"edge-000001"}, Goal: model.GoalHTTPResponse},
		{BranchID: "branch-000002", ParentBranchID: ptrBranch("branch-000001"), OrderedEdgeIDs: []model.EdgeID{"edge-000002"}, Goal: model.GoalHTTPResponse},
		{BranchID: "branch-000003", ParentBranchID: ptrBranch("branch-000001"), OrderedEdgeIDs: []model.EdgeID{"edge-000003"}, Goal: model.GoalHTTPResponse},
	}
	r.Findings = []model.Finding{{FindingID: "finding-000001", Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelInferred, BranchIDs: []model.BranchID{"branch-000001"}, PathPositions: []model.PathPosition{{BranchID: "branch-000001", Position: 0}}, Selection: model.SelectionNone}}
	out, issues := Apply(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if out.Findings[0].Selection != model.SelectionGlobalPrimary {
		t.Fatalf("want pre-split finding global: %#v", out.Findings)
	}
}

func TestUnexploredBranchPreventsGlobalPromotion(t *testing.T) {
	r := selectionRun()
	r.Evidence.ServicePath.Branches = []model.Branch{
		{BranchID: "branch-000001", OrderedEdgeIDs: []model.EdgeID{"edge-000001"}, Goal: model.GoalHTTPResponse},
		{BranchID: "branch-000002", OrderedEdgeIDs: []model.EdgeID{"edge-000002"}, Goal: model.GoalHTTPResponse},
	}
	r.Findings = []model.Finding{{FindingID: "finding-000001", Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelInferred, BranchIDs: []model.BranchID{"branch-000001"}, PathPositions: []model.PathPosition{{BranchID: "branch-000001", Position: 0}}, Selection: model.SelectionNone}}
	out, issues := Apply(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if out.Findings[0].Selection == model.SelectionGlobalPrimary {
		t.Fatalf("unexplored branch was ignored: %#v", out.Findings)
	}
}

func TestBranchPrimaryTieBreakIsDeterministic(t *testing.T) {
	r := selectionRun()
	r.Findings = []model.Finding{
		{FindingID: "finding-000002", Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelObserved, BranchIDs: []model.BranchID{"branch-000001"}, PathPositions: []model.PathPosition{{BranchID: "branch-000001", Position: 0}}, Selection: model.SelectionNone, RuleID: "b.rule/v1"},
		{FindingID: "finding-000001", Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelInferred, BranchIDs: []model.BranchID{"branch-000001"}, PathPositions: []model.PathPosition{{BranchID: "branch-000001", Position: 0}}, Selection: model.SelectionNone, RuleID: "a.rule/v1"},
	}
	out, issues := Apply(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if out.Findings[0].Selection != model.SelectionGlobalPrimary || out.Findings[1].Selection != model.SelectionAdditional {
		t.Fatalf("unexpected deterministic tie break: %#v", out.Findings)
	}
}

func TestEquivalentObservedFindingsOnlyOneIsBranchPrimary(t *testing.T) {
	r := selectionRunWithUnexploredBranch()
	r.Claims = []model.Claim{
		tcpRefusedClaim("claim-000001", "entity-endpoint", timeAt(1)),
		tcpRefusedClaim("claim-000002", "entity-endpoint", timeAt(2)),
	}
	r.Findings = []model.Finding{
		observedRefusedFinding("finding-000001", "claim-000001", "branch-000001"),
		observedRefusedFinding("finding-000002", "claim-000002", "branch-000001"),
	}
	out, issues := Apply(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	primary, additional := 0, 0
	for _, finding := range out.Findings {
		switch finding.Selection {
		case model.SelectionBranchPrimary:
			primary++
		case model.SelectionAdditional:
			additional++
		}
	}
	if primary != 1 || additional != 1 {
		t.Fatalf("equivalent selections = %#v, want one primary and one additional", out.Findings)
	}
}

func TestEquivalentSelectionIsDeterministicWhenInputOrderReverses(t *testing.T) {
	makeRun := func(reversed bool) model.EvaluatedRun {
		r := selectionRunWithUnexploredBranch()
		r.Claims = []model.Claim{
			tcpRefusedClaim("claim-000001", "entity-endpoint", timeAt(1)),
			tcpRefusedClaim("claim-000002", "entity-endpoint", timeAt(2)),
		}
		findings := []model.Finding{
			observedRefusedFinding("finding-000001", "claim-000001", "branch-000001"),
			observedRefusedFinding("finding-000002", "claim-000002", "branch-000001"),
		}
		if reversed {
			findings[0], findings[1] = findings[1], findings[0]
		}
		r.Findings = findings
		return r
	}
	a, aIssues := Apply(makeRun(false))
	b, bIssues := Apply(makeRun(true))
	if len(aIssues) != 0 || len(bIssues) != 0 {
		t.Fatalf("selection issues: %v / %v", aIssues, bIssues)
	}
	selectionByID := func(r model.EvaluatedRun) map[model.FindingID]model.Selection {
		out := make(map[model.FindingID]model.Selection, len(r.Findings))
		for _, finding := range r.Findings {
			out[finding.FindingID] = finding.Selection
		}
		return out
	}
	if got, want := selectionByID(a), selectionByID(b); !reflect.DeepEqual(got, want) {
		t.Fatalf("reversed input changed selection: got %#v want %#v", got, want)
	}
}

func TestSameTitleDifferentBranchesRemainIndependentlyPrimary(t *testing.T) {
	r := selectionRun()
	r.Evidence.ServicePath.Branches = []model.Branch{
		{BranchID: "branch-000001", OrderedEdgeIDs: []model.EdgeID{"edge-000001"}, Goal: model.GoalHTTPResponse},
		{BranchID: "branch-000002", OrderedEdgeIDs: []model.EdgeID{"edge-000002"}, Goal: model.GoalHTTPResponse},
	}
	r.Claims = []model.Claim{
		tcpRefusedClaim("claim-000001", "entity-endpoint-a", timeAt(1)),
		tcpRefusedClaim("claim-000002", "entity-endpoint-b", timeAt(2)),
	}
	r.Findings = []model.Finding{
		observedRefusedFinding("finding-000001", "claim-000001", "branch-000001"),
		observedRefusedFinding("finding-000002", "claim-000002", "branch-000002"),
	}
	out, issues := Apply(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	for _, finding := range out.Findings {
		if finding.Selection != model.SelectionBranchPrimary {
			t.Fatalf("independent finding was not branch-primary: %#v", out.Findings)
		}
	}
}

func TestSameBranchSameTitleDifferentClaimsRemainDistinctPrimaries(t *testing.T) {
	r := selectionRunWithUnexploredBranch()
	r.Claims = []model.Claim{
		tcpRefusedClaim("claim-000001", "entity-endpoint-a", timeAt(1)),
		tcpRefusedClaim("claim-000002", "entity-endpoint-b", timeAt(2)),
	}
	r.Findings = []model.Finding{
		observedRefusedFinding("finding-000001", "claim-000001", "branch-000001"),
		observedRefusedFinding("finding-000002", "claim-000002", "branch-000001"),
	}
	out, issues := Apply(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	for _, finding := range out.Findings {
		if finding.Selection != model.SelectionBranchPrimary {
			t.Fatalf("distinct proposition was collapsed: %#v", out.Findings)
		}
	}
}

func tcpRefusedClaim(id model.ClaimID, endpoint model.EntityID, observedAt time.Time) model.Claim {
	return model.Claim{ClaimID: id, StatementCode: model.StatementTCPConnectionRefused, Level: model.ClaimLevelObserved, SubjectEntityIDs: []model.EntityID{endpoint}, BranchIDs: []model.BranchID{"branch-000001"}, Parameters: model.ClaimParameters{Kind: model.StatementTCPConnectionRefused, TCPRefused: &model.TCPRefusedClaimParameters{EndpointEntityID: endpoint, VantageID: "vantage-000001", ObservedAt: observedAt}}, SupportingEvidence: []model.EvidenceRef{}, ContradictingEvidence: []model.EvidenceRef{}, RequiredMissingEvidence: []model.MissingEvidenceRequirement{}, RuleID: "tcp.connection_refused/v1"}
}

func observedRefusedFinding(id model.FindingID, claim model.ClaimID, branch model.BranchID) model.Finding {
	return model.Finding{FindingID: id, Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelObserved, BranchIDs: []model.BranchID{branch}, PathPositions: []model.PathPosition{{BranchID: branch, Position: 0}}, ClaimIDs: []model.ClaimID{claim}, RuleID: "tcp.connection_refused/v1", Limitations: []model.Limitation{}, SuggestedExperiments: []string{}, Selection: model.SelectionNone}
}

func timeAt(second int) time.Time {
	return time.Date(2026, 8, 10, 10, 0, second, 0, time.UTC)
}

func ptrBranch(v model.BranchID) *model.BranchID { return &v }
func selectionRun() model.EvaluatedRun {
	r := model.EvaluatedRun{Evidence: model.EvidenceRun{ServicePath: model.ServicePath{Branches: []model.Branch{{BranchID: "branch-000001", OrderedEdgeIDs: []model.EdgeID{"edge-000001", "edge-000002"}, Goal: model.GoalHTTPResponse}}}}, Findings: []model.Finding{}}
	return r
}

func selectionRunWithUnexploredBranch() model.EvaluatedRun {
	r := selectionRun()
	r.Evidence.ServicePath.Branches = append(r.Evidence.ServicePath.Branches, model.Branch{BranchID: "branch-000002", OrderedEdgeIDs: []model.EdgeID{"edge-000003"}, Goal: model.GoalHTTPResponse})
	return r
}
