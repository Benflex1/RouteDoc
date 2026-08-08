package selection

import (
	"testing"

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

func ptrBranch(v model.BranchID) *model.BranchID { return &v }
func selectionRun() model.EvaluatedRun {
	r := model.EvaluatedRun{Evidence: model.EvidenceRun{ServicePath: model.ServicePath{Branches: []model.Branch{{BranchID: "branch-000001", OrderedEdgeIDs: []model.EdgeID{"edge-000001", "edge-000002"}, Goal: model.GoalHTTPResponse}}}}, Findings: []model.Finding{}}
	return r
}
