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
func TestExistingAggregateGlobal(t *testing.T) {
	r := selectionRun()
	r.Evidence.ServicePath.Branches = []model.Branch{{BranchID: "branch-000001", OrderedEdgeIDs: []model.EdgeID{"edge-000001"}, Goal: model.GoalHTTPResponse}, {BranchID: "branch-000002", OrderedEdgeIDs: []model.EdgeID{"edge-000002"}, Goal: model.GoalHTTPResponse}}
	r.Findings = []model.Finding{{FindingID: "finding-000001", Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelInferred, BranchIDs: []model.BranchID{"branch-000001", "branch-000002"}, PathPositions: []model.PathPosition{{BranchID: "branch-000001", Position: 0}, {BranchID: "branch-000002", Position: 0}}, Selection: model.SelectionNone}}
	out, issues := Apply(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if out.Findings[0].Selection != model.SelectionGlobalPrimary {
		t.Fatalf("want global: %#v", out.Findings)
	}
}
func selectionRun() model.EvaluatedRun {
	r := model.EvaluatedRun{Evidence: model.EvidenceRun{ServicePath: model.ServicePath{Branches: []model.Branch{{BranchID: "branch-000001", OrderedEdgeIDs: []model.EdgeID{"edge-000001", "edge-000002"}, Goal: model.GoalHTTPResponse}}}}, Findings: []model.Finding{}}
	return r
}
