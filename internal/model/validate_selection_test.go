package model

import "testing"

func TestValidateSelectionRejectsLeafCoverageGlobalPrimary(t *testing.T) {
	r := EvaluatedRun{Evidence: EvidenceRun{ServicePath: ServicePath{Branches: []Branch{
		{BranchID: "branch-000001", OrderedEdgeIDs: []EdgeID{"edge-000001"}},
		{BranchID: "branch-000002", OrderedEdgeIDs: []EdgeID{"edge-000002"}},
	}}}, Findings: []Finding{{
		FindingID: "finding-000001", Kind: FindingBlocker, TitleCode: TitleTCPConnectionRefused, Level: ClaimLevelInferred,
		BranchIDs: []BranchID{"branch-000001", "branch-000002"}, PathPositions: []PathPosition{{BranchID: "branch-000001"}, {BranchID: "branch-000002"}}, Selection: SelectionGlobalPrimary,
	}}}
	if issues := ValidateSelection(r); len(issues) == 0 {
		t.Fatal("malicious persisted global primary was accepted")
	}
}

func TestValidateSelectionAcceptsPreSplitGlobalPrimary(t *testing.T) {
	root := BranchID("branch-000001")
	r := EvaluatedRun{Evidence: EvidenceRun{ServicePath: ServicePath{Branches: []Branch{
		{BranchID: root, OrderedEdgeIDs: []EdgeID{"edge-000001"}},
		{BranchID: "branch-000002", ParentBranchID: &root, OrderedEdgeIDs: []EdgeID{"edge-000002"}},
		{BranchID: "branch-000003", ParentBranchID: &root, OrderedEdgeIDs: []EdgeID{"edge-000003"}},
	}}}, Findings: []Finding{{
		FindingID: "finding-000001", Kind: FindingBlocker, TitleCode: TitleTCPConnectionRefused, Level: ClaimLevelInferred,
		BranchIDs: []BranchID{root}, PathPositions: []PathPosition{{BranchID: root}}, Selection: SelectionGlobalPrimary,
	}}}
	if issues := ValidateSelection(r); len(issues) != 0 {
		t.Fatalf("pre-split global primary rejected: %v", issues)
	}
}
