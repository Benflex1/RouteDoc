package model

import "testing"

func TestCanonicalizeRandomInsertion(t *testing.T) {
	r := EvidenceRun{VantagePoints: []VantagePoint{{VantageID: VantageID("vantage-000002")}, {VantageID: VantageID("vantage-000001")}}, Capabilities: []Capability{{CapabilityID: CapabilityID("capability-000002")}, {CapabilityID: CapabilityID("capability-000001")}}}
	c, issues := CanonicalizeEvidence(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if c.VantagePoints[0].VantageID != "vantage-000001" || c.Capabilities[0].CapabilityID != "capability-000001" {
		t.Fatal("SET not sorted")
	}
	if r.VantagePoints[0].VantageID != "vantage-000002" {
		t.Fatal("input mutated")
	}
}
func TestOrderedArraysPreserved(t *testing.T) {
	r := EvidenceRun{ServicePath: ServicePath{Branches: []Branch{{BranchID: "branch-000001", OrderedEdgeIDs: []EdgeID{"edge-b", "edge-a"}}}}}
	c, _ := CanonicalizeEvidence(r)
	if c.ServicePath.Branches[0].OrderedEdgeIDs[0] != "edge-b" {
		t.Fatal("ordered array sorted")
	}
}
func TestEvaluatedModelShape(t *testing.T) {
	c := Claim{ClaimID: "claim-000001", StatementCode: StatementTCPConnectionRefused, Level: ClaimLevelInferred, RuleID: "tcp.connection_refused/v1"}
	f := Finding{FindingID: "finding-000001", ClaimIDs: []ClaimID{c.ClaimID}, Selection: SelectionNone}
	if len(f.ClaimIDs) != 1 {
		t.Fatal()
	}
}
