package model

type PathNode struct{ EntityID EntityID }
type PathEdge struct {
	EdgeID       EdgeID
	From         EntityID
	To           EntityID
	Relation     PathRelation
	Provenance   PathProvenance
	EvidenceRefs []EvidenceRef
}
type Branch struct {
	BranchID       BranchID
	ParentBranchID *BranchID
	OrderedEdgeIDs []EdgeID
	Goal           GoalKind
}
type ServicePath struct {
	Nodes    []PathNode
	Edges    []PathEdge
	Branches []Branch
}
