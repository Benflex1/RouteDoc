package model

func ValidateSelection(r EvaluatedRun) ValidationIssues {
	var is ValidationIssues
	global := 0
	for i, f := range r.Findings {
		if f.Selection != SelectionGlobalPrimary {
			continue
		}
		global++
		if !GlobalPrimaryProof(f, r.Evidence.ServicePath.Branches) {
			addIssue(&is, CodeFindingInvalidGlobalPrimary, "/findings/"+itoa(i)+"/selection", "global primary lacks a pre-split proof for every leaf branch")
		}
	}
	if global > 1 {
		addIssue(&is, CodeFindingInvalidGlobalPrimary, "/findings", "multiple global primary findings")
	}
	return is
}

// GlobalPrimaryProof is the shared construction/persistence rule for global
// selection. A finding can be global only when an existing finding is attached
// to a branch that is an ancestor of every leaf and has a valid position on
// that branch. Leaf coverage alone is deliberately insufficient: the model
// has no independent aggregate-finding marker in Milestone 0.
func GlobalPrimaryProof(f Finding, branches []Branch) bool {
	if f.Kind != FindingBlocker || (f.Level != ClaimLevelObserved && f.Level != ClaimLevelInferred) {
		return false
	}
	byID := make(map[BranchID]Branch, len(branches))
	children := make(map[BranchID]bool, len(branches))
	for _, b := range branches {
		byID[b.BranchID] = b
		if b.ParentBranchID != nil {
			children[*b.ParentBranchID] = true
		}
	}
	leaves := make([]BranchID, 0, len(branches))
	for _, b := range branches {
		if !children[b.BranchID] {
			leaves = append(leaves, b.BranchID)
		}
	}
	if len(leaves) == 0 {
		return false
	}
	for _, candidate := range f.BranchIDs {
		if _, ok := byID[candidate]; !ok || !findingHasPosition(f, candidate) {
			continue
		}
		if !isAncestorOfAll(candidate, leaves, byID) {
			continue
		}
		if positionForBranch(f, candidate) >= uint64(len(byID[candidate].OrderedEdgeIDs)) {
			continue
		}
		return true
	}
	return false
}

func isAncestorOfAll(candidate BranchID, leaves []BranchID, byID map[BranchID]Branch) bool {
	for _, leaf := range leaves {
		current := leaf
		seen := map[BranchID]bool{}
		found := false
		for {
			if seen[current] {
				return false
			}
			seen[current] = true
			if current == candidate {
				found = true
				break
			}
			b, ok := byID[current]
			if !ok || b.ParentBranchID == nil {
				break
			}
			current = *b.ParentBranchID
		}
		if !found {
			return false
		}
	}
	return true
}

func findingHasPosition(f Finding, id BranchID) bool {
	for _, p := range f.PathPositions {
		if p.BranchID == id {
			return true
		}
	}
	return false
}

func positionForBranch(f Finding, id BranchID) uint64 {
	for _, p := range f.PathPositions {
		if p.BranchID == id {
			return p.Position
		}
	}
	return 0
}

func itoa(i int) string { // local, allocation-free enough for validation pointers
	if i == 0 {
		return "0"
	}
	b := make([]byte, 0, 12)
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
