package model

func ValidateSelection(r EvaluatedRun) ValidationIssues {
	var is ValidationIssues
	global := 0
	leaves := make(map[BranchID]bool)
	parents := make(map[BranchID]bool)
	for _, b := range r.Evidence.ServicePath.Branches {
		if b.ParentBranchID != nil {
			parents[*b.ParentBranchID] = true
		}
	}
	for _, b := range r.Evidence.ServicePath.Branches {
		if !parents[b.BranchID] {
			leaves[b.BranchID] = true
		}
	}
	for i, f := range r.Findings {
		if f.Selection != SelectionGlobalPrimary {
			continue
		}
		global++
		covered := make(map[BranchID]bool)
		for _, id := range f.BranchIDs {
			covered[id] = true
		}
		for id := range leaves {
			if !covered[id] {
				addIssue(&is, CodeFindingInvalidGlobalPrimary, "/findings/"+itoa(i)+"/selection", "global primary does not cover every leaf branch")
			}
		}
		if len(leaves) == 0 {
			addIssue(&is, CodeFindingInvalidGlobalPrimary, "/findings/"+itoa(i)+"/selection", "global primary has no branch coverage")
		}
	}
	if global > 1 {
		addIssue(&is, CodeFindingInvalidGlobalPrimary, "/findings", "multiple global primary findings")
	}
	return is
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
