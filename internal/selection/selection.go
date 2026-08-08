package selection

import (
	"sort"

	"routedoc/internal/model"
)

type candidate struct{ index, pos int }

func Apply(in model.EvaluatedRun) (model.EvaluatedRun, model.ValidationIssues) {
	out := in
	out.Findings = append([]model.Finding{}, in.Findings...)
	var issues model.ValidationIssues
	for i := range out.Findings {
		out.Findings[i].Selection = model.SelectionNone
	}
	branches := out.Evidence.ServicePath.Branches
	children := map[model.BranchID]bool{}
	for _, b := range branches {
		if b.ParentBranchID != nil {
			children[*b.ParentBranchID] = true
		}
	}
	leaves := make([]model.BranchID, 0)
	for _, b := range branches {
		if !children[b.BranchID] {
			leaves = append(leaves, b.BranchID)
		}
	}
	sort.Slice(leaves, func(i, j int) bool { return leaves[i] < leaves[j] })

	for _, bid := range leaves {
		candidates := make([]candidate, 0)
		for i, f := range out.Findings {
			if f.Kind != model.FindingBlocker || (f.Level != model.ClaimLevelObserved && f.Level != model.ClaimLevelInferred) || !containsBranch(f.BranchIDs, bid) {
				continue
			}
			pos, ok := position(f, bid)
			if !ok {
				issues = append(issues, model.ValidationIssue{Code: model.CodeFindingInvalidGlobalPrimary, Pointer: "/findings", Message: "finding has no path position for branch"})
				continue
			}
			if pos >= branchEdgeCount(branches, bid) {
				issues = append(issues, model.ValidationIssue{Code: model.CodeFindingInvalidGlobalPrimary, Pointer: "/findings", Message: "finding path position is outside branch"})
				continue
			}
			candidates = append(candidates, candidate{i, int(pos)})
		}
		if len(candidates) == 0 {
			continue
		}
		min := candidates[0].pos
		for _, c := range candidates[1:] {
			if c.pos < min {
				min = c.pos
			}
		}
		at := candidates[:0]
		for _, c := range candidates {
			if c.pos == min {
				at = append(at, c)
			}
		}
		sort.Slice(at, func(i, j int) bool { return lessFinding(out.Findings[at[i].index], out.Findings[at[j].index]) })
		observed := hasObservedEquivalent(at, out.Findings)
		for _, c := range at {
			if observed && out.Findings[c.index].Level == model.ClaimLevelInferred && sameStatement(out.Findings[c.index], out.Findings[at[0].index]) {
				out.Findings[c.index].Selection = model.SelectionAdditional
				continue
			}
			out.Findings[c.index].Selection = model.SelectionBranchPrimary
		}
	}

	for i, f := range out.Findings {
		if f.Kind != model.FindingBlocker || (f.Level != model.ClaimLevelObserved && f.Level != model.ClaimLevelInferred) || len(leaves) == 0 {
			continue
		}
		covered := true
		for _, bid := range leaves {
			if !containsBranch(f.BranchIDs, bid) {
				covered = false
				break
			}
		}
		if covered {
			out.Findings[i].Selection = model.SelectionGlobalPrimary
			for j := range out.Findings {
				if j != i && out.Findings[j].Selection == model.SelectionGlobalPrimary {
					out.Findings[j].Selection = model.SelectionAdditional
				}
			}
		}
	}
	return out, issues
}

func containsBranch(v []model.BranchID, id model.BranchID) bool {
	for _, x := range v {
		if x == id {
			return true
		}
	}
	return false
}
func position(f model.Finding, id model.BranchID) (uint64, bool) {
	for _, p := range f.PathPositions {
		if p.BranchID == id {
			return p.Position, true
		}
	}
	return 0, false
}
func branchEdgeCount(v []model.Branch, id model.BranchID) uint64 {
	for _, b := range v {
		if b.BranchID == id {
			return uint64(len(b.OrderedEdgeIDs))
		}
	}
	return 0
}
func sameStatement(a, b model.Finding) bool { return a.Kind == b.Kind && a.TitleCode == b.TitleCode }
func lessFinding(a, b model.Finding) bool {
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	return model.CompareFindingID(a.FindingID, b.FindingID) < 0
}
func hasObservedEquivalent(v []candidate, findings []model.Finding) bool {
	for _, a := range v {
		for _, b := range v {
			if findings[a.index].Level == model.ClaimLevelObserved && sameStatement(findings[a.index], findings[b.index]) {
				return true
			}
		}
	}
	return false
}
