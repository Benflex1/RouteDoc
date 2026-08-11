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
	branchByID := map[model.BranchID]model.Branch{}
	children := map[model.BranchID]bool{}
	for _, b := range branches {
		branchByID[b.BranchID] = b
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
			if f.Kind != model.FindingBlocker || (f.Level != model.ClaimLevelObserved && f.Level != model.ClaimLevelInferred) {
				continue
			}
			attached, pos, ok := findingBranchPosition(f, bid, branchByID)
			if !ok {
				continue
			}
			if pos >= branchEdgeCount(branches, attached) {
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
		selected := make([]candidate, 0, len(at))
		for _, c := range at {
			observedEquivalent := false
			for _, other := range at {
				if out.Findings[other.index].Level == model.ClaimLevelObserved && sameStatement(out.Findings[c.index], out.Findings[other.index], out.Claims) {
					observedEquivalent = true
					break
				}
			}
			if observedEquivalent && out.Findings[c.index].Level != model.ClaimLevelObserved {
				out.Findings[c.index].Selection = model.SelectionAdditional
				continue
			}
			duplicate := false
			for _, previous := range selected {
				if sameStatement(out.Findings[c.index], out.Findings[previous.index], out.Claims) {
					duplicate = true
					break
				}
			}
			if duplicate {
				out.Findings[c.index].Selection = model.SelectionAdditional
				continue
			}
			out.Findings[c.index].Selection = model.SelectionBranchPrimary
			selected = append(selected, c)
		}
	}

	globalCandidates := make([]int, 0)
	for i, f := range out.Findings {
		if f.Kind != model.FindingBlocker || (f.Level != model.ClaimLevelObserved && f.Level != model.ClaimLevelInferred) || len(leaves) == 0 {
			continue
		}
		if model.GlobalPrimaryProof(f, branches) {
			globalCandidates = append(globalCandidates, i)
		}
	}
	if len(globalCandidates) > 0 {
		sort.Slice(globalCandidates, func(i, j int) bool {
			a, b := out.Findings[globalCandidates[i]], out.Findings[globalCandidates[j]]
			if a.Level != b.Level {
				return a.Level == model.ClaimLevelObserved
			}
			return lessFinding(a, b)
		})
		for i, index := range globalCandidates {
			if i == 0 {
				out.Findings[index].Selection = model.SelectionGlobalPrimary
			} else {
				out.Findings[index].Selection = model.SelectionAdditional
			}
		}
	}
	return out, issues
}

func findingBranchPosition(f model.Finding, leaf model.BranchID, branches map[model.BranchID]model.Branch) (model.BranchID, uint64, bool) {
	current := leaf
	seen := map[model.BranchID]bool{}
	for {
		if seen[current] {
			return "", 0, false
		}
		seen[current] = true
		if containsBranch(f.BranchIDs, current) {
			if pos, ok := position(f, current); ok {
				return current, pos, true
			}
		}
		b, ok := branches[current]
		if !ok || b.ParentBranchID == nil {
			return "", 0, false
		}
		current = *b.ParentBranchID
	}
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
func sameStatement(a, b model.Finding, claims []model.Claim) bool {
	if a.Kind != b.Kind || a.TitleCode != b.TitleCode || len(a.ClaimIDs) != len(b.ClaimIDs) {
		return false
	}
	if len(a.ClaimIDs) == 0 {
		return true
	}
	for i := range a.ClaimIDs {
		first, firstOK := claimByID(claims, a.ClaimIDs[i])
		second, secondOK := claimByID(claims, b.ClaimIDs[i])
		if !firstOK || !secondOK || !sameClaimProposition(first, second) {
			return false
		}
	}
	return true
}

func claimByID(claims []model.Claim, id model.ClaimID) (model.Claim, bool) {
	for _, claim := range claims {
		if claim.ClaimID == id {
			return claim, true
		}
	}
	return model.Claim{}, false
}

func sameClaimProposition(a, b model.Claim) bool {
	if a.StatementCode != b.StatementCode || a.Parameters.Kind != b.Parameters.Kind {
		return false
	}
	switch a.Parameters.Kind {
	case model.StatementTCPConnectionRefused:
		if a.Parameters.TCPRefused == nil || b.Parameters.TCPRefused == nil {
			return false
		}
		return a.Parameters.TCPRefused.EndpointEntityID == b.Parameters.TCPRefused.EndpointEntityID && a.Parameters.TCPRefused.VantageID == b.Parameters.TCPRefused.VantageID
	case model.StatementTLSCertificateHostnameMismatch:
		if a.Parameters.HostnameMismatch == nil || b.Parameters.HostnameMismatch == nil {
			return false
		}
		return a.Parameters.HostnameMismatch.PeerEntityID == b.Parameters.HostnameMismatch.PeerEntityID && a.Parameters.HostnameMismatch.Hostname == b.Parameters.HostnameMismatch.Hostname && a.Parameters.HostnameMismatch.TrustSource == b.Parameters.HostnameMismatch.TrustSource
	case model.StatementNoMatchingListenerVisible:
		if a.Parameters.ListenerAbsent == nil || b.Parameters.ListenerAbsent == nil {
			return false
		}
		return *a.Parameters.ListenerAbsent == *b.Parameters.ListenerAbsent
	default:
		return a.ClaimID == b.ClaimID
	}
}
func lessFinding(a, b model.Finding) bool {
	if a.RuleID != b.RuleID {
		return a.RuleID < b.RuleID
	}
	return model.CompareFindingID(a.FindingID, b.FindingID) < 0
}
