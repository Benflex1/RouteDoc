package clientprobe

import "routedoc/internal/model"

type ReportStatus uint8

const (
	StatusIndeterminate ReportStatus = iota
	StatusSatisfied
	StatusBlocked
)

func Status(v model.ValidatedEvaluatedRun) ReportStatus {
	r := v.Value()
	branches, children := leafBranches(r.Evidence.ServicePath.Branches)
	if len(branches) == 0 {
		return StatusIndeterminate
	}
	definitions := map[model.CheckID]model.CheckKind{}
	for _, definition := range r.Evidence.CheckDefinitions {
		definitions[definition.CheckID] = definition.Kind
	}
	observations := map[model.ObservationID]model.Observation{}
	for _, observation := range r.Evidence.Observations {
		observations[observation.ObservationID] = observation
	}
	certPass := map[model.BranchID]bool{}
	httpPass := map[model.BranchID]bool{}
	incomplete := map[model.BranchID]bool{}
	for _, execution := range r.Evidence.CheckExecutions {
		if execution.BranchID == nil {
			continue
		}
		branch := *execution.BranchID
		if execution.Lifecycle == model.CheckNotRun && execution.ReasonCode != nil {
			if *execution.ReasonCode == reasonAddressAttemptCap || *execution.ReasonCode == "probe_pending" {
				incomplete[branch] = true
			}
		}
		if execution.Lifecycle != model.CheckCompleted || execution.Verdict != model.CheckPass {
			continue
		}
		switch definitions[execution.CheckID] {
		case model.CheckCertificateVerification:
			for _, id := range execution.ObservationIDs {
				if o, ok := observations[id]; ok && o.Payload.CertificateVerification != nil && o.Payload.CertificateVerification.Result == model.CertVerified {
					certPass[branch] = true
				}
			}
		case model.CheckHTTP:
			for _, id := range execution.ObservationIDs {
				if o, ok := observations[id]; ok && o.Payload.HTTP != nil && o.Payload.HTTP.ResultKind.Valid() {
					httpPass[branch] = true
				}
			}
		}
	}
	for _, branch := range branches {
		if httpPass[branch] && (r.Evidence.Target.Scheme == "http" || certPass[branch]) {
			return StatusSatisfied
		}
	}
	for _, limitation := range r.Evidence.Limitations {
		if limitation.Code == model.LimitationPartialVisibility && limitation.Scope.Kind == model.LimitationRun {
			return StatusIndeterminate
		}
	}
	for _, branch := range branches {
		if incomplete[branch] {
			return StatusIndeterminate
		}
	}
	covered := map[model.BranchID]bool{}
	for _, finding := range r.Findings {
		if finding.Kind != model.FindingBlocker || (finding.Level != model.ClaimLevelObserved && finding.Level != model.ClaimLevelInferred) {
			continue
		}
		if finding.Selection == model.SelectionGlobalPrimary {
			for _, branch := range branches {
				covered[branch] = true
			}
			continue
		}
		if finding.Selection != model.SelectionBranchPrimary {
			continue
		}
		for _, branchID := range finding.BranchIDs {
			for _, branch := range branches {
				if branchID == branch || isAncestor(branchID, branch, children) {
					covered[branch] = true
				}
			}
		}
	}
	for _, branch := range branches {
		if !covered[branch] {
			return StatusIndeterminate
		}
	}
	return StatusBlocked
}

func leafBranches(all []model.Branch) ([]model.BranchID, map[model.BranchID]model.Branch) {
	byID := map[model.BranchID]model.Branch{}
	children := map[model.BranchID]model.Branch{}
	for _, branch := range all {
		byID[branch.BranchID] = branch
	}
	for _, branch := range all {
		if branch.ParentBranchID != nil {
			children[*branch.ParentBranchID] = byID[*branch.ParentBranchID]
		}
	}
	leaves := []model.BranchID{}
	for _, branch := range all {
		if _, ok := children[branch.BranchID]; !ok && branch.Goal == model.GoalHTTPResponse {
			leaves = append(leaves, branch.BranchID)
		}
	}
	return leaves, byID
}

func isAncestor(candidate, leaf model.BranchID, byID map[model.BranchID]model.Branch) bool {
	current := leaf
	seen := map[model.BranchID]bool{}
	for {
		if seen[current] {
			return false
		}
		seen[current] = true
		branch, ok := byID[current]
		if !ok || branch.ParentBranchID == nil {
			return false
		}
		current = *branch.ParentBranchID
		if current == candidate {
			return true
		}
	}
}
