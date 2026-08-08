package model

import "sort"

func CanonicalizeEvidence(in EvidenceRun) (EvidenceRun, ValidationIssues) {
	out := cloneEvidence(in)
	var issues ValidationIssues
	sort.Slice(out.VantagePoints, func(i, j int) bool { return out.VantagePoints[i].VantageID < out.VantagePoints[j].VantageID })
	for i := range out.VantagePoints {
		sortLimitations(out.VantagePoints[i].Limitations)
	}
	sort.Slice(out.Capabilities, func(i, j int) bool { return out.Capabilities[i].CapabilityID < out.Capabilities[j].CapabilityID })
	sort.Slice(out.OperatorAssertions, func(i, j int) bool {
		return out.OperatorAssertions[i].AssertionID < out.OperatorAssertions[j].AssertionID
	})
	sort.Slice(out.Entities, func(i, j int) bool { return out.Entities[i].EntityID < out.Entities[j].EntityID })
	sort.Slice(out.ServicePath.Nodes, func(i, j int) bool { return out.ServicePath.Nodes[i].EntityID < out.ServicePath.Nodes[j].EntityID })
	sort.Slice(out.ServicePath.Edges, func(i, j int) bool { return out.ServicePath.Edges[i].EdgeID < out.ServicePath.Edges[j].EdgeID })
	for i := range out.ServicePath.Edges {
		sortEvidenceRefs(out.ServicePath.Edges[i].EvidenceRefs)
	}
	var ok bool
	out.ServicePath.Branches, ok = canonicalBranches(out.ServicePath.Branches)
	if !ok {
		issues = append(issues, ValidationIssue{Code: CodeJustificationCycle, Pointer: "/service_path/branches", Message: "branch parent cycle or missing parent"})
	}
	sort.Slice(out.CheckDefinitions, func(i, j int) bool { return out.CheckDefinitions[i].CheckID < out.CheckDefinitions[j].CheckID })
	for i := range out.CheckDefinitions {
		sort.Slice(out.CheckDefinitions[i].DependencyCheckIDs, func(a, b int) bool {
			return out.CheckDefinitions[i].DependencyCheckIDs[a] < out.CheckDefinitions[i].DependencyCheckIDs[b]
		})
		sort.Slice(out.CheckDefinitions[i].RequiredCapabilityIDs, func(a, b int) bool {
			return out.CheckDefinitions[i].RequiredCapabilityIDs[a] < out.CheckDefinitions[i].RequiredCapabilityIDs[b]
		})
	}
	sort.Slice(out.CheckExecutions, func(i, j int) bool { return out.CheckExecutions[i].ExecutionID < out.CheckExecutions[j].ExecutionID })
	for i := range out.CheckExecutions {
		sort.Slice(out.CheckExecutions[i].ObservationIDs, func(a, b int) bool {
			return out.CheckExecutions[i].ObservationIDs[a] < out.CheckExecutions[i].ObservationIDs[b]
		})
		sort.Slice(out.CheckExecutions[i].VisibilityAssessmentIDs, func(a, b int) bool {
			return out.CheckExecutions[i].VisibilityAssessmentIDs[a] < out.CheckExecutions[i].VisibilityAssessmentIDs[b]
		})
	}
	sort.Slice(out.Observations, func(i, j int) bool { return out.Observations[i].ObservationID < out.Observations[j].ObservationID })
	for i := range out.Observations {
		sort.Slice(out.Observations[i].SubjectEntityIDs, func(a, b int) bool {
			return out.Observations[i].SubjectEntityIDs[a] < out.Observations[i].SubjectEntityIDs[b]
		})
		sortLimitations(out.Observations[i].Limitations)
	}
	sort.Slice(out.VisibilityAssessments, func(i, j int) bool {
		return out.VisibilityAssessments[i].VisibilityID < out.VisibilityAssessments[j].VisibilityID
	})
	for i := range out.VisibilityAssessments {
		sort.Slice(out.VisibilityAssessments[i].BasisObservationIDs, func(a, b int) bool {
			return out.VisibilityAssessments[i].BasisObservationIDs[a] < out.VisibilityAssessments[i].BasisObservationIDs[b]
		})
		sortLimitations(out.VisibilityAssessments[i].Limitations)
	}
	sortLimitations(out.Limitations)
	return out, issues
}

func CanonicalizeEvaluated(in EvaluatedRun) (EvaluatedRun, ValidationIssues) {
	out := in
	var issues ValidationIssues
	out.Evidence, issues = CanonicalizeEvidence(in.Evidence)
	if len(in.Claims) > 0 {
		out.Claims = append([]Claim{}, in.Claims...)
	}
	if len(in.Findings) > 0 {
		out.Findings = append([]Finding{}, in.Findings...)
	}
	sort.Slice(out.Claims, func(i, j int) bool { return CompareClaimID(out.Claims[i].ClaimID, out.Claims[j].ClaimID) < 0 })
	sort.Slice(out.Findings, func(i, j int) bool { return CompareFindingID(out.Findings[i].FindingID, out.Findings[j].FindingID) < 0 })
	for i := range out.Claims {
		out.Claims[i].SubjectEntityIDs = append([]EntityID{}, out.Claims[i].SubjectEntityIDs...)
		out.Claims[i].BranchIDs = append([]BranchID{}, out.Claims[i].BranchIDs...)
		out.Claims[i].SupportingEvidence = append([]EvidenceRef{}, out.Claims[i].SupportingEvidence...)
		out.Claims[i].ContradictingEvidence = append([]EvidenceRef{}, out.Claims[i].ContradictingEvidence...)
		out.Claims[i].RequiredMissingEvidence = append([]MissingEvidenceRequirement{}, out.Claims[i].RequiredMissingEvidence...)
		sort.Slice(out.Claims[i].SubjectEntityIDs, func(a, b int) bool { return out.Claims[i].SubjectEntityIDs[a] < out.Claims[i].SubjectEntityIDs[b] })
		sort.SliceStable(out.Claims[i].BranchIDs, func(a, b int) bool {
			return branchIndex(out.Evidence.ServicePath.Branches, out.Claims[i].BranchIDs[a]) < branchIndex(out.Evidence.ServicePath.Branches, out.Claims[i].BranchIDs[b])
		})
		sortEvidenceRefs(out.Claims[i].SupportingEvidence)
		sortEvidenceRefs(out.Claims[i].ContradictingEvidence)
	}
	for i := range out.Findings {
		out.Findings[i].BranchIDs = append([]BranchID{}, out.Findings[i].BranchIDs...)
		out.Findings[i].PathPositions = append([]PathPosition{}, out.Findings[i].PathPositions...)
		out.Findings[i].ClaimIDs = append([]ClaimID{}, out.Findings[i].ClaimIDs...)
		out.Findings[i].Limitations = append([]Limitation{}, out.Findings[i].Limitations...)
		out.Findings[i].SuggestedExperiments = append([]string{}, out.Findings[i].SuggestedExperiments...)
		sort.SliceStable(out.Findings[i].BranchIDs, func(a, b int) bool {
			return branchIndex(out.Evidence.ServicePath.Branches, out.Findings[i].BranchIDs[a]) < branchIndex(out.Evidence.ServicePath.Branches, out.Findings[i].BranchIDs[b])
		})
		sort.Slice(out.Findings[i].PathPositions, func(a, b int) bool {
			return branchIndex(out.Evidence.ServicePath.Branches, out.Findings[i].PathPositions[a].BranchID) < branchIndex(out.Evidence.ServicePath.Branches, out.Findings[i].PathPositions[b].BranchID)
		})
		sort.Slice(out.Findings[i].ClaimIDs, func(a, b int) bool {
			return CompareClaimID(out.Findings[i].ClaimIDs[a], out.Findings[i].ClaimIDs[b]) < 0
		})
		sortLimitations(out.Findings[i].Limitations)
	}
	sort.Slice(out.Evidence.Limitations, func(i, j int) bool {
		return out.Evidence.Limitations[i].LimitationID < out.Evidence.Limitations[j].LimitationID
	})
	return out, issues
}

func sortLimitations(v []Limitation) {
	sort.Slice(v, func(i, j int) bool { return v[i].LimitationID < v[j].LimitationID })
}
func sortEvidenceRefs(v []EvidenceRef) {
	sort.Slice(v, func(i, j int) bool {
		ki, kj := evidenceKindOrder(v[i].Kind), evidenceKindOrder(v[j].Kind)
		if ki != kj {
			return ki < kj
		}
		return evidenceRefID(v[i]) < evidenceRefID(v[j])
	})
}
func evidenceKindOrder(k EvidenceKind) int {
	switch k {
	case EvidenceKindObservation:
		return 0
	case EvidenceKindClaim:
		return 1
	case EvidenceKindVisibility:
		return 2
	case EvidenceKindAssertion:
		return 3
	}
	return 99
}
func evidenceRefID(r EvidenceRef) string {
	if r.ObservationID != nil {
		return string(*r.ObservationID)
	}
	if r.ClaimID != nil {
		return string(*r.ClaimID)
	}
	if r.VisibilityID != nil {
		return string(*r.VisibilityID)
	}
	if r.AssertionID != nil {
		return string(*r.AssertionID)
	}
	return ""
}
func canonicalBranches(in []Branch) ([]Branch, bool) {
	if len(in) == 0 {
		return []Branch{}, true
	}
	by := map[BranchID]Branch{}
	for _, b := range in {
		by[b.BranchID] = b
	}
	out := make([]Branch, 0, len(in))
	done := map[BranchID]bool{}
	for len(out) < len(in) {
		var candidates []Branch
		for _, b := range in {
			if done[b.BranchID] {
				continue
			}
			if b.ParentBranchID == nil || done[*b.ParentBranchID] {
				candidates = append(candidates, b)
			}
		}
		if len(candidates) == 0 {
			return append([]Branch{}, in...), false
		}
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].BranchID < candidates[j].BranchID })
		for _, b := range candidates {
			done[b.BranchID] = true
			out = append(out, b)
		}
	}
	return out, true
}
func branchIndex(v []Branch, id BranchID) int {
	for i, b := range v {
		if b.BranchID == id {
			return i
		}
	}
	return len(v) + 1
}

func cloneEvidence(in EvidenceRun) EvidenceRun {
	out := in
	out.VantagePoints = append([]VantagePoint{}, in.VantagePoints...)
	for i := range out.VantagePoints {
		out.VantagePoints[i].Limitations = append([]Limitation{}, in.VantagePoints[i].Limitations...)
	}
	out.Capabilities = append([]Capability{}, in.Capabilities...)
	out.OperatorAssertions = append([]OperatorAssertion{}, in.OperatorAssertions...)
	out.Entities = append([]Entity{}, in.Entities...)
	out.ServicePath.Nodes = append([]PathNode{}, in.ServicePath.Nodes...)
	out.ServicePath.Edges = append([]PathEdge{}, in.ServicePath.Edges...)
	for i := range out.ServicePath.Edges {
		out.ServicePath.Edges[i].EvidenceRefs = append([]EvidenceRef{}, in.ServicePath.Edges[i].EvidenceRefs...)
	}
	out.ServicePath.Branches = append([]Branch{}, in.ServicePath.Branches...)
	for i := range out.ServicePath.Branches {
		out.ServicePath.Branches[i].OrderedEdgeIDs = append([]EdgeID{}, in.ServicePath.Branches[i].OrderedEdgeIDs...)
	}
	out.CheckDefinitions = append([]CheckDefinition{}, in.CheckDefinitions...)
	for i := range out.CheckDefinitions {
		out.CheckDefinitions[i].DependencyCheckIDs = append([]CheckID{}, in.CheckDefinitions[i].DependencyCheckIDs...)
		out.CheckDefinitions[i].RequiredCapabilityIDs = append([]CapabilityID{}, in.CheckDefinitions[i].RequiredCapabilityIDs...)
	}
	out.CheckExecutions = append([]CheckExecution{}, in.CheckExecutions...)
	for i := range out.CheckExecutions {
		out.CheckExecutions[i].ObservationIDs = append([]ObservationID{}, in.CheckExecutions[i].ObservationIDs...)
		out.CheckExecutions[i].VisibilityAssessmentIDs = append([]VisibilityID{}, in.CheckExecutions[i].VisibilityAssessmentIDs...)
	}
	out.Observations = append([]Observation{}, in.Observations...)
	for i := range out.Observations {
		out.Observations[i].SubjectEntityIDs = append([]EntityID{}, in.Observations[i].SubjectEntityIDs...)
		out.Observations[i].Limitations = append([]Limitation{}, in.Observations[i].Limitations...)
	}
	out.VisibilityAssessments = append([]VisibilityAssessment{}, in.VisibilityAssessments...)
	for i := range out.VisibilityAssessments {
		out.VisibilityAssessments[i].BasisObservationIDs = append([]ObservationID{}, in.VisibilityAssessments[i].BasisObservationIDs...)
		out.VisibilityAssessments[i].Limitations = append([]Limitation{}, in.VisibilityAssessments[i].Limitations...)
	}
	out.Limitations = append([]Limitation{}, in.Limitations...)
	return out
}
