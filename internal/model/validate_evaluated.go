package model

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"time"
)

type ValidatedEvaluatedRun struct{ run EvaluatedRun }

func (v ValidatedEvaluatedRun) Value() EvaluatedRun { return v.run }

func ValidatePersistedEvaluatedRun(r EvaluatedRun) (ValidatedEvaluatedRun, ValidationIssues) {
	var is ValidationIssues
	base, baseIssues := ValidateEvidenceRun(r.Evidence)
	_ = base
	is = append(is, baseIssues...)
	if r.Evaluation.OrderedRuleIDs == nil {
		addIssue(&is, CodeMissingRequiredField, "/evaluation/ordered_rule_ids", "required collection")
	}
	if r.Claims == nil {
		addIssue(&is, CodeMissingRequiredField, "/claims", "required collection")
	}
	if r.Findings == nil {
		addIssue(&is, CodeMissingRequiredField, "/findings", "required collection")
	}
	if r.Evaluation.EvaluatedAt.IsZero() || r.Evaluation.EvaluatedAt.Location() != time.UTC {
		addIssue(&is, CodeInvalidValue, "/evaluation/evaluated_at", "evaluation time must be UTC")
	}
	rules := map[RuleID]int{}
	for i, id := range r.Evaluation.OrderedRuleIDs {
		p := fmt.Sprintf("/evaluation/ordered_rule_ids/%d", i)
		if !id.Valid() {
			addIssue(&is, CodeInvalidValue, p, "invalid rule ID")
		}
		rules[id]++
		if i > 0 && r.Evaluation.OrderedRuleIDs[i-1] >= id {
			addIssue(&is, CodeInvalidValue, p, "rule IDs must be unique and ascending")
		}
	}
	claimByID := map[ClaimID]int{}
	for i, c := range r.Claims {
		p := fmt.Sprintf("/claims/%d", i)
		if !c.ClaimID.Valid() {
			addIssue(&is, CodeInvalidGeneratedSequence, p+"/claim_id", "invalid generated claim ID")
		}
		if _, ok := claimByID[c.ClaimID]; ok {
			addIssue(&is, CodeDuplicateID, p+"/claim_id", "duplicate claim ID")
		}
		claimByID[c.ClaimID] = i
		want := generatedID(claimPrefix, i+1)
		if string(c.ClaimID) != want {
			addIssue(&is, CodeInvalidGeneratedSequence, p+"/claim_id", "claim IDs must be sequential")
		}
		if !c.StatementCode.Valid() {
			addIssue(&is, CodeUnknownUnionKind, p+"/statement_code", "unknown claim statement")
		}
		if !c.Level.Valid() {
			addIssue(&is, CodeUnknownEnumValue, p+"/level", "unknown claim level")
		}
		if c.RuleID == "" {
			addIssue(&is, CodeClaimRuleRequired, p+"/rule_id", "claim rule is required")
		} else if rules[c.RuleID] != 1 {
			addIssue(&is, CodeUnlistedProvenance, p+"/rule_id", "claim rule is not listed exactly once")
		}
		if c.SubjectEntityIDs == nil {
			addIssue(&is, CodeMissingRequiredField, p+"/subject_entity_ids", "required collection")
		}
		if c.BranchIDs == nil {
			addIssue(&is, CodeMissingRequiredField, p+"/branch_ids", "required collection")
		}
		if c.SupportingEvidence == nil {
			addIssue(&is, CodeJustificationMissing, p+"/supporting_evidence", "supporting evidence is required")
		}
		if c.ContradictingEvidence == nil {
			addIssue(&is, CodeMissingRequiredField, p+"/contradicting_evidence", "required collection")
		}
		if c.RequiredMissingEvidence == nil {
			addIssue(&is, CodeMissingRequiredField, p+"/required_missing_evidence", "required collection")
		}
		validateClaimParameters(&is, c, p)
		for j, missing := range c.RequiredMissingEvidence {
			validateMissingEvidenceRequirement(&is, missing, fmt.Sprintf("%s/required_missing_evidence/%d", p, j))
		}
	}
	for i, c := range r.Claims {
		validateClaimRefs(&is, c, i, r, claimByID, rules)
		if c.StatementCode == StatementNoMatchingListenerVisible {
			validateListenerAbsenceClaim(&is, c, i, r)
		}
	}
	validateClaimGraphs(&is, r, claimByID)
	findingByID := map[FindingID]int{}
	globalCount := 0
	for i, f := range r.Findings {
		p := fmt.Sprintf("/findings/%d", i)
		if !f.FindingID.Valid() {
			addIssue(&is, CodeInvalidGeneratedSequence, p+"/finding_id", "invalid generated finding ID")
		}
		if _, ok := findingByID[f.FindingID]; ok {
			addIssue(&is, CodeDuplicateID, p+"/finding_id", "duplicate finding ID")
		}
		findingByID[f.FindingID] = i
		want := generatedID(findingPrefix, i+1)
		if string(f.FindingID) != want {
			addIssue(&is, CodeInvalidGeneratedSequence, p+"/finding_id", "finding IDs must be sequential")
		}
		if !f.Kind.Valid() {
			addIssue(&is, CodeUnknownEnumValue, p+"/kind", "unknown finding kind")
		}
		if !f.TitleCode.Valid() {
			addIssue(&is, CodeUnknownUnionKind, p+"/title_code", "unknown finding title")
		}
		if !f.Level.Valid() {
			addIssue(&is, CodeUnknownEnumValue, p+"/level", "unknown finding level")
		}
		if f.RuleID == "" {
			addIssue(&is, CodeFindingRuleRequired, p+"/rule_id", "finding rule is required")
		} else if rules[f.RuleID] != 1 {
			addIssue(&is, CodeUnlistedProvenance, p+"/rule_id", "finding rule is not listed exactly once")
		}
		if f.ClaimIDs == nil || len(f.ClaimIDs) == 0 {
			addIssue(&is, CodeFindingClaimRequired, p+"/claim_ids", "finding must cite a claim")
		}
		if f.BranchIDs == nil {
			addIssue(&is, CodeMissingRequiredField, p+"/branch_ids", "required collection")
		}
		if f.PathPositions == nil {
			addIssue(&is, CodeMissingRequiredField, p+"/path_positions", "required collection")
		}
		if f.Limitations == nil {
			addIssue(&is, CodeMissingRequiredField, p+"/limitations", "required collection")
		}
		if f.SuggestedExperiments == nil {
			addIssue(&is, CodeMissingRequiredField, p+"/suggested_experiments", "required collection")
		}
		if !f.Selection.Valid() {
			addIssue(&is, CodeUnknownEnumValue, p+"/selection", "unknown selection")
		}
		if f.Selection == SelectionGlobalPrimary {
			globalCount++
			if f.Level == ClaimLevelSuspected {
				addIssue(&is, CodeFindingInvalidGlobalPrimary, p+"/selection", "suspected finding cannot be global primary")
			}
		}
		validateFindingRefs(&is, f, i, r, claimByID)
	}
	if globalCount > 1 {
		addIssue(&is, CodeFindingInvalidGlobalPrimary, "/findings", "multiple global primaries")
	}
	is = append(is, ValidateSelection(r)...)
	canonical, ci := CanonicalizeEvaluated(r)
	is = append(is, ci...)
	if len(ci) == 0 && !reflect.DeepEqual(canonical, r) {
		addIssue(&is, CodeOrderingNoncanonical, "/", "persisted collections are not canonical")
	}
	SortValidationIssues(is)
	if len(is) != 0 {
		return ValidatedEvaluatedRun{}, is
	}
	return ValidatedEvaluatedRun{run: r}, is
}

func CanonicalizeAndValidateEvaluatedRun(r EvaluatedRun) (ValidatedEvaluatedRun, ValidationIssues) {
	c, issues := CanonicalizeEvaluated(r)
	if len(issues) > 0 {
		return ValidatedEvaluatedRun{}, issues
	}
	v, more := ValidatePersistedEvaluatedRun(c)
	return v, more
}
func generatedID(prefix string, n int) string {
	v := strconv.Itoa(n)
	for len(v) < 6 {
		v = "0" + v
	}
	return prefix + v
}
func validateClaimParameters(is *ValidationIssues, c Claim, p string) {
	n := 0
	if c.Parameters.HostnameMismatch != nil {
		n++
	}
	if c.Parameters.TCPRefused != nil {
		n++
	}
	if c.Parameters.ListenerAbsent != nil {
		n++
	}
	if n != 1 || c.Parameters.Kind != c.StatementCode {
		addIssue(is, CodeUnknownUnionKind, p+"/parameters", "claim parameter discriminant mismatch")
	}
	switch c.StatementCode {
	case StatementTLSCertificateHostnameMismatch:
		if c.Parameters.HostnameMismatch == nil {
			break
		}
		v := c.Parameters.HostnameMismatch
		if validateHostname(v.Hostname) != nil || !v.TrustSource.Valid() || v.VerificationTime.Location() != time.UTC {
			addIssue(is, CodeInvalidValue, p+"/parameters", "invalid hostname mismatch parameters")
		}
	case StatementTCPConnectionRefused:
		if c.Parameters.TCPRefused == nil {
			break
		}
		v := c.Parameters.TCPRefused
		if !v.VantageID.Valid() || v.ObservedAt.Location() != time.UTC {
			addIssue(is, CodeInvalidValue, p+"/parameters", "invalid TCP refusal parameters")
		}
	case StatementNoMatchingListenerVisible:
		if c.Parameters.ListenerAbsent == nil {
			break
		}
		v := c.Parameters.ListenerAbsent
		if !v.VantageID.Valid() || !v.Protocol.Valid() || !v.AddressFamily.Valid() || !v.BindSemantics.Valid() {
			addIssue(is, CodeInvalidValue, p+"/parameters", "invalid listener absence parameters")
		}
	}
}

func validateMissingEvidenceRequirement(is *ValidationIssues, m MissingEvidenceRequirement, p string) {
	invalidExtra := func(condition bool) {
		if condition {
			addIssue(is, CodeInvalidValue, p, "missing-evidence fields do not match its kind")
		}
	}
	switch m.Kind {
	case MissingObservationRequired:
		if m.ObservationKind == nil {
			addIssue(is, CodeUnknownUnionKind, p+"/observation_kind", "observation kind is required")
		} else if !m.ObservationKind.Valid() {
			addIssue(is, CodeUnknownEnumValue, p+"/observation_kind", "unknown observation kind")
		}
		invalidExtra(m.VisibilitySubjectKind != nil || m.VisibilityScope != nil || m.VantageID != nil)
	case MissingVisibilityRequired:
		if m.VisibilitySubjectKind == nil || !m.VisibilitySubjectKind.Valid() {
			addIssue(is, CodeUnknownEnumValue, p+"/visibility_subject_kind", "listener visibility subject is required")
		}
		if m.VisibilityScope == nil || m.VisibilityScope.Listener == nil || m.VisibilityScope.Kind != "LISTENER" {
			addIssue(is, CodeUnknownUnionKind, p+"/visibility_scope", "listener visibility scope is required")
		} else {
			s := m.VisibilityScope.Listener
			if !s.NamespaceEntityID.Valid() || !s.Protocol.Valid() || !s.AddressFamily.Valid() || !s.BindSemantics.Valid() || s.PortStart > s.PortEnd {
				addIssue(is, CodeInvalidValue, p+"/visibility_scope", "invalid listener visibility scope")
			}
		}
		invalidExtra(m.ObservationKind != nil || m.VantageID != nil)
	case MissingVantageRequired:
		if m.VantageID == nil {
			addIssue(is, CodeUnknownUnionKind, p+"/vantage_id", "vantage ID is required")
		} else if !m.VantageID.Valid() {
			addIssue(is, CodeInvalidValue, p+"/vantage_id", "invalid vantage ID")
		}
		invalidExtra(m.ObservationKind != nil || m.VisibilitySubjectKind != nil || m.VisibilityScope != nil)
	default:
		addIssue(is, CodeUnknownUnionKind, p+"/kind", "unknown missing-evidence kind")
	}
}

func validateListenerAbsenceClaim(is *ValidationIssues, c Claim, index int, r EvaluatedRun) {
	prefix := fmt.Sprintf("/claims/%d", index)
	v := c.Parameters.ListenerAbsent
	if v == nil {
		return
	}
	if c.Level != ClaimLevelInferred {
		addIssue(is, CodeClaimInvalidSupportLevel, prefix+"/level", "listener absence must be inferred")
	}
	if v.Port != r.Evidence.Target.EffectivePort {
		addIssue(is, CodeVisibilityScopeMismatch, prefix+"/parameters/port", "listener absence port must match target port")
	}
	var visibility *VisibilityAssessment
	supportedObservations := map[ObservationID]bool{}
	for _, ref := range c.SupportingEvidence {
		switch ref.Kind {
		case EvidenceKindVisibility:
			if ref.VisibilityID != nil {
				for i := range r.Evidence.VisibilityAssessments {
					if r.Evidence.VisibilityAssessments[i].VisibilityID == *ref.VisibilityID {
						if visibility != nil {
							addIssue(is, CodeVisibilityScopeMismatch, prefix+"/supporting_evidence", "listener absence requires one visibility assessment")
						} else {
							visibility = &r.Evidence.VisibilityAssessments[i]
						}
					}
				}
			}
		case EvidenceKindObservation:
			if ref.ObservationID != nil {
				supportedObservations[*ref.ObservationID] = true
			}
		}
	}
	if visibility == nil {
		addIssue(is, CodeVisibilityInsufficientForAbsence, prefix+"/supporting_evidence", "listener absence requires a visibility assessment")
		return
	}
	s := visibility.Scope.Listener
	if s == nil || v.NamespaceEntityID != s.NamespaceEntityID || v.VantageID != visibility.VantageID || v.Protocol != s.Protocol || v.AddressFamily != s.AddressFamily || v.BindSemantics != s.BindSemantics {
		addIssue(is, CodeVisibilityScopeMismatch, prefix+"/parameters", "listener absence parameters do not match visibility scope")
	}
	if !ListenerAbsenceEvidenceValid(r.Evidence, *visibility, v.Port) {
		addIssue(is, CodeVisibilityInsufficientForAbsence, prefix+"/supporting_evidence", "listener absence evidence does not prove completed scoped inventory")
	}
	for _, id := range visibility.BasisObservationIDs {
		if !supportedObservations[id] {
			addIssue(is, CodeJustificationMissing, prefix+"/supporting_evidence", "listener absence must cite every visibility basis observation")
		}
	}
}
func refTargetCount(r EvidenceRef) int {
	n := 0
	if r.ObservationID != nil {
		n++
	}
	if r.ClaimID != nil {
		n++
	}
	if r.VisibilityID != nil {
		n++
	}
	if r.AssertionID != nil {
		n++
	}
	return n
}
func validateClaimRefs(is *ValidationIssues, c Claim, index int, r EvaluatedRun, by map[ClaimID]int, rules map[RuleID]int) {
	all := append(append([]EvidenceRef{}, c.SupportingEvidence...), c.ContradictingEvidence...)
	for j, x := range all {
		p := fmt.Sprintf("/claims/%d/supporting_evidence/%d", index, j)
		if j >= len(c.SupportingEvidence) {
			p = fmt.Sprintf("/claims/%d/contradicting_evidence/%d", index, j-len(c.SupportingEvidence))
		}
		if !x.Kind.Valid() || refTargetCount(x) != 1 {
			addIssue(is, CodeReferenceKindMismatch, p, "reference must have one target")
			continue
		}
		switch x.Kind {
		case EvidenceKindObservation:
			if x.ObservationID == nil || !containsObservation(r.Evidence.Observations, *x.ObservationID) {
				addIssue(is, CodeReferenceMissing, p, "observation reference missing")
			}
		case EvidenceKindVisibility:
			if x.VisibilityID == nil || !containsVisibility(r.Evidence.VisibilityAssessments, *x.VisibilityID) {
				addIssue(is, CodeReferenceMissing, p, "visibility reference missing")
			}
		case EvidenceKindAssertion:
			if x.AssertionID == nil || !containsAssertion(r.Evidence.OperatorAssertions, *x.AssertionID) {
				addIssue(is, CodeReferenceMissing, p, "assertion reference missing")
			}
		case EvidenceKindClaim:
			if x.ClaimID == nil {
				addIssue(is, CodeReferenceKindMismatch, p, "claim target missing")
				continue
			}
			target, ok := by[*x.ClaimID]
			if !ok {
				addIssue(is, CodeReferenceMissing, p, "claim reference missing")
				continue
			}
			if target >= index {
				addIssue(is, CodeReferenceForwardClaim, p, "claim reference must point backward")
			}
			if r.Claims[target].RuleID != c.RuleID {
				addIssue(is, CodeReferenceCrossRuleClaim, p, "claim reference crosses rule")
			}
		}
	}
}
func validateClaimGraphs(is *ValidationIssues, r EvaluatedRun, by map[ClaimID]int) {
	cycle := claimGraphHasCycle(r, by)
	if cycle {
		addIssue(is, CodeJustificationCycle, "/claims", "claim support graph contains a cycle")
	}
	for i, c := range r.Claims {
		if len(c.SupportingEvidence) == 0 {
			continue
		}
		base := false
		claimOnly := true
		for _, x := range c.SupportingEvidence {
			if x.Kind != EvidenceKindClaim {
				base = true
				claimOnly = false
			}
		}
		if claimOnly && c.Level == ClaimLevelObserved {
			addIssue(is, CodeClaimInvalidSupportLevel, fmt.Sprintf("/claims/%d/level", i), "observed claim cannot rely only on another claim")
		}
		if c.Level == ClaimLevelSuspected && len(c.RequiredMissingEvidence) == 0 {
			addIssue(is, CodeJustificationMissing, fmt.Sprintf("/claims/%d/required_missing_evidence", i), "suspected claim must name missing evidence")
		}
		if !base {
			if !claimPathReachesBase(r, i, by) {
				addIssue(is, CodeJustificationMissing, fmt.Sprintf("/claims/%d/supporting_evidence", i), "claim has no admissible base support")
			}
		}
	}
}

func claimGraphHasCycle(r EvaluatedRun, by map[ClaimID]int) bool {
	state := make(map[int]uint8)
	type frame struct{ index, next int }
	for start := range r.Claims {
		if state[start] != 0 {
			continue
		}
		stack := []frame{{index: start}}
		state[start] = 1
		for len(stack) > 0 {
			f := &stack[len(stack)-1]
			refs := r.Claims[f.index].SupportingEvidence
			advanced := false
			for f.next < len(refs) {
				x := refs[f.next]
				f.next++
				if x.Kind != EvidenceKindClaim || x.ClaimID == nil {
					continue
				}
				n, ok := by[*x.ClaimID]
				if !ok {
					continue
				}
				if state[n] == 1 {
					return true
				}
				if state[n] == 0 {
					state[n] = 1
					stack = append(stack, frame{index: n})
					advanced = true
					break
				}
			}
			if advanced {
				continue
			}
			state[f.index] = 2
			stack = stack[:len(stack)-1]
		}
	}
	return false
}
func claimPathReachesBase(r EvaluatedRun, start int, by map[ClaimID]int) bool {
	state := map[int]uint8{}
	stack := []int{start}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if state[n] == 1 {
			return false
		}
		if state[n] == 2 {
			continue
		}
		state[n] = 1
		found := false
		for _, x := range r.Claims[n].SupportingEvidence {
			if x.Kind != EvidenceKindClaim {
				found = true
				continue
			}
			if x.ClaimID == nil {
				return false
			}
			next, ok := by[*x.ClaimID]
			if !ok {
				return false
			}
			if state[next] == 1 {
				return false
			}
			if state[next] == 0 {
				stack = append(stack, next)
			}
		}
		state[n] = 2
		if found {
			return true
		}
	}
	return false
}
func validateFindingRefs(is *ValidationIssues, f Finding, index int, r EvaluatedRun, claims map[ClaimID]int) {
	seen := map[BranchID]bool{}
	for i, id := range f.BranchIDs {
		if seen[id] {
			addIssue(is, CodeDuplicateID, fmt.Sprintf("/findings/%d/branch_ids/%d", index, i), "duplicate branch")
		}
		seen[id] = true
		if !containsBranch(r.Evidence.ServicePath.Branches, id) {
			addIssue(is, CodeReferenceMissing, fmt.Sprintf("/findings/%d/branch_ids/%d", index, i), "branch missing")
		}
	}
	for i, p := range f.PathPositions {
		if !containsBranch(r.Evidence.ServicePath.Branches, p.BranchID) || int(p.Position) >= branchEdgeCount(r.Evidence.ServicePath.Branches, p.BranchID) {
			addIssue(is, CodeInvalidValue, fmt.Sprintf("/findings/%d/path_positions/%d", index, i), "invalid branch position")
		}
	}
	for i, id := range f.ClaimIDs {
		ci, ok := claims[id]
		if !ok {
			addIssue(is, CodeReferenceMissing, fmt.Sprintf("/findings/%d/claim_ids/%d", index, i), "claim missing")
			continue
		}
		if r.Claims[ci].RuleID != f.RuleID {
			addIssue(is, CodeFindingRuleMismatch, fmt.Sprintf("/findings/%d/claim_ids/%d", index, i), "finding claim has a different rule")
		}
		if r.Claims[ci].Level == ClaimLevelSuspected && f.Selection != SelectionNone && f.Selection != SelectionAdditional {
			addIssue(is, CodeFindingInvalidGlobalPrimary, fmt.Sprintf("/findings/%d/selection", index), "suspected claim cannot support selected confirmed finding")
		}
	}
}
func containsObservation(v []Observation, id ObservationID) bool {
	for _, x := range v {
		if x.ObservationID == id {
			return true
		}
	}
	return false
}
func containsVisibility(v []VisibilityAssessment, id VisibilityID) bool {
	for _, x := range v {
		if x.VisibilityID == id {
			return true
		}
	}
	return false
}
func containsAssertion(v []OperatorAssertion, id AssertionID) bool {
	for _, x := range v {
		if x.AssertionID == id {
			return true
		}
	}
	return false
}
func containsBranch(v []Branch, id BranchID) bool {
	for _, x := range v {
		if x.BranchID == id {
			return true
		}
	}
	return false
}
func branchEdgeCount(v []Branch, id BranchID) int {
	for _, x := range v {
		if x.BranchID == id {
			return len(x.OrderedEdgeIDs)
		}
	}
	return 0
}
func sortedClaimIDs(v []Claim) bool {
	for i := 1; i < len(v); i++ {
		if CompareClaimID(v[i-1].ClaimID, v[i].ClaimID) > 0 {
			return false
		}
	}
	return true
}

var _ = sort.Slice
