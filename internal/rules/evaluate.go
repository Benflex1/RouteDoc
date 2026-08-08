package rules

import (
	"sort"
	"time"

	"routedoc/internal/model"
	"routedoc/internal/selection"
)

type Evaluator struct{ registry Registry }

func NewEvaluator(r Registry) Evaluator { return Evaluator{registry: r} }

type compiledCandidate struct {
	rule      model.RuleID
	key       string
	candidate RuleCandidate
	local     map[string]model.ClaimID
}

func (e Evaluator) Evaluate(v model.ValidatedEvidenceRun, clock time.Time) (model.ValidatedEvaluatedRun, model.ValidationIssues) {
	if !v.Value().ReportSchemaVersion.Exact() {
		return model.ValidatedEvaluatedRun{}, model.ValidationIssues{{Code: model.CodeExactVersionRequired, Pointer: "/report_schema_version", Message: "evaluation requires exact schema version"}}
	}
	clock = clock.UTC()
	var is model.ValidationIssues
	candidates := make([]compiledCandidate, 0)
	for _, rule := range e.registry.rulesCopy() {
		raw := rule.Evaluate(v)
		seen := map[string]bool{}
		for _, c := range raw {
			if !validCandidateKey(c.CandidateKey) {
				is = append(is, model.ValidationIssue{Code: model.CodeDuplicateCandidateKey, Pointer: "/evaluation", Message: "candidate key is invalid or sensitive"})
				continue
			}
			if seen[c.CandidateKey] {
				is = append(is, model.ValidationIssue{Code: model.CodeDuplicateCandidateKey, Pointer: "/evaluation", Message: "duplicate candidate key"})
				continue
			}
			seen[c.CandidateKey] = true
			candidates = append(candidates, compiledCandidate{rule: rule.ID(), key: c.CandidateKey, candidate: c})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].rule != candidates[j].rule {
			return candidates[i].rule < candidates[j].rule
		}
		return candidates[i].key < candidates[j].key
	})
	if len(is) > 0 {
		model.SortValidationIssues(is)
		return model.ValidatedEvaluatedRun{}, is
	}
	evaluated := model.EvaluatedRun{Evidence: v.Value(), Evaluation: model.Evaluation{EvaluatedAt: clock, OrderedRuleIDs: e.registry.RuleIDs()}, Claims: []model.Claim{}, Findings: []model.Finding{}}
	claimNumber := 1
	for i := range candidates {
		candidates[i].local = map[string]model.ClaimID{}
		for _, t := range candidates[i].candidate.Claims {
			if t.LocalKey == "" || candidates[i].local[t.LocalKey] != "" {
				is = append(is, model.ValidationIssue{Code: model.CodeInvalidValue, Pointer: "/evaluation", Message: "duplicate or empty local claim key"})
				continue
			}
			id := model.ClaimID(claimID(claimNumber))
			claimNumber++
			candidates[i].local[t.LocalKey] = id
			claim := model.Claim{ClaimID: id, StatementCode: t.StatementCode, Level: t.Level, SubjectEntityIDs: append([]model.EntityID{}, t.SubjectEntityIDs...), BranchIDs: append([]model.BranchID{}, t.BranchIDs...), Parameters: t.Parameters, SupportingEvidence: make([]model.EvidenceRef, len(t.SupportingEvidence)), ContradictingEvidence: make([]model.EvidenceRef, len(t.ContradictingEvidence)), RequiredMissingEvidence: append([]model.MissingEvidenceRequirement{}, t.RequiredMissingEvidence...), RuleID: candidates[i].rule}
			for j, x := range t.SupportingEvidence {
				if x.Kind == model.EvidenceKindClaim && candidates[i].local[x.ClaimLocalKey] == "" {
					is = append(is, model.ValidationIssue{Code: model.CodeReferenceForwardClaim, Pointer: "/evaluation", Message: "template claim reference is not earlier in candidate"})
				}
				claim.SupportingEvidence[j] = evidenceFromTemplate(x, candidates[i].local)
			}
			for j, x := range t.ContradictingEvidence {
				if x.Kind == model.EvidenceKindClaim && candidates[i].local[x.ClaimLocalKey] == "" {
					is = append(is, model.ValidationIssue{Code: model.CodeReferenceForwardClaim, Pointer: "/evaluation", Message: "template claim reference is not earlier in candidate"})
				}
				claim.ContradictingEvidence[j] = evidenceFromTemplate(x, candidates[i].local)
			}
			evaluated.Claims = append(evaluated.Claims, claim)
		}
	}
	findingNumber := 1
	for i := range candidates {
		for _, t := range candidates[i].candidate.Findings {
			f := model.Finding{FindingID: model.FindingID(findingID(findingNumber)), Kind: t.Kind, TitleCode: t.TitleCode, Level: t.Level, BranchIDs: append([]model.BranchID{}, t.BranchIDs...), PathPositions: append([]model.PathPosition{}, t.PathPositions...), ClaimIDs: make([]model.ClaimID, len(t.ClaimLocalKeys)), RuleID: candidates[i].rule, Limitations: append([]model.Limitation{}, t.Limitations...), SuggestedExperiments: append([]string{}, t.SuggestedExperiments...), Selection: model.SelectionNone}
			findingNumber++
			for j, key := range t.ClaimLocalKeys {
				id := candidates[i].local[key]
				if id == "" {
					is = append(is, model.ValidationIssue{Code: model.CodeReferenceMissing, Pointer: "/evaluation", Message: "finding local claim key missing"})
				}
				f.ClaimIDs[j] = id
			}
			evaluated.Findings = append(evaluated.Findings, f)
		}
	}
	if len(is) > 0 {
		model.SortValidationIssues(is)
		return model.ValidatedEvaluatedRun{}, is
	}
	evaluated, selIssues := selection.Apply(evaluated)
	if len(selIssues) > 0 {
		return model.ValidatedEvaluatedRun{}, selIssues
	}
	return model.CanonicalizeAndValidateEvaluatedRun(evaluated)
}

func (e Evaluator) Reevaluate(v model.ValidatedEvaluatedRun, clock time.Time) (model.ValidatedEvaluatedRun, model.ValidationIssues) {
	r := v.Value()
	if r.Evidence.ReportSchemaVersion != (model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}) {
		return model.ValidatedEvaluatedRun{}, model.ValidationIssues{{Code: model.CodeExactVersionRequired, Pointer: "/report_schema_version", Message: "re-evaluation requires exact version"}}
	}
	base, issues := model.ValidateEvidenceRun(r.Evidence)
	if len(issues) != 0 {
		return model.ValidatedEvaluatedRun{}, issues
	}
	return e.Evaluate(base, clock)
}
