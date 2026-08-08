package render

import (
	"fmt"
	"io"
	"routedoc/internal/model"
	"sort"
)

type ResolvedEvidence struct {
	Ref           model.EvidenceRef
	Observation   *model.Observation
	Visibility    *model.VisibilityAssessment
	Assertion     *model.OperatorAssertion
	Contradicting bool
}
type Explanation struct {
	Finding  model.Finding
	Claims   []model.Claim
	Evidence []ResolvedEvidence
}

func BuildExplanation(v model.ValidatedEvaluatedRun, id model.FindingID) (Explanation, error) {
	r := v.Value()
	var out Explanation
	var found bool
	for _, f := range r.Findings {
		if f.FindingID == id {
			out.Finding = f
			found = true
			break
		}
	}
	if !found {
		return out, fmt.Errorf("finding %s not found", id)
	}
	by := map[model.ClaimID]model.Claim{}
	for _, c := range r.Claims {
		by[c.ClaimID] = c
	}
	queue := append([]model.ClaimID{}, out.Finding.ClaimIDs...)
	visited := map[model.ClaimID]bool{}
	evidence := map[string]ResolvedEvidence{}
	for len(queue) > 0 {
		cid := queue[0]
		queue = queue[1:]
		if visited[cid] {
			continue
		}
		visited[cid] = true
		c, ok := by[cid]
		if !ok {
			return out, fmt.Errorf("claim %s not found", cid)
		}
		out.Claims = append(out.Claims, c)
		for _, pair := range []struct {
			refs          []model.EvidenceRef
			contradicting bool
		}{{c.SupportingEvidence, false}, {c.ContradictingEvidence, true}} {
			for _, ref := range pair.refs {
				if ref.Kind == model.EvidenceKindClaim && ref.ClaimID != nil {
					if !visited[*ref.ClaimID] {
						queue = append(queue, *ref.ClaimID)
					}
					continue
				}
				key := string(ref.Kind) + ":" + refID(ref)
				if _, ok := evidence[key]; ok {
					continue
				}
				x := ResolvedEvidence{Ref: ref, Contradicting: pair.contradicting}
				switch ref.Kind {
				case model.EvidenceKindObservation:
					for i := range r.Evidence.Observations {
						if ref.ObservationID != nil && r.Evidence.Observations[i].ObservationID == *ref.ObservationID {
							x.Observation = &r.Evidence.Observations[i]
						}
					}
				case model.EvidenceKindVisibility:
					for i := range r.Evidence.VisibilityAssessments {
						if ref.VisibilityID != nil && r.Evidence.VisibilityAssessments[i].VisibilityID == *ref.VisibilityID {
							x.Visibility = &r.Evidence.VisibilityAssessments[i]
						}
					}
				case model.EvidenceKindAssertion:
					for i := range r.Evidence.OperatorAssertions {
						if ref.AssertionID != nil && r.Evidence.OperatorAssertions[i].AssertionID == *ref.AssertionID {
							x.Assertion = &r.Evidence.OperatorAssertions[i]
						}
					}
				}
				evidence[key] = x
			}
		}
	}
	for _, c := range out.Claims {
		_ = c
	}
	keys := make([]string, 0, len(evidence))
	for key := range evidence {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return evidenceKeyLess(keys[i], keys[j]) })
	for _, key := range keys {
		out.Evidence = append(out.Evidence, evidence[key])
	}
	return out, nil
}
func evidenceKeyLess(a, b string) bool {
	order := func(s string) int {
		switch {
		case len(s) >= 12 && s[:12] == "OBSERVATION:":
			return 0
		case len(s) >= 11 && s[:11] == "VISIBILITY:":
			return 1
		case len(s) >= 10 && s[:10] == "ASSERTION:":
			return 2
		}
		return 9
	}
	oa, ob := order(a), order(b)
	if oa != ob {
		return oa < ob
	}
	return a < b
}
func Explain(w io.Writer, v model.ValidatedEvaluatedRun, id model.FindingID, o Options) error {
	e, err := BuildExplanation(v, id)
	if err != nil {
		return err
	}
	if err = writeLine(w, "Explanation: "+titleText(e.Finding.TitleCode)); err != nil {
		return err
	}
	if err = writeLine(w, fmt.Sprintf("Finding %s level=%s rule=%s", e.Finding.FindingID, e.Finding.Level, e.Finding.RuleID)); err != nil {
		return err
	}
	if err = writeLine(w, fmt.Sprintf("Claims: %d  Evidence: %d", len(e.Claims), len(e.Evidence))); err != nil {
		return err
	}
	if o.Verbose {
		for _, c := range e.Claims {
			if err = writeLine(w, fmt.Sprintf("- claim %s %s support=[%s] contradiction=[%s]", c.ClaimID, c.StatementCode, refsText(c.SupportingEvidence), refsText(c.ContradictingEvidence))); err != nil {
				return err
			}
		}
		for _, x := range e.Evidence {
			if err = writeLine(w, fmt.Sprintf("  evidence %s:%s contradicting=%t", x.Ref.Kind, refID(x.Ref), x.Contradicting)); err != nil {
				return err
			}
		}
	}
	return nil
}
