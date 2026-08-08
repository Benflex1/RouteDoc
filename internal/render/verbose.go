package render

import (
	"fmt"
	"io"
	"routedoc/internal/model"
)

func reportVerbose(w io.Writer, v model.ValidatedEvaluatedRun) error {
	r := v.Value()
	if err := reportConcise(w, v); err != nil {
		return err
	}
	if err := writeLine(w, "VANTAGE POINTS"); err != nil {
		return err
	}
	for _, p := range r.Evidence.VantagePoints {
		if err := writeLine(w, fmt.Sprintf("- %s kind=%s role=%s label=%s", p.VantageID, p.Kind, p.Role, p.DisplayLabel)); err != nil {
			return err
		}
	}
	if err := writeLine(w, "BRANCHES"); err != nil {
		return err
	}
	for _, b := range r.Evidence.ServicePath.Branches {
		if err := writeLine(w, "- "+branchText(b)); err != nil {
			return err
		}
	}
	if err := writeLine(w, "FINDINGS"); err != nil {
		return err
	}
	for _, f := range r.Findings {
		if err := writeLine(w, fmt.Sprintf("- %s %s level=%s rule=%s selection=%s branches=%v positions=%v claims=%v", f.FindingID, titleText(f.TitleCode), f.Level, f.RuleID, f.Selection, f.BranchIDs, f.PathPositions, f.ClaimIDs)); err != nil {
			return err
		}
		for _, c := range r.Claims {
			for _, id := range f.ClaimIDs {
				if c.ClaimID == id {
					if err := writeLine(w, fmt.Sprintf("  claim %s statement=%s support=[%s] contradiction=[%s]", c.ClaimID, c.StatementCode, refsText(c.SupportingEvidence), refsText(c.ContradictingEvidence))); err != nil {
						return err
					}
				}
			}
		}
	}
	if len(r.Evidence.CheckExecutions) > 0 {
		if err := writeLine(w, "CHECKS"); err != nil {
			return err
		}
		for _, e := range r.Evidence.CheckExecutions {
			if err := writeLine(w, fmt.Sprintf("- %s lifecycle=%s verdict=%s reason=%s observations=%v visibility=%v", e.CheckID, e.Lifecycle, e.Verdict, stringValue(e.ReasonCode), e.ObservationIDs, e.VisibilityAssessmentIDs)); err != nil {
				return err
			}
		}
	}
	return nil
}
func stringValue(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
