package render

import (
	"fmt"
	"io"
	"routedoc/internal/model"
)

func reportConcise(w io.Writer, v model.ValidatedEvaluatedRun) error {
	r := v.Value()
	if err := writeLine(w, "RouteDoctor report"); err != nil {
		return err
	}
	if err := writeLine(w, "Target: "+targetText(r.Evidence.Target)); err != nil {
		return err
	}
	if err := writeLine(w, "Goal: "+string(r.Evidence.Goal.Kind)); err != nil {
		return err
	}
	if err := writeLine(w, fmt.Sprintf("Vantages: %d  Branches: %d", len(r.Evidence.VantagePoints), len(r.Evidence.ServicePath.Branches))); err != nil {
		return err
	}
	selected := 0
	for _, f := range r.Findings {
		if f.Selection == model.SelectionGlobalPrimary || f.Selection == model.SelectionBranchPrimary {
			selected++
			if err := writeLine(w, fmt.Sprintf("PRIMARY [%s] %s", f.Selection, titleText(f.TitleCode))); err != nil {
				return err
			}
		}
	}
	if selected == 0 {
		if err := writeLine(w, "No primary finding."); err != nil {
			return err
		}
	}
	for _, e := range r.Evidence.CheckExecutions {
		if err := writeLine(w, fmt.Sprintf("Check %s: %s/%s", e.CheckID, e.Lifecycle, e.Verdict)); err != nil {
			return err
		}
	}
	if len(r.Evidence.Limitations) > 0 {
		if err := writeLine(w, fmt.Sprintf("Limitations: %d", len(r.Evidence.Limitations))); err != nil {
			return err
		}
	}
	return nil
}
