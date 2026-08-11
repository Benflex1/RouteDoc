package render

import (
	"io"
	"routedoc/internal/model"
)

type Options struct{ Verbose bool }

func Report(w io.Writer, v model.ValidatedEvaluatedRun, o Options) error {
	if isClientReport(v) {
		if o.Verbose {
			return reportClientVerbose(w, v)
		}
		return reportClientConcise(w, v)
	}
	if o.Verbose {
		return reportVerbose(w, v)
	}
	return reportConcise(w, v)
}
