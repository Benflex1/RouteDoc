package render

import (
	"io"
	"routedoc/internal/model"
)

type Options struct{ Verbose bool }

func Report(w io.Writer, v model.ValidatedEvaluatedRun, o Options) error {
	if o.Verbose {
		return reportVerbose(w, v)
	}
	return reportConcise(w, v)
}
