package v1

import "routedoc/internal/model"

type Operation uint8

const (
	ReadRender Operation = iota
	ReadExplain
	ReadValidate
	CanonicalJSON
	Reevaluate
)

type DecodedReport struct {
	Run      model.EvaluatedRun
	Version  model.SchemaVersion
	Exact    bool
	Warnings model.ValidationIssues
}
