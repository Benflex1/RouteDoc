package ruleapi

import "routedoc/internal/model"

type Rule interface {
	ID() model.RuleID
	Evaluate(model.ValidatedEvidenceRun) []RuleCandidate
}
type EvidenceTemplate struct {
	Kind          model.EvidenceKind
	ObservationID model.ObservationID
	ClaimLocalKey string
	VisibilityID  model.VisibilityID
	AssertionID   model.AssertionID
}
type ClaimTemplate struct {
	LocalKey                string
	StatementCode           model.ClaimStatementCode
	Level                   model.ClaimLevel
	SubjectEntityIDs        []model.EntityID
	BranchIDs               []model.BranchID
	Parameters              model.ClaimParameters
	SupportingEvidence      []EvidenceTemplate
	ContradictingEvidence   []EvidenceTemplate
	RequiredMissingEvidence []model.MissingEvidenceRequirement
}
type FindingTemplate struct {
	Kind                 model.FindingKind
	TitleCode            model.FindingTitleCode
	Level                model.ClaimLevel
	BranchIDs            []model.BranchID
	PathPositions        []model.PathPosition
	ClaimLocalKeys       []string
	Limitations          []model.Limitation
	SuggestedExperiments []string
	Selection            model.Selection
}
type RuleCandidate struct {
	CandidateKey string
	Claims       []ClaimTemplate
	Findings     []FindingTemplate
}
