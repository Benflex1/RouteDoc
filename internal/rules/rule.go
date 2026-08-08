package rules

import (
	"routedoc/internal/model"
	"routedoc/internal/rules/ruleapi"
)

type Rule = ruleapi.Rule
type RuleCandidate = ruleapi.RuleCandidate
type ClaimTemplate = ruleapi.ClaimTemplate
type FindingTemplate = ruleapi.FindingTemplate
type EvidenceTemplate = ruleapi.EvidenceTemplate

var _ model.RuleID
