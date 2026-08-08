package ruleapi

import (
	"testing"
	"time"

	"routedoc/internal/model"
)

func TestRuleContractCompiles(t *testing.T) {
	var _ Rule = testRule{}
	r := testRule{id: "test.rule/v1"}
	if r.ID() != "test.rule/v1" {
		t.Fatal()
	}
	if len(r.Evaluate(model.ValidatedEvidenceRun{})) != 0 {
		t.Fatal()
	}
}

type testRule struct{ id model.RuleID }

func (r testRule) ID() model.RuleID                                    { return r.id }
func (r testRule) Evaluate(model.ValidatedEvidenceRun) []RuleCandidate { return nil }

var _ = time.UTC
