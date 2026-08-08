package rules

import (
	"sort"

	"routedoc/internal/model"
)

type Registry struct{ rules []Rule }

func NewRegistry(in ...Rule) (Registry, model.ValidationIssues) {
	r := Registry{rules: append([]Rule{}, in...)}
	sort.Slice(r.rules, func(i, j int) bool { return r.rules[i].ID() < r.rules[j].ID() })
	var is model.ValidationIssues
	for i := 1; i < len(r.rules); i++ {
		if r.rules[i-1].ID() == r.rules[i].ID() {
			is = append(is, model.ValidationIssue{Code: model.CodeRegistryDuplicate, Pointer: "/rules", Message: "duplicate rule ID"})
		}
	}
	return r, is
}
func (r Registry) RuleIDs() []model.RuleID {
	v := make([]model.RuleID, len(r.rules))
	for i, x := range r.rules {
		v[i] = x.ID()
	}
	return v
}
func (r Registry) rulesCopy() []Rule { return append([]Rule{}, r.rules...) }
