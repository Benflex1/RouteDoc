package listener

import (
	"routedoc/internal/model"
	"routedoc/internal/rules/ruleapi"
)

type noMatchingListenerVisible struct{}

func NewNoMatchingListenerVisible() ruleapi.Rule { return noMatchingListenerVisible{} }
func (noMatchingListenerVisible) ID() model.RuleID {
	return model.RuleID("listener.no_matching_listener_visible/v1")
}
func (noMatchingListenerVisible) Evaluate(v model.ValidatedEvidenceRun) []ruleapi.RuleCandidate {
	r := v.Value()
	out := []ruleapi.RuleCandidate{}
	for _, vis := range r.VisibilityAssessments {
		if vis.Scope.Listener == nil || !model.ListenerAbsenceEvidenceValid(r, vis, r.Target.EffectivePort) {
			continue
		}
		s := vis.Scope.Listener
		basis := []ruleapi.EvidenceTemplate{}
		for _, id := range vis.BasisObservationIDs {
			basis = append(basis, ruleapi.EvidenceTemplate{Kind: model.EvidenceKindObservation, ObservationID: id})
		}
		branches, positions := branchesFor(r, vis.VisibilityID)
		c := ruleapi.ClaimTemplate{LocalKey: "absence", StatementCode: model.StatementNoMatchingListenerVisible, Level: model.ClaimLevelInferred, SubjectEntityIDs: []model.EntityID{s.NamespaceEntityID}, BranchIDs: branches, Parameters: model.ClaimParameters{Kind: model.StatementNoMatchingListenerVisible, ListenerAbsent: &model.ListenerAbsentClaimParameters{NamespaceEntityID: s.NamespaceEntityID, VantageID: vis.VantageID, Protocol: s.Protocol, AddressFamily: s.AddressFamily, BindSemantics: s.BindSemantics, Port: s.PortStart}}, SupportingEvidence: append([]ruleapi.EvidenceTemplate{{Kind: model.EvidenceKindVisibility, VisibilityID: vis.VisibilityID}}, basis...), ContradictingEvidence: []ruleapi.EvidenceTemplate{}, RequiredMissingEvidence: []model.MissingEvidenceRequirement{}}
		c.Parameters.ListenerAbsent.Port = r.Target.EffectivePort
		f := ruleapi.FindingTemplate{Kind: model.FindingBlocker, TitleCode: model.TitleNoMatchingListenerVisible, Level: model.ClaimLevelInferred, BranchIDs: append([]model.BranchID{}, branches...), PathPositions: positions, ClaimLocalKeys: []string{"absence"}, Limitations: []model.Limitation{}, SuggestedExperiments: []string{"inspect the listener in the matching namespace"}, Selection: model.SelectionNone}
		out = append(out, ruleapi.RuleCandidate{CandidateKey: "listener-" + string(vis.VisibilityID), Claims: []ruleapi.ClaimTemplate{c}, Findings: []ruleapi.FindingTemplate{f}})
	}
	return out
}
func branchesFor(r model.EvidenceRun, id model.VisibilityID) ([]model.BranchID, []model.PathPosition) {
	var b []model.BranchID
	var p []model.PathPosition
	for _, br := range r.ServicePath.Branches {
		for pos, eid := range br.OrderedEdgeIDs {
			for _, e := range r.ServicePath.Edges {
				if e.EdgeID != eid {
					continue
				}
				for _, x := range e.EvidenceRefs {
					if x.Kind == model.EvidenceKindVisibility && x.VisibilityID != nil && *x.VisibilityID == id {
						b = append(b, br.BranchID)
						p = append(p, model.PathPosition{BranchID: br.BranchID, Position: uint64(pos)})
					}
				}
			}
		}
	}
	return b, p
}
