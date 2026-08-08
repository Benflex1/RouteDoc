package tcp

import (
	"routedoc/internal/model"
	"routedoc/internal/rules/ruleapi"
)

type connectionRefused struct{}

func NewConnectionRefused() ruleapi.Rule   { return connectionRefused{} }
func (connectionRefused) ID() model.RuleID { return model.RuleID("tcp.connection_refused/v1") }
func (connectionRefused) Evaluate(v model.ValidatedEvidenceRun) []ruleapi.RuleCandidate {
	r := v.Value()
	out := []ruleapi.RuleCandidate{}
	for _, o := range r.Observations {
		if o.Kind != model.ObservationTCPConnection || o.Payload.TCP == nil || o.Payload.TCP.Result != model.TCPRefused || o.VantageID == nil {
			continue
		}
		p := o.Payload.TCP
		contradiction := false
		for _, other := range r.Observations {
			if other.Kind == model.ObservationTCPConnection && other.Payload.TCP != nil && other.Payload.TCP.Result == model.TCPAccepted && other.Payload.TCP.EndpointEntityID == p.EndpointEntityID && other.VantageID != nil && *other.VantageID == *o.VantageID {
				contradiction = true
			}
		}
		if contradiction {
			continue
		}
		branches, positions := branchesFor(r, o.ObservationID)
		c := ruleapi.ClaimTemplate{LocalKey: "refused", StatementCode: model.StatementTCPConnectionRefused, Level: model.ClaimLevelObserved, SubjectEntityIDs: []model.EntityID{p.EndpointEntityID}, BranchIDs: branches, Parameters: model.ClaimParameters{Kind: model.StatementTCPConnectionRefused, TCPRefused: &model.TCPRefusedClaimParameters{EndpointEntityID: p.EndpointEntityID, VantageID: *o.VantageID, ObservedAt: o.ObservedAt}}, SupportingEvidence: []ruleapi.EvidenceTemplate{{Kind: model.EvidenceKindObservation, ObservationID: o.ObservationID}}, ContradictingEvidence: []ruleapi.EvidenceTemplate{}, RequiredMissingEvidence: []model.MissingEvidenceRequirement{}}
		f := ruleapi.FindingTemplate{Kind: model.FindingBlocker, TitleCode: model.TitleTCPConnectionRefused, Level: model.ClaimLevelObserved, BranchIDs: append([]model.BranchID{}, branches...), PathPositions: positions, ClaimLocalKeys: []string{"refused"}, Limitations: []model.Limitation{}, SuggestedExperiments: []string{"compare the endpoint from the same vantage"}, Selection: model.SelectionNone}
		out = append(out, ruleapi.RuleCandidate{CandidateKey: "tcp-" + string(o.ObservationID), Claims: []ruleapi.ClaimTemplate{c}, Findings: []ruleapi.FindingTemplate{f}})
	}
	return out
}
func branchesFor(r model.EvidenceRun, id model.ObservationID) ([]model.BranchID, []model.PathPosition) {
	var b []model.BranchID
	var p []model.PathPosition
	for _, br := range r.ServicePath.Branches {
		for pos, eid := range br.OrderedEdgeIDs {
			for _, e := range r.ServicePath.Edges {
				if e.EdgeID != eid {
					continue
				}
				for _, x := range e.EvidenceRefs {
					if x.Kind == model.EvidenceKindObservation && x.ObservationID != nil && *x.ObservationID == id {
						b = append(b, br.BranchID)
						p = append(p, model.PathPosition{BranchID: br.BranchID, Position: uint64(pos)})
					}
				}
			}
		}
	}
	return b, p
}
