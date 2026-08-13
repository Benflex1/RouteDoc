package listener

import (
	"net/netip"

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
	localDiagnosis := r.RequestedScope.Kind == model.ScopeLocalOrigin
	out := []ruleapi.RuleCandidate{}
	for _, vis := range r.VisibilityAssessments {
		if vis.Scope.Listener == nil || (localDiagnosis && !scopeAppliesToTarget(r, vis.Scope.Listener.AddressFamily)) || !model.ListenerAbsenceEvidenceValid(r, vis, r.Target.EffectivePort) {
			continue
		}
		if localDiagnosis && hasCompatibleListener(r, *vis.Scope.Listener) {
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

// hasCompatibleListener prevents an empty binding bucket from becoming an
// absence conclusion when another observed listener covers the target
// destination. The inventory buckets remain separate evidence; compatibility
// is considered only while deciding whether to emit this blocker.
func hasCompatibleListener(r model.EvidenceRun, scope model.ListenerVisibilityScope) bool {
	destinations := targetDestinations(r, scope.AddressFamily)
	if len(destinations) == 0 {
		return false
	}
	entities := map[model.EntityID]model.Entity{}
	for _, entity := range r.Entities {
		entities[entity.EntityID] = entity
	}
	for _, observation := range r.Observations {
		if observation.Kind != model.ObservationListenerInventory || observation.Payload.Listener == nil {
			continue
		}
		entry := observation.Payload.Listener
		if entry.NamespaceEntityID != scope.NamespaceEntityID || entry.Protocol != scope.Protocol || entry.Port != scope.PortStart {
			continue
		}
		entity, ok := entities[entry.ListenerEntityID]
		if !ok || entity.Identity.Listener == nil {
			continue
		}
		endpoint := entity.Identity.Listener.Endpoint
		if endpoint.Transport != model.TransportTCP || endpoint.Port != scope.PortStart || addressFamily(endpoint.Address) != scope.AddressFamily {
			continue
		}
		for _, destination := range destinations {
			if bindingCovers(entry.BindSemantics, endpoint.Address, destination) {
				return true
			}
		}
	}
	return false
}

func scopeAppliesToTarget(r model.EvidenceRun, family model.AddressFamily) bool {
	if len(targetDestinations(r, family)) > 0 {
		return true
	}
	if address, err := netip.ParseAddr(r.Target.Hostname); err == nil {
		return addressFamily(address) == family
	}
	for _, entity := range r.Entities {
		if entity.Kind == model.EntitySocketEndpoint && entity.Identity.Endpoint != nil && entity.Identity.Endpoint.Transport == model.TransportTCP && entity.Identity.Endpoint.Port == r.Target.EffectivePort {
			return false
		}
	}
	// Preserve the existing rule behavior for hostname-only evidence that does
	// not expose a concrete destination address.
	return true
}

func targetDestinations(r model.EvidenceRun, family model.AddressFamily) []netip.Addr {
	result := []netip.Addr{}
	for _, entity := range r.Entities {
		if entity.Kind != model.EntitySocketEndpoint || entity.Identity.Endpoint == nil {
			continue
		}
		endpoint := entity.Identity.Endpoint
		if endpoint.Transport == model.TransportTCP && endpoint.Port == r.Target.EffectivePort && addressFamily(endpoint.Address) == family {
			result = appendUniqueAddress(result, endpoint.Address)
		}
	}
	if address, err := netip.ParseAddr(r.Target.Hostname); err == nil && addressFamily(address) == family {
		result = appendUniqueAddress(result, address)
	}
	return result
}

func appendUniqueAddress(addresses []netip.Addr, address netip.Addr) []netip.Addr {
	for _, existing := range addresses {
		if existing == address {
			return addresses
		}
	}
	return append(addresses, address)
}

func addressFamily(address netip.Addr) model.AddressFamily {
	if address.Is6() {
		return model.AddressFamilyIPv6
	}
	return model.AddressFamilyIPv4
}

func bindingCovers(binding model.BindSemantics, listener, destination netip.Addr) bool {
	switch binding {
	case model.BindExact:
		return listener == destination
	case model.BindWildcard:
		return listener.IsUnspecified()
	case model.BindLoopback:
		return destination == netip.MustParseAddr("127.0.0.1") || destination == netip.MustParseAddr("::1")
	default:
		return false
	}
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
