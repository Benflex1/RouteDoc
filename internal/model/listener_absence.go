package model

import (
	"net/netip"
	"time"
)

// ListenerVisibilityComplete applies the listener completeness contract. A
// COMPLETE_FOR_SCOPE level is grounded only by a successful, typed inventory
// result whose scope covers the entire visibility scope. Listener entries and
// execution state are supplementary facts; neither can authenticate
// completeness.
func ListenerVisibilityComplete(r EvidenceRun, v VisibilityAssessment) bool {
	if v.SubjectKind != VisibilitySubjectListener || v.Level != VisibilityCompleteForScope || v.Scope.Kind != "LISTENER" || v.Scope.Listener == nil || v.VantageID == "" || len(v.BasisObservationIDs) == 0 || len(v.Limitations) != 0 {
		return false
	}
	s := v.Scope.Listener
	if !listenerVisibilityScopeValid(*s) {
		return false
	}
	if !listenerNamespaceMatchesVantage(r, s.NamespaceEntityID, v.VantageID) {
		return false
	}
	observations := observationsByID(r.Observations)
	seen := make(map[ObservationID]bool, len(v.BasisObservationIDs))
	results := make([]ListenerInventoryResult, 0, 1)
	entries := make([]ListenerInventoryEntry, 0)
	ownership := make([]ProcessOwnershipEntry, 0)
	for _, id := range v.BasisObservationIDs {
		if seen[id] {
			return false
		}
		seen[id] = true
		o, ok := observations[id]
		if !ok || o.VantageID == nil || *o.VantageID != v.VantageID || len(o.Limitations) != 0 || !listenerObservationTimeCoherent(r, o.ObservedAt, v.AssessedAt) {
			return false
		}
		switch o.Kind {
		case ObservationListenerInventoryResult:
			if o.Payload.ListenerInventoryResult == nil || !listenerInventoryResultMatchesVisibility(*o.Payload.ListenerInventoryResult, v) {
				return false
			}
			results = append(results, *o.Payload.ListenerInventoryResult)
		case ObservationListenerInventory:
			if o.Payload.Listener == nil || !listenerEntryMatchesScope(*o.Payload.Listener, *s) {
				return false
			}
			entries = append(entries, *o.Payload.Listener)
		case ObservationProcessOwnership:
			if !s.ProcessOwnershipRequired || o.Payload.ProcessOwnership == nil {
				return false
			}
			ownership = append(ownership, *o.Payload.ProcessOwnership)
		default:
			return false
		}
	}
	if len(results) == 0 {
		return false
	}
	result := results[0]
	for _, candidate := range results[1:] {
		if candidate != result {
			return false
		}
	}
	if !s.ProcessOwnershipRequired {
		return true
	}
	if result.MatchingListenerCount == 0 {
		// An empty completed inventory has no listener whose ownership could be
		// mapped. Ownership observations cannot manufacture one.
		return len(ownership) == 0
	}
	if result.PortStart != s.PortStart || result.PortEnd != s.PortEnd {
		return false
	}
	listenerKeys := make(map[concreteListenerIdentity]bool)
	for _, entry := range entries {
		key, ok := concreteListenerKey(r, entry)
		if !ok {
			return false
		}
		listenerKeys[key] = true
	}
	if uint64(len(listenerKeys)) != result.MatchingListenerCount {
		return false
	}
	owned := make(map[concreteListenerIdentity]bool)
	for _, item := range ownership {
		if item.Result != OwnershipOwned || item.ProcessEntityID == nil {
			return false
		}
		entry := ListenerInventoryEntry{ListenerEntityID: item.ListenerEntityID, NamespaceEntityID: s.NamespaceEntityID, Protocol: s.Protocol, AddressFamily: s.AddressFamily, BindSemantics: s.BindSemantics, Port: s.PortStart}
		key, ok := concreteListenerKey(r, entry)
		if !ok || !listenerKeys[key] {
			return false
		}
		owned[key] = true
	}
	if len(owned) != len(listenerKeys) {
		return false
	}
	for key := range listenerKeys {
		if !owned[key] {
			return false
		}
	}
	return true
}

// listenerVisibilityBasisIssueCode gives validators the stable distinction
// between an absent completion result, a vantage mismatch, and a mismatched
// typed scope. A nonzero return is the code to report for a complete
// assessment that is not grounded.
func listenerVisibilityBasisIssueCode(r EvidenceRun, v VisibilityAssessment) ValidationCode {
	if len(v.BasisObservationIDs) == 0 {
		return CodeVisibilityInsufficientForAbsence
	}
	observations := observationsByID(r.Observations)
	hasResult := false
	hasSameVantage := false
	for _, id := range v.BasisObservationIDs {
		o, ok := observations[id]
		if !ok || o.Kind != ObservationListenerInventoryResult {
			continue
		}
		hasResult = true
		if o.VantageID == nil || *o.VantageID != v.VantageID {
			continue
		}
		hasSameVantage = true
		if o.Payload.ListenerInventoryResult == nil {
			return CodeVisibilityInsufficientForAbsence
		}
		p := o.Payload.ListenerInventoryResult
		s := v.Scope.Listener
		if s == nil || p.NamespaceEntityID != s.NamespaceEntityID || p.Protocol != s.Protocol || p.AddressFamily != s.AddressFamily || p.BindSemantics != s.BindSemantics || p.PortStart > s.PortStart || p.PortEnd < s.PortEnd {
			return CodeVisibilityScopeMismatch
		}
		if len(o.Limitations) != 0 || !listenerObservationTimeCoherent(r, o.ObservedAt, v.AssessedAt) {
			return CodeVisibilityInsufficientForAbsence
		}
	}
	if hasResult && !hasSameVantage {
		return CodeVantageMismatch
	}
	if !hasResult {
		return CodeVisibilityInsufficientForAbsence
	}
	return ""
}

// ListenerAbsenceEvidenceValid applies the single evidence contract used by
// the listener rule and persisted claim validation. The claim's single port
// is treated as the degenerate range [targetPort, targetPort] only for these
// containment and contradiction checks.
func ListenerAbsenceEvidenceValid(r EvidenceRun, v VisibilityAssessment, targetPort uint16) bool {
	if !ListenerVisibilityComplete(r, v) || v.Scope.Listener == nil {
		return false
	}
	s := v.Scope.Listener
	if targetPort < s.PortStart || targetPort > s.PortEnd {
		return false
	}
	observations := observationsByID(r.Observations)
	hasZeroResult := false
	for _, id := range v.BasisObservationIDs {
		o, ok := observations[id]
		if !ok || o.Kind != ObservationListenerInventoryResult || o.Payload.ListenerInventoryResult == nil {
			continue
		}
		if o.Payload.ListenerInventoryResult.MatchingListenerCount != 0 {
			return false
		}
		hasZeroResult = true
	}
	if !hasZeroResult {
		return false
	}
	for _, o := range r.Observations {
		if o.VantageID == nil || *o.VantageID != v.VantageID || !listenerObservationTimeCoherent(r, o.ObservedAt, v.AssessedAt) {
			continue
		}
		switch o.Kind {
		case ObservationListenerInventory:
			if o.Payload.Listener == nil {
				continue
			}
			p := o.Payload.Listener
			if p.NamespaceEntityID == s.NamespaceEntityID && p.Protocol == s.Protocol && p.AddressFamily == s.AddressFamily && p.BindSemantics == s.BindSemantics && p.Port == targetPort {
				return false
			}
		case ObservationListenerInventoryResult:
			if o.Payload.ListenerInventoryResult == nil || o.Payload.ListenerInventoryResult.MatchingListenerCount == 0 {
				continue
			}
			p := o.Payload.ListenerInventoryResult
			if o.Payload.ListenerInventoryResult.NamespaceEntityID == s.NamespaceEntityID && p.Protocol == s.Protocol && p.AddressFamily == s.AddressFamily && p.BindSemantics == s.BindSemantics && p.PortStart >= targetPort && p.PortEnd <= targetPort {
				return false
			}
		}
	}
	return true
}

// ListenerAbsenceEvidenceIssueCode mirrors ListenerAbsenceEvidenceValid for
// persisted-report diagnostics. It deliberately exposes only the stable
// architecture codes: a typed vantage mismatch, a mismatched listener scope,
// or insufficient/contradictory absence evidence.
func ListenerAbsenceEvidenceIssueCode(r EvidenceRun, v VisibilityAssessment, targetPort uint16) ValidationCode {
	if v.Scope.Listener == nil || v.Scope.Kind != "LISTENER" {
		return CodeVisibilityInsufficientForAbsence
	}
	s := v.Scope.Listener
	if targetPort < s.PortStart || targetPort > s.PortEnd {
		return CodeVisibilityScopeMismatch
	}
	if code := listenerVisibilityBasisIssueCode(r, v); code == CodeVantageMismatch || code == CodeVisibilityScopeMismatch {
		return code
	}
	if !ListenerVisibilityComplete(r, v) {
		return CodeVisibilityInsufficientForAbsence
	}
	observations := observationsByID(r.Observations)
	hasZeroResult := false
	for _, id := range v.BasisObservationIDs {
		o, ok := observations[id]
		if !ok || o.Kind != ObservationListenerInventoryResult || o.Payload.ListenerInventoryResult == nil {
			continue
		}
		if o.Payload.ListenerInventoryResult.MatchingListenerCount != 0 {
			return CodeVisibilityInsufficientForAbsence
		}
		hasZeroResult = true
	}
	if !hasZeroResult {
		return CodeVisibilityInsufficientForAbsence
	}
	if !ListenerAbsenceEvidenceValid(r, v, targetPort) {
		return CodeVisibilityInsufficientForAbsence
	}
	return ""
}

func listenerVisibilityScopeValid(s ListenerVisibilityScope) bool {
	return s.NamespaceEntityID.Valid() && s.Protocol.Valid() && s.AddressFamily.Valid() && s.BindSemantics.Valid() && s.PortStart <= s.PortEnd
}

func listenerInventoryResultMatchesVisibility(p ListenerInventoryResult, v VisibilityAssessment) bool {
	s := v.Scope.Listener
	return s != nil && p.NamespaceEntityID == s.NamespaceEntityID && p.Protocol == s.Protocol && p.AddressFamily == s.AddressFamily && p.BindSemantics == s.BindSemantics && p.PortStart <= s.PortStart && p.PortEnd >= s.PortEnd
}

func listenerEntryMatchesScope(p ListenerInventoryEntry, s ListenerVisibilityScope) bool {
	return p.NamespaceEntityID == s.NamespaceEntityID && p.Protocol == s.Protocol && p.AddressFamily == s.AddressFamily && p.BindSemantics == s.BindSemantics && p.Port >= s.PortStart && p.Port <= s.PortEnd
}

func observationsByID(all []Observation) map[ObservationID]Observation {
	out := make(map[ObservationID]Observation, len(all))
	for _, o := range all {
		out[o.ObservationID] = o
	}
	return out
}

func listenerObservationTimeCoherent(r EvidenceRun, observedAt, assessedAt time.Time) bool {
	if r.Policy.CoherenceWindowNS < 0 {
		return false
	}
	delta := observedAt.Sub(assessedAt)
	if delta < 0 {
		delta = -delta
	}
	return delta <= time.Duration(r.Policy.CoherenceWindowNS)
}

type concreteListenerIdentity struct {
	Namespace EntityID
	Address   netip.Addr
	Port      uint16
	Protocol  Transport
}

func concreteListenerKey(r EvidenceRun, entry ListenerInventoryEntry) (concreteListenerIdentity, bool) {
	for _, entity := range r.Entities {
		if entity.EntityID != entry.ListenerEntityID || entity.Kind != EntityListener || entity.Identity.Listener == nil {
			continue
		}
		ep := entity.Identity.Listener.Endpoint
		return concreteListenerIdentity{Namespace: entry.NamespaceEntityID, Address: ep.Address, Port: ep.Port, Protocol: ep.Transport}, true
	}
	return concreteListenerIdentity{}, false
}

func listenerNamespaceMatchesVantage(r EvidenceRun, namespaceID EntityID, vantageID VantageID) bool {
	var namespace *NamespaceIdentity
	for _, entity := range r.Entities {
		if entity.EntityID == namespaceID && entity.Kind == EntityNetworkNamespace {
			namespace = entity.Identity.Namespace
			break
		}
	}
	if namespace == nil {
		return false
	}
	for _, vantage := range r.VantagePoints {
		if vantage.VantageID != vantageID {
			continue
		}
		return vantage.Kind == VantageKindHostNamespace && vantage.Identity.HostNamespace != nil && vantage.Identity.HostNamespace.NamespaceInode == namespace.NamespaceInode
	}
	return false
}
