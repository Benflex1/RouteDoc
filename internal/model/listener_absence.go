package model

// ListenerAbsenceEvidenceValid applies the single evidence contract used by
// the listener rule and persisted claim validation. A complete visibility
// level is not, by itself, collection provenance: the assessment must cite at
// least one matching-dimension listener inventory entry from the completed
// inventory. The entry may be outside targetPort when the assessment covers a
// broader port range; that is how a nonempty completed inventory proves zero
// matches for the target port without inventing a zero-basis observation.
func ListenerAbsenceEvidenceValid(r EvidenceRun, v VisibilityAssessment, targetPort uint16) bool {
	if v.SubjectKind != VisibilitySubjectListener || v.Level != VisibilityCompleteForScope || v.Scope.Kind != "LISTENER" || v.Scope.Listener == nil || v.VantageID == "" || len(v.BasisObservationIDs) == 0 {
		return false
	}
	s := v.Scope.Listener
	if !s.Protocol.Valid() || !s.AddressFamily.Valid() || !s.BindSemantics.Valid() || s.PortStart > s.PortEnd || targetPort < s.PortStart || targetPort > s.PortEnd || len(v.Limitations) != 0 {
		return false
	}
	observations := make(map[ObservationID]Observation, len(r.Observations))
	for _, o := range r.Observations {
		observations[o.ObservationID] = o
	}
	seen := make(map[ObservationID]bool, len(v.BasisObservationIDs))
	listenerIDs := make(map[EntityID]bool)
	ownershipByListener := make(map[EntityID]bool)
	processes := make([]ProcessOwnershipEntry, 0)
	listenerBasis := 0
	for _, id := range v.BasisObservationIDs {
		if seen[id] {
			return false
		}
		seen[id] = true
		o, ok := observations[id]
		if !ok || o.VantageID == nil || *o.VantageID != v.VantageID || len(o.Limitations) != 0 {
			return false
		}
		switch o.Kind {
		case ObservationListenerInventory:
			if o.Payload.Listener == nil || !listenerEntryMatchesScope(*o.Payload.Listener, *s) {
				return false
			}
			listenerBasis++
			listenerIDs[o.Payload.Listener.ListenerEntityID] = true
		case ObservationProcessOwnership:
			if !s.ProcessOwnershipRequired || o.Payload.ProcessOwnership == nil || !o.Payload.ProcessOwnership.Result.Valid() {
				return false
			}
			processes = append(processes, *o.Payload.ProcessOwnership)
		default:
			return false
		}
	}
	if listenerBasis == 0 {
		return false
	}
	if s.ProcessOwnershipRequired {
		for _, p := range processes {
			if !listenerIDs[p.ListenerEntityID] {
				return false
			}
			ownershipByListener[p.ListenerEntityID] = true
		}
		for id := range listenerIDs {
			if !ownershipByListener[id] {
				return false
			}
		}
	}
	for _, o := range r.Observations {
		if o.Kind != ObservationListenerInventory || o.Payload.Listener == nil || o.VantageID == nil || *o.VantageID != v.VantageID {
			continue
		}
		p := o.Payload.Listener
		if p.NamespaceEntityID == s.NamespaceEntityID && p.Protocol == s.Protocol && p.AddressFamily == s.AddressFamily && p.BindSemantics == s.BindSemantics && p.Port == targetPort {
			return false
		}
	}
	return true
}

func listenerEntryMatchesScope(p ListenerInventoryEntry, s ListenerVisibilityScope) bool {
	return p.NamespaceEntityID == s.NamespaceEntityID && p.Protocol == s.Protocol && p.AddressFamily == s.AddressFamily && p.BindSemantics == s.BindSemantics && p.Port >= s.PortStart && p.Port <= s.PortEnd
}
