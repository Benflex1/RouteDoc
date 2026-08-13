package render

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"

	"routedoc/internal/model"
)

func isLocalReport(v model.ValidatedEvaluatedRun) bool {
	return v.Value().Evidence.RequestedScope.Kind == model.ScopeLocalOrigin
}

type localListener struct {
	entity model.Entity
	entry  model.ListenerInventoryEntry
	owner  *model.ProcessOwnershipEntry
}

func localListeners(r model.EvidenceRun) []localListener {
	entities := map[model.EntityID]model.Entity{}
	for _, entity := range r.Entities {
		entities[entity.EntityID] = entity
	}
	owners := map[model.EntityID]model.ProcessOwnershipEntry{}
	for _, observation := range r.Observations {
		if observation.Kind == model.ObservationProcessOwnership && observation.Payload.ProcessOwnership != nil {
			owners[observation.Payload.ProcessOwnership.ListenerEntityID] = *observation.Payload.ProcessOwnership
		}
	}
	result := []localListener{}
	for _, observation := range r.Observations {
		if observation.Kind != model.ObservationListenerInventory || observation.Payload.Listener == nil {
			continue
		}
		entry := *observation.Payload.Listener
		entity, ok := entities[entry.ListenerEntityID]
		if !ok || entity.Identity.Listener == nil {
			continue
		}
		item := localListener{entity: entity, entry: entry}
		if owner, ok := owners[entry.ListenerEntityID]; ok {
			item.owner = &owner
		}
		result = append(result, item)
	}
	sort.SliceStable(result, func(i, j int) bool {
		left, right := result[i].entity.Identity.Listener.Endpoint, result[j].entity.Identity.Listener.Endpoint
		if left.Address != right.Address {
			return left.Address.Compare(right.Address) < 0
		}
		return left.Port < right.Port
	})
	return result
}

func localVisibility(r model.EvidenceRun) (complete, partial bool) {
	for _, visibility := range r.VisibilityAssessments {
		if visibility.Scope.Listener == nil || visibility.Scope.Listener.PortStart != r.Target.EffectivePort || visibility.Scope.Listener.PortEnd != r.Target.EffectivePort {
			continue
		}
		switch visibility.Level {
		case model.VisibilityCompleteForScope:
			complete = true
		case model.VisibilityPartial, model.VisibilityUnknown:
			partial = true
		}
	}
	return complete, partial
}

func reportLocalConcise(w io.Writer, v model.ValidatedEvaluatedRun) error {
	r := v.Value()
	if err := writeLine(w, "RouteDoctor — local service "+clientTargetText(r.Evidence.Target)); err != nil {
		return err
	}
	listeners := localListeners(r.Evidence)
	complete, partial := localVisibility(r.Evidence)
	if len(listeners) == 0 {
		if complete && !partial {
			if err := writeLine(w, fmt.Sprintf("Listener   ✗ nothing listening on TCP port %d", r.Evidence.Target.EffectivePort)); err != nil {
				return err
			}
		} else {
			if err := writeLine(w, "Listener   ⚠ inventory unavailable or incomplete"); err != nil {
				return err
			}
		}
	} else {
		for _, listener := range listeners {
			if err := writeLine(w, "Listener   ✓ "+listenerEndpoint(listener.entity)); err != nil {
				return err
			}
		}
	}
	if len(listeners) > 0 && partial {
		if err := writeLine(w, "Listener   ⚠ visibility is partial; some procfs listener tables were unavailable"); err != nil {
			return err
		}
	}

	if len(listeners) > 0 {
		seenProcesses := map[string]bool{}
		ownershipUnavailable := false
		for _, listener := range listeners {
			if listener.owner == nil || listener.owner.Result != model.OwnershipOwned || listener.owner.ProcessEntityID == nil {
				ownershipUnavailable = true
				continue
			}
			processLabel := processLabel(r.Evidence.Entities, *listener.owner.ProcessEntityID)
			if !seenProcesses[processLabel] {
				seenProcesses[processLabel] = true
				if err := writeLine(w, "Process    ✓ "+processLabel); err != nil {
					return err
				}
			}
		}
		if ownershipUnavailable {
			if err := writeLine(w, "Process    ⚠ ownership unavailable"); err != nil {
				return err
			}
		}
	}

	writeProbeSummary := func() error {
		tcp, tcpSeen := localTCPStatus(r.Evidence)
		if tcpSeen {
			if err := writeLine(w, "TCP        "+tcp); err != nil {
				return err
			}
		} else if err := writeLine(w, "TCP        — not attempted"); err != nil {
			return err
		}
		if r.Evidence.Target.Scheme == "https" {
			tls, tlsSeen := localTLSStatus(r.Evidence)
			if tlsSeen {
				if err := writeLine(w, "TLS        "+tls); err != nil {
					return err
				}
			} else if err := writeLine(w, "TLS        — not attempted"); err != nil {
				return err
			}
		}
		http, httpSeen := localHTTPStatus(r.Evidence)
		if httpSeen {
			return writeLine(w, "HTTP       "+http)
		}
		return writeLine(w, "HTTP       — not completed")
	}
	if err := writeProbeSummary(); err != nil {
		return err
	}

	if len(listeners) == 0 && complete && !partial {
		if err := writeLine(w, "No matching TCP listener was observed on this machine in the current network namespace."); err != nil {
			return err
		}
	} else if len(listeners) == 0 && (partial || !complete) {
		if err := writeLine(w, "Listener visibility was incomplete; no listener-absence conclusion is drawn."); err != nil {
			return err
		}
	} else if allLoopback(listeners) && complete && !partial {
		if err := writeLine(w, "The service is listening only on loopback."); err != nil {
			return err
		}
		if err := writeLine(w, "Direct connections to this port through non-loopback local addresses will not reach these listeners."); err != nil {
			return err
		}
	}
	if localHTTPSucceeded(r.Evidence) {
		return writeLine(w, "Local service is reachable.")
	}
	if len(listeners) > 0 {
		return writeLine(w, "A matching listener was observed, but the local TCP/TLS/HTTP probe did not succeed.")
	}
	return nil
}

func reportLocalVerbose(w io.Writer, v model.ValidatedEvaluatedRun) error {
	if err := reportLocalConcise(w, v); err != nil {
		return err
	}
	r := v.Value()
	if err := writeLine(w, "LOCAL LISTENER EVIDENCE"); err != nil {
		return err
	}
	entities := map[model.EntityID]model.Entity{}
	for _, entity := range r.Evidence.Entities {
		entities[entity.EntityID] = entity
	}
	for _, observation := range r.Evidence.Observations {
		switch observation.Kind {
		case model.ObservationListenerInventory:
			if observation.Payload.Listener == nil {
				continue
			}
			entry := observation.Payload.Listener
			if entity := entities[entry.ListenerEntityID]; entity.Identity.Listener != nil {
				if err := writeLine(w, fmt.Sprintf("- %s address=%s family=%s port=%d binding=%s", observation.ObservationID, listenerEndpoint(entity), entry.AddressFamily, entry.Port, entry.BindSemantics)); err != nil {
					return err
				}
			}
		case model.ObservationProcessOwnership:
			if observation.Payload.ProcessOwnership == nil {
				continue
			}
			ownership := observation.Payload.ProcessOwnership
			process := ""
			if ownership.ProcessEntityID != nil {
				process = string(*ownership.ProcessEntityID)
			}
			if err := writeLine(w, fmt.Sprintf("- %s listener=%s result=%s process=%s", observation.ObservationID, ownership.ListenerEntityID, ownership.Result, process)); err != nil {
				return err
			}
		case model.ObservationListenerInventoryResult:
			if observation.Payload.ListenerInventoryResult == nil {
				continue
			}
			result := observation.Payload.ListenerInventoryResult
			if err := writeLine(w, fmt.Sprintf("- %s family=%s port=%d binding=%s matching=%d", observation.ObservationID, result.AddressFamily, result.PortStart, result.BindSemantics, result.MatchingListenerCount)); err != nil {
				return err
			}
		}
	}
	if err := writeLine(w, "LOCAL VISIBILITY"); err != nil {
		return err
	}
	for _, visibility := range r.Evidence.VisibilityAssessments {
		if visibility.Scope.Listener == nil || visibility.Scope.Listener.PortStart != r.Evidence.Target.EffectivePort {
			continue
		}
		if err := writeLine(w, fmt.Sprintf("- %s level=%s family=%s binding=%s basis=%v limitations=%v", visibility.VisibilityID, visibility.Level, visibility.Scope.Listener.AddressFamily, visibility.Scope.Listener.BindSemantics, visibility.BasisObservationIDs, visibility.Limitations)); err != nil {
			return err
		}
	}
	if err := writeLine(w, "CLIENT PROBE EVIDENCE"); err != nil {
		return err
	}
	for _, execution := range r.Evidence.CheckExecutions {
		if err := writeLine(w, fmt.Sprintf("- %s check=%s lifecycle=%s verdict=%s reason=%s observations=%v", execution.ExecutionID, execution.CheckID, execution.Lifecycle, execution.Verdict, stringValue(execution.ReasonCode), execution.ObservationIDs)); err != nil {
			return err
		}
	}
	return nil
}

func listenerEndpoint(entity model.Entity) string {
	if entity.Identity.Listener == nil {
		return "unknown listener"
	}
	endpoint := entity.Identity.Listener.Endpoint
	return net.JoinHostPort(endpoint.Address.String(), strconv.Itoa(int(endpoint.Port)))
}

func processLabel(entities []model.Entity, id model.EntityID) string {
	for _, entity := range entities {
		if entity.EntityID == id {
			return entity.DisplayLabel
		}
	}
	return string(id)
}

func allLoopback(listeners []localListener) bool {
	if len(listeners) == 0 {
		return false
	}
	for _, listener := range listeners {
		if listener.entry.BindSemantics != model.BindLoopback {
			return false
		}
	}
	return true
}

func localTCPStatus(r model.EvidenceRun) (string, bool) {
	seen := false
	for _, observation := range r.Observations {
		if observation.Payload.TCP == nil {
			continue
		}
		seen = true
		if observation.Payload.TCP.Result == model.TCPAccepted {
			return "✓ connection accepted", true
		}
	}
	if seen {
		return "✗ connection failed", true
	}
	return "", false
}

func localTLSStatus(r model.EvidenceRun) (string, bool) {
	seen := false
	for _, observation := range r.Observations {
		if observation.Payload.TLSTransport == nil {
			continue
		}
		seen = true
		if observation.Payload.TLSTransport.Result == model.TLSTransportCompleted {
			return "✓ handshake completed", true
		}
	}
	if seen {
		return "✗ handshake failed", true
	}
	return "", false
}

func localHTTPStatus(r model.EvidenceRun) (string, bool) {
	for _, observation := range r.Observations {
		if observation.Payload.HTTP == nil || !observation.Payload.HTTP.ResultKind.Valid() {
			continue
		}
		return "✓ " + strconv.Itoa(int(observation.Payload.HTTP.StatusCode)), true
	}
	return "", false
}

func localHTTPSucceeded(r model.EvidenceRun) bool {
	_, ok := localHTTPStatus(r)
	return ok
}
