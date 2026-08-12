package localdiagnosis

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"routedoc/internal/clientprobe"
	"routedoc/internal/model"
	"routedoc/internal/rules"
)

type ProbeFunc func(context.Context, string, model.Producer) (model.ValidatedEvaluatedRun, error)

func Diagnose(ctx context.Context, rawURL string, producer model.Producer) (model.ValidatedEvaluatedRun, error) {
	if !platformSupported() {
		return model.ValidatedEvaluatedRun{}, ErrUnsupportedPlatform
	}
	return diagnoseWith(ctx, rawURL, producer, NewOSProcFS(), clientprobe.Diagnose)
}

// DiagnoseWith is the test seam for local report assembly. It is intentionally
// separate from the production entry point so fixture tests can inject both a
// procfs root and a single counted client probe.
func DiagnoseWith(ctx context.Context, rawURL string, producer model.Producer, fs ProcFS, probe ProbeFunc) (model.ValidatedEvaluatedRun, error) {
	return diagnoseWith(ctx, rawURL, producer, fs, probe)
}

func diagnoseWith(ctx context.Context, rawURL string, producer model.Producer, fs ProcFS, probe ProbeFunc) (model.ValidatedEvaluatedRun, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	target, err := clientprobe.ParseTarget(rawURL)
	if err != nil {
		return model.ValidatedEvaluatedRun{}, err
	}
	if probe == nil {
		probe = clientprobe.Diagnose
	}
	inventory := collectWithProcFS(fs, target.EffectivePort)
	clientReport, err := probe(ctx, rawURL, producer)
	if err != nil {
		return model.ValidatedEvaluatedRun{}, err
	}
	evidence := clientReport.Value().Evidence
	addLocalEvidence(&evidence, inventory)
	validated, issues := model.CanonicalizeAndValidateEvidenceRun(evidence)
	if len(issues) > 0 {
		return model.ValidatedEvaluatedRun{}, fmt.Errorf("local diagnosis evidence invalid: %s", issues.Err())
	}
	evaluated, issues := rules.NewEvaluator(rules.DefaultRegistry()).Evaluate(validated, evidence.FinishedAt)
	if len(issues) > 0 {
		return model.ValidatedEvaluatedRun{}, fmt.Errorf("local diagnosis evaluation failed: %s", issues.Err())
	}
	return evaluated, nil
}

type localIDs struct {
	listener int
	process  int
	result   int
	entry    int
	owner    int
	visible  int
	limit    int
}

func (i *localIDs) listenerID() model.EntityID {
	i.listener++
	return model.EntityID(fmt.Sprintf("entity-local-listener-%03d", i.listener))
}
func (i *localIDs) processID(pid uint64) model.EntityID {
	return model.EntityID("entity-local-process-" + strconv.FormatUint(pid, 10))
}
func (i *localIDs) resultID(family model.AddressFamily, binding model.BindSemantics) model.ObservationID {
	i.result++
	return model.ObservationID(fmt.Sprintf("observation-local-result-%s-%s-%03d", familyToken(family), bindingToken(binding), i.result))
}
func (i *localIDs) entryID() model.ObservationID {
	i.entry++
	return model.ObservationID(fmt.Sprintf("observation-local-listener-%03d", i.entry))
}
func (i *localIDs) ownerID() model.ObservationID {
	i.owner++
	return model.ObservationID(fmt.Sprintf("observation-local-owner-%03d", i.owner))
}
func (i *localIDs) visibilityID(family model.AddressFamily, binding model.BindSemantics) model.VisibilityID {
	i.visible++
	return model.VisibilityID(fmt.Sprintf("visibility-local-%s-%s-%03d", familyToken(family), bindingToken(binding), i.visible))
}
func (i *localIDs) limitationID(family model.AddressFamily) model.LimitationID {
	i.limit++
	return model.LimitationID(fmt.Sprintf("limitation-local-procfs-%s-%03d", familyToken(family), i.limit))
}

func addLocalEvidence(evidence *model.EvidenceRun, inventory Inventory) {
	const namespaceID = model.EntityID("entity-local-network-namespace")
	vantageID := model.VantageID("vantage-local-host")
	now := evidence.FinishedAt.UTC()
	if now.IsZero() {
		now = evidence.StartedAt.UTC()
	}
	if now.IsZero() {
		now = time.Unix(0, 0).UTC()
	}

	evidence.Goal = model.Goal{Kind: model.GoalOriginPathDiagnosis}
	evidence.RequestedScope = model.RequestedScope{Kind: model.ScopeLocalOrigin}
	ids := localIDs{}
	vantage := model.VantagePoint{
		VantageID: vantageID, Role: model.VantageRoleOriginHost,
		DisplayLabel: "current proc-visible network namespace", Limitations: []model.Limitation{},
	}
	if inventory.NamespaceComplete {
		vantage.Kind = model.VantageKindHostNamespace
		vantage.Identity = model.VantageIdentity{Kind: model.VantageKindHostNamespace, HostNamespace: &model.HostNamespaceIdentity{NamespaceInode: inventory.NamespaceInode}}
		vantage.Establishment = model.VantageDirectlyObserved
	} else {
		vantage.Kind = model.VantageKindUnknownNamespace
		vantage.Identity = model.VantageIdentity{Kind: model.VantageKindUnknownNamespace, UnknownNamespace: &model.UnknownNamespaceIdentity{ReasonCode: "namespace_identity_unavailable"}}
		vantage.Establishment = model.VantageIdentityUnknown
		limitation := model.Limitation{LimitationID: "limitation-local-namespace-001", Code: model.LimitationUnknownVantage, Scope: model.LimitationScope{Kind: model.LimitationVantage, VantageID: &vantageID}}
		vantage.Limitations = append(vantage.Limitations, limitation)
		evidence.Limitations = append(evidence.Limitations, limitation)
	}
	evidence.VantagePoints = append(evidence.VantagePoints, vantage)
	evidence.Entities = append(evidence.Entities, model.Entity{
		EntityID: namespaceID, Kind: model.EntityNetworkNamespace, DisplayLabel: "current proc-visible network namespace",
		Identity: model.EntityIdentity{Kind: model.EntityNetworkNamespace, Namespace: &model.NamespaceIdentity{NamespaceInode: inventory.NamespaceInode}},
	})
	evidence.ServicePath.Nodes = append(evidence.ServicePath.Nodes, model.PathNode{EntityID: namespaceID})

	listenerIDs := map[uint64]model.EntityID{}
	processIDs := map[uint64]model.EntityID{}
	for _, listener := range inventory.Listeners {
		id := ids.listenerID()
		listenerIDs[listener.Inode] = id
		evidence.Entities = append(evidence.Entities, model.Entity{
			EntityID: id, Kind: model.EntityListener,
			DisplayLabel: listenerEntityLabel(listener.Address, listener.Port),
			Identity:     model.EntityIdentity{Kind: model.EntityListener, Listener: &model.ListenerIdentity{Endpoint: model.EndpointIdentity{Address: listener.Address, Port: listener.Port, Transport: model.TransportTCP}}},
		})
		evidence.ServicePath.Nodes = append(evidence.ServicePath.Nodes, model.PathNode{EntityID: id})
		if owner, ok := inventory.Attribution.Owners[listener.Inode]; ok {
			if processIDs[owner.PID] == "" {
				processIDs[owner.PID] = ids.processID(owner.PID)
				evidence.Entities = append(evidence.Entities, model.Entity{
					EntityID: processIDs[owner.PID], Kind: model.EntityProcess, DisplayLabel: owner.Label,
					Identity: model.EntityIdentity{Kind: model.EntityProcess, Process: &model.ProcessIdentity{PID: owner.PID}},
				})
				evidence.ServicePath.Nodes = append(evidence.ServicePath.Nodes, model.PathNode{EntityID: processIDs[owner.PID]})
			}
		}
	}

	listenerCapabilityState := model.CapabilityUnknown
	listenerReason := "procfs_partial"
	if inventory.NamespaceComplete && inventory.TableComplete[model.AddressFamilyIPv4] && inventory.TableComplete[model.AddressFamilyIPv6] {
		listenerCapabilityState = model.CapabilityAvailable
		listenerReason = "procfs_tcp_tables"
	} else if !inventory.NamespaceComplete {
		listenerReason = "namespace_identity_unavailable"
	}
	evidence.Capabilities = append(evidence.Capabilities,
		model.Capability{CapabilityID: "capability-local-listener-inventory", Kind: model.CapabilityListenerInventory, State: listenerCapabilityState, ReasonCode: listenerReason},
		model.Capability{CapabilityID: "capability-local-process-ownership", Kind: model.CapabilityProcessOwnership, State: capabilityProcessState(inventory.Attribution), ReasonCode: processCapabilityReason(inventory.Attribution)},
	)

	for _, listener := range inventory.Listeners {
		listenerID := listenerIDs[listener.Inode]
		entryID := ids.entryID()
		entry := model.ListenerInventoryEntry{ListenerEntityID: listenerID, NamespaceEntityID: namespaceID, Protocol: model.TransportTCP, AddressFamily: listener.Family, BindSemantics: listener.Binding, Port: listener.Port}
		evidence.Observations = append(evidence.Observations, model.Observation{
			ObservationID: entryID, Kind: model.ObservationListenerInventory, SubjectEntityIDs: []model.EntityID{listenerID, namespaceID}, VantageID: &vantageID, ObservedAt: now,
			Payload: model.ObservationPayload{Kind: model.ObservationListenerInventory, Listener: &entry}, AcquisitionMethod: model.AcquisitionSystemInspection, SourceComponent: model.SourceSocketInspector, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{},
		})
		ownerID := ids.ownerID()
		ownership := model.ProcessOwnershipEntry{ListenerEntityID: listenerID, Result: model.OwnershipUnresolved}
		if owner, ok := inventory.Attribution.Owners[listener.Inode]; ok {
			processID := processIDs[owner.PID]
			ownership.ProcessEntityID = &processID
			ownership.Result = model.OwnershipOwned
		}
		evidence.Observations = append(evidence.Observations, model.Observation{
			ObservationID: ownerID, Kind: model.ObservationProcessOwnership, SubjectEntityIDs: ownershipSubjects(listenerID, namespaceID, ownership.ProcessEntityID), VantageID: &vantageID, ObservedAt: now,
			Payload: model.ObservationPayload{Kind: model.ObservationProcessOwnership, ProcessOwnership: &ownership}, AcquisitionMethod: model.AcquisitionSystemInspection, SourceComponent: model.SourceProcessInspector, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{},
		})
	}

	for _, family := range []model.AddressFamily{model.AddressFamilyIPv4, model.AddressFamilyIPv6} {
		complete := inventory.NamespaceComplete && inventory.TableComplete[family]
		for _, binding := range []model.BindSemantics{model.BindLoopback, model.BindWildcard, model.BindExact} {
			basis := []model.ObservationID{}
			limitations := []model.Limitation{}
			level := model.VisibilityPartial
			if complete {
				count := countListeners(inventory.Listeners, family, binding)
				resultID := ids.resultID(family, binding)
				result := model.ListenerInventoryResult{NamespaceEntityID: namespaceID, Protocol: model.TransportTCP, AddressFamily: family, BindSemantics: binding, PortStart: inventory.Port, PortEnd: inventory.Port, MatchingListenerCount: count}
				evidence.Observations = append(evidence.Observations, model.Observation{
					ObservationID: resultID, Kind: model.ObservationListenerInventoryResult, SubjectEntityIDs: []model.EntityID{namespaceID}, VantageID: &vantageID, ObservedAt: now,
					Payload: model.ObservationPayload{Kind: model.ObservationListenerInventoryResult, ListenerInventoryResult: &result}, AcquisitionMethod: model.AcquisitionSystemInspection, SourceComponent: model.SourceSocketInspector, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{},
				})
				basis = append(basis, resultID)
				level = model.VisibilityCompleteForScope
			} else {
				limitation := model.Limitation{LimitationID: ids.limitationID(family), Code: model.LimitationPartialVisibility, Scope: model.LimitationScope{Kind: model.LimitationVisibility}}
				limitations = append(limitations, limitation)
				evidence.Limitations = append(evidence.Limitations, limitation)
			}
			visibilityID := ids.visibilityID(family, binding)
			evidence.VisibilityAssessments = append(evidence.VisibilityAssessments, model.VisibilityAssessment{
				VisibilityID: visibilityID, SubjectKind: model.VisibilitySubjectListener, VantageID: vantageID,
				Scope: model.VisibilityScope{Kind: "LISTENER", Listener: &model.ListenerVisibilityScope{NamespaceEntityID: namespaceID, Protocol: model.TransportTCP, AddressFamily: family, BindSemantics: binding, PortStart: inventory.Port, PortEnd: inventory.Port, ProcessOwnershipRequired: false}},
				Level: level, BasisObservationIDs: basis, Limitations: limitations, AssessedAt: now,
			})
		}
	}
}

func capabilityProcessState(attribution Attribution) model.CapabilityState {
	if attribution.Complete {
		return model.CapabilityAvailable
	}
	return model.CapabilityUnknown
}

func processCapabilityReason(attribution Attribution) string {
	if attribution.Complete {
		return "proc_fd_scan"
	}
	return "process_ownership_unavailable"
}

func ownershipSubjects(listenerID, namespaceID model.EntityID, processID *model.EntityID) []model.EntityID {
	result := []model.EntityID{listenerID, namespaceID}
	if processID != nil {
		result = append(result, *processID)
	}
	return result
}

func countListeners(listeners []Listener, family model.AddressFamily, binding model.BindSemantics) uint64 {
	var count uint64
	for _, listener := range listeners {
		if listener.Family == family && listener.Binding == binding {
			count++
		}
	}
	return count
}

func familyToken(family model.AddressFamily) string {
	if family == model.AddressFamilyIPv6 {
		return "ipv6"
	}
	return "ipv4"
}

func bindingToken(binding model.BindSemantics) string {
	switch binding {
	case model.BindLoopback:
		return "loopback"
	case model.BindWildcard:
		return "wildcard"
	default:
		return "exact"
	}
}

func listenerEntityLabel(address netip.Addr, port uint16) string {
	return "listener " + strings.ReplaceAll(address.String(), ":", "-") + " port " + strconv.Itoa(int(port))
}
