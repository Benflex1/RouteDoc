package clientprobe

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"routedoc/internal/model"
)

type idAllocator struct {
	entity, edge, branch, check, execution, observation, limitation int
}

func (a *idAllocator) entityID() model.EntityID {
	a.entity++
	return model.EntityID(fmt.Sprintf("entity-%06d", a.entity))
}
func (a *idAllocator) edgeID() model.EdgeID {
	a.edge++
	return model.EdgeID(fmt.Sprintf("edge-%06d", a.edge))
}
func (a *idAllocator) branchID() model.BranchID {
	a.branch++
	return model.BranchID(fmt.Sprintf("branch-%06d", a.branch))
}
func (a *idAllocator) checkID() model.CheckID {
	a.check++
	return model.CheckID(fmt.Sprintf("check-%06d", a.check))
}
func (a *idAllocator) executionID() model.ExecutionID {
	a.execution++
	return model.ExecutionID(fmt.Sprintf("execution-%06d", a.execution))
}
func (a *idAllocator) observationID() model.ObservationID {
	a.observation++
	return model.ObservationID(fmt.Sprintf("observation-%06d", a.observation))
}
func (a *idAllocator) limitationID() model.LimitationID {
	a.limitation++
	return model.LimitationID(fmt.Sprintf("limitation-%06d", a.limitation))
}

func assembleEvidence(f runFacts) model.EvidenceRun {
	now := f.started.UTC()
	if now.IsZero() {
		now = time.Unix(0, 0).UTC()
	}
	finished := f.finished.UTC()
	if finished.IsZero() || finished.Before(now) {
		finished = now
	}
	plans := mergeEndpointPlans(f)
	_, retainedTruncated := retainAddresses(f.resolution.addresses)
	if retainedTruncated {
		f.resolution.truncated = true
	}
	if len(f.endpoints) == 0 && len(f.resolution.addresses) > 0 {
		plans = mergeEndpointPlans(runFacts{endpoints: planEndpoints(f.resolution.addresses, f.target.persisted.EffectivePort), normal: f.normal})
	}
	if f.resolution.truncated {
		found := false
		for _, x := range f.limitations {
			if x.Code == model.LimitationPartialVisibility {
				found = true
			}
		}
		if !found {
			f.limitations = append(f.limitations, model.Limitation{Code: model.LimitationPartialVisibility, Scope: model.LimitationScope{Kind: model.LimitationRun}})
		}
	}

	var ids idAllocator
	targetID := ids.entityID()
	hostID := ids.entityID()
	vID := model.VantageID(vantageID())
	entities := []model.Entity{
		{EntityID: targetID, Kind: model.EntityURLTarget, DisplayLabel: "URL target", Identity: model.EntityIdentity{Kind: model.EntityURLTarget, URLTarget: &model.URLTargetIdentity{Marker: true}}},
		{EntityID: hostID, Kind: model.EntityHostname, DisplayLabel: f.target.persisted.Hostname, Identity: model.EntityIdentity{Kind: model.EntityHostname, Hostname: &model.HostnameIdentity{Hostname: f.target.persisted.Hostname}}},
	}
	addressIDs := map[netip.Addr]model.EntityID{}
	endpointIDs := map[endpointKey]model.EntityID{}
	for _, p := range plans {
		if p.retained {
			id := ids.entityID()
			addressIDs[p.key.address] = id
			entities = append(entities, model.Entity{EntityID: id, Kind: model.EntityIPAddress, DisplayLabel: safeAddressLabel(p.key.address), Identity: model.EntityIdentity{Kind: model.EntityIPAddress, IPAddress: &model.IPAddressIdentity{Address: p.key.address}}})
		}
		id := ids.entityID()
		endpointIDs[p.key] = id
		entities = append(entities, model.Entity{EntityID: id, Kind: model.EntitySocketEndpoint, DisplayLabel: endpointLabel(p.key), Identity: model.EntityIdentity{Kind: model.EntitySocketEndpoint, Endpoint: &model.EndpointIdentity{Address: p.key.address, Port: p.key.port, Transport: model.TransportTCP}}})
	}
	tlsFacts := append([]tlsFact{}, f.tls...)
	sort.SliceStable(tlsFacts, func(i, j int) bool {
		if endpointSort(tlsFacts[i].endpoint, tlsFacts[j].endpoint) != endpointSort(tlsFacts[j].endpoint, tlsFacts[i].endpoint) {
			return endpointSort(tlsFacts[i].endpoint, tlsFacts[j].endpoint)
		}
		return tlsFacts[i].mode < tlsFacts[j].mode
	})
	peerIDs := map[string]model.EntityID{}
	for _, fact := range tlsFacts {
		if fact.peer == nil || peerIDs[fact.peer.fingerprint] != "" {
			continue
		}
		id := ids.entityID()
		peerIDs[fact.peer.fingerprint] = id
		entities = append(entities, model.Entity{EntityID: id, Kind: model.EntityTLSPeer, DisplayLabel: "TLS peer", Identity: model.EntityIdentity{Kind: model.EntityTLSPeer, TLSPeer: &model.TLSPeerIdentity{Fingerprint: fact.peer.fingerprint}}})
	}

	vantage := model.VantagePoint{VantageID: vID, Kind: model.VantageKindClientNetwork, Role: model.VantageRoleClient, DisplayLabel: "current client network", Identity: model.VantageIdentity{Kind: model.VantageKindClientNetwork, ClientNetwork: &model.ClientNetworkIdentity{Label: "current client network"}}, Establishment: model.VantageDirectlyObserved, Limitations: []model.Limitation{}}
	capabilities := append([]model.Capability{}, f.capabilities...)
	if capabilities == nil {
		capabilities = []model.Capability{}
	}

	observations := []model.Observation{}
	resolutionObservationIDs := map[netip.Addr]model.ObservationID{}
	resolutionObs := makeResolutionObservations(&ids, f, hostID, vID, now, addressIDs)
	observations = append(observations, resolutionObs...)
	for _, o := range resolutionObs {
		if o.Payload.Resolution != nil && o.Payload.Resolution.AddressEntityID != nil {
			for address, id := range addressIDs {
				if id == *o.Payload.Resolution.AddressEntityID {
					resolutionObservationIDs[address] = o.ObservationID
				}
			}
		}
	}

	tcpFacts := append([]tcpFact{}, f.tcp...)
	if f.normal != nil {
		tcpFacts = append(tcpFacts, tcpFact{mode: modeNormal, endpoint: f.normal.endpoint, result: f.normal.tcpResult, reason: f.normal.reason, durationNS: f.normal.durationNS, started: f.normal.started, finished: f.normal.finished, exact: f.normal.exact, conn: f.normal.conn})
	}
	sort.SliceStable(tcpFacts, func(i, j int) bool {
		if endpointSort(tcpFacts[i].endpoint, tcpFacts[j].endpoint) != endpointSort(tcpFacts[j].endpoint, tcpFacts[i].endpoint) {
			return endpointSort(tcpFacts[i].endpoint, tcpFacts[j].endpoint)
		}
		if tcpFacts[i].mode != tcpFacts[j].mode {
			return tcpFacts[i].mode < tcpFacts[j].mode
		}
		return tcpFacts[i].finished.Before(tcpFacts[j].finished)
	})
	tcpObservationIDs := map[endpointKey][]model.ObservationID{}
	for _, fact := range tcpFacts {
		if !fact.exact {
			continue
		}
		endpointID := endpointIDs[fact.endpoint]
		if endpointID == "" {
			continue
		}
		observedAt := fact.finished.UTC()
		if observedAt.IsZero() {
			observedAt = now
		}
		o := model.Observation{ObservationID: ids.observationID(), Kind: model.ObservationTCPConnection, SubjectEntityIDs: []model.EntityID{endpointID}, VantageID: &vID, ObservedAt: observedAt, Payload: model.ObservationPayload{Kind: model.ObservationTCPConnection, TCP: &model.TCPConnectionResult{EndpointEntityID: endpointID, Result: fact.result, DurationNS: nonNegative(fact.durationNS), DeadlinePartOfExpectedCondition: fact.result == model.TCPTimedOut}}, AcquisitionMethod: model.AcquisitionDirectProbe, SourceComponent: model.SourceTCPProbe, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}}
		observations = append(observations, o)
		tcpObservationIDs[fact.endpoint] = append(tcpObservationIDs[fact.endpoint], o.ObservationID)
	}
	tlsObservationIDs := map[endpointKey][]model.ObservationID{}
	peerObservationIDs := map[endpointKey][]model.ObservationID{}
	certificateObservationIDs := map[endpointKey][]model.ObservationID{}
	for _, fact := range tlsFacts {
		endpointID := endpointIDs[fact.endpoint]
		if endpointID == "" {
			continue
		}
		observedAt := fact.verificationTime.UTC()
		if observedAt.IsZero() {
			observedAt = now
		}
		var peerID *model.EntityID
		if fact.peer != nil {
			id := peerIDs[fact.peer.fingerprint]
			peerID = &id
		}
		transport := &model.TLSTransportResultPayload{EndpointEntityID: endpointID, PeerEntityID: peerID, Result: fact.result, ProtocolVersion: fact.protocolVersion, CipherSuite: fact.cipherSuite, NegotiatedALPN: fact.negotiatedALPN, SNISent: fact.sniSent, DurationNS: nonNegative(fact.durationNS)}
		o := model.Observation{ObservationID: ids.observationID(), Kind: model.ObservationTLSTransport, SubjectEntityIDs: subjectWithPeer(endpointID, peerID), VantageID: &vID, ObservedAt: observedAt, Payload: model.ObservationPayload{Kind: model.ObservationTLSTransport, TLSTransport: transport}, AcquisitionMethod: model.AcquisitionDirectProbe, SourceComponent: model.SourceTLSProbe, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}}
		observations = append(observations, o)
		tlsObservationIDs[fact.endpoint] = append(tlsObservationIDs[fact.endpoint], o.ObservationID)
		if fact.peer == nil {
			continue
		}
		peerSummary := &model.TLSPeerSummary{PeerEntityID: *peerID, CertificateCount: fact.peer.count, LeafSHA256: fact.peer.fingerprint, NotBefore: fact.peer.notBefore.UTC(), NotAfter: fact.peer.notAfter.UTC(), SANType: fact.peer.sanType, SANCount: fact.peer.sanCount}
		peerObs := model.Observation{ObservationID: ids.observationID(), Kind: model.ObservationTLSPeer, SubjectEntityIDs: []model.EntityID{*peerID}, VantageID: &vID, ObservedAt: observedAt, Payload: model.ObservationPayload{Kind: model.ObservationTLSPeer, TLSPeer: peerSummary}, AcquisitionMethod: model.AcquisitionDirectProbe, SourceComponent: model.SourceTLSProbe, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}}
		observations = append(observations, peerObs)
		peerObservationIDs[fact.endpoint] = append(peerObservationIDs[fact.endpoint], peerObs.ObservationID)
		result := fact.verification
		var failure *model.CertificateVerificationResult
		if result != model.CertVerified {
			failure = &result
		}
		certObs := model.Observation{ObservationID: ids.observationID(), Kind: model.ObservationCertificateVerification, SubjectEntityIDs: []model.EntityID{*peerID, hostID}, VantageID: &vID, ObservedAt: observedAt, Payload: model.ObservationPayload{Kind: model.ObservationCertificateVerification, CertificateVerification: &model.CertificateVerificationResultPayload{PeerEntityID: *peerID, VerifiedHostname: f.target.persisted.Hostname, VerificationTime: fact.verificationTime.UTC(), TrustSource: fact.trustSource, Result: result, FailureReason: failure}}, AcquisitionMethod: model.AcquisitionDirectProbe, SourceComponent: model.SourceCertificateVerifier, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}}
		observations = append(observations, certObs)
		certificateObservationIDs[fact.endpoint] = append(certificateObservationIDs[fact.endpoint], certObs.ObservationID)
	}

	edges := []model.PathEdge{}
	resEdgeIDs := map[netip.Addr]model.EdgeID{}
	for _, p := range plans {
		if !p.retained {
			continue
		}
		addressID := addressIDs[p.key.address]
		observationID := resolutionObservationIDs[p.key.address]
		if addressID == "" || observationID == "" {
			continue
		}
		e := model.PathEdge{EdgeID: ids.edgeID(), From: hostID, To: addressID, Relation: model.RelationResolvesTo, Provenance: model.ProvenanceDirectlyObserved, EvidenceRefs: []model.EvidenceRef{model.ObservationRef(observationID)}}
		edges = append(edges, e)
		resEdgeIDs[p.key.address] = e.EdgeID
	}

	connectEdgeIDs := map[endpointKey]model.EdgeID{}
	for _, fact := range tcpFacts {
		if !fact.exact || len(tcpObservationIDs[fact.endpoint]) == 0 {
			continue
		}
		from := targetID
		if addressID := addressIDs[fact.endpoint.address]; addressID != "" {
			from = addressID
		}
		to := endpointIDs[fact.endpoint]
		if to == "" {
			continue
		}
		e := model.PathEdge{EdgeID: ids.edgeID(), From: from, To: to, Relation: model.RelationConnectsTo, Provenance: model.ProvenanceDirectlyObserved, EvidenceRefs: []model.EvidenceRef{model.ObservationRef(tcpObservationIDs[fact.endpoint][len(tcpObservationIDs[fact.endpoint])-1])}}
		edges = append(edges, e)
		connectEdgeIDs[fact.endpoint] = e.EdgeID
	}
	tlsEdgeIDs := map[endpointKey][]model.EdgeID{}
	verifyEdgeIDs := map[endpointKey][]model.EdgeID{}
	for _, fact := range tlsFacts {
		if fact.peer == nil || len(tlsObservationIDs[fact.endpoint]) == 0 {
			continue
		}
		endpointID := endpointIDs[fact.endpoint]
		peerID := peerIDs[fact.peer.fingerprint]
		e := model.PathEdge{EdgeID: ids.edgeID(), From: endpointID, To: peerID, Relation: model.RelationNegotiatesTLSWith, Provenance: model.ProvenanceDirectlyObserved, EvidenceRefs: []model.EvidenceRef{model.ObservationRef(tlsObservationIDs[fact.endpoint][len(tlsObservationIDs[fact.endpoint])-1])}}
		edges = append(edges, e)
		tlsEdgeIDs[fact.endpoint] = append(tlsEdgeIDs[fact.endpoint], e.EdgeID)
		if len(certificateObservationIDs[fact.endpoint]) > 0 {
			v := model.PathEdge{EdgeID: ids.edgeID(), From: peerID, To: hostID, Relation: model.RelationVerifies, Provenance: model.ProvenanceDirectlyObserved, EvidenceRefs: []model.EvidenceRef{model.ObservationRef(certificateObservationIDs[fact.endpoint][len(certificateObservationIDs[fact.endpoint])-1])}}
			edges = append(edges, v)
			verifyEdgeIDs[fact.endpoint] = append(verifyEdgeIDs[fact.endpoint], v.EdgeID)
		}
	}

	branches := []model.Branch{}
	for _, p := range plans {
		ordered := []model.EdgeID{}
		if edgeID := resEdgeIDs[p.key.address]; edgeID != "" {
			ordered = append(ordered, edgeID)
		}
		if edgeID := connectEdgeIDs[p.key]; edgeID != "" {
			ordered = append(ordered, edgeID)
		}
		ordered = append(ordered, tlsEdgeIDs[p.key]...)
		ordered = append(ordered, verifyEdgeIDs[p.key]...)
		branches = append(branches, model.Branch{BranchID: ids.branchID(), OrderedEdgeIDs: ordered, Goal: model.GoalHTTPResponse})
	}

	definitions, executions := makeChecks(&ids, f, plans, branches, targetID, hostID, endpointIDs, vID, now, tcpFacts, tlsFacts, tcpObservationIDs, tlsObservationIDs, peerObservationIDs, certificateObservationIDs)
	limitations := append([]model.Limitation{}, f.limitations...)
	for i := range limitations {
		if limitations[i].LimitationID == "" {
			limitations[i].LimitationID = ids.limitationID()
		}
	}
	return model.EvidenceRun{
		ReportSchemaVersion: model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}, Producer: fProducer(f), RunID: "run-000001", Target: f.target.persisted, Goal: model.Goal{Kind: model.GoalHTTPResponse}, RequestedScope: model.RequestedScope{Kind: model.ScopeClientOnly}, Policy: model.Policy{CoherenceWindowNS: coherenceWindow.Nanoseconds()}, StartedAt: now, FinishedAt: finished, VantagePoints: []model.VantagePoint{vantage}, Capabilities: capabilities, OperatorAssertions: []model.OperatorAssertion{}, Entities: entities, ServicePath: model.ServicePath{Nodes: nodesForEntities(entities), Edges: edges, Branches: branches}, CheckDefinitions: definitions, CheckExecutions: executions, Observations: observations, VisibilityAssessments: []model.VisibilityAssessment{}, Limitations: limitations,
	}
}

func fProducer(f runFacts) model.Producer {
	if f.target.requestURL != nil {
		return model.Producer{Name: "routedoc", Version: "0.0.0-milestone1", Build: "development"}
	}
	return model.Producer{Name: "routedoc", Version: "0.0.0-milestone1", Build: "test"}
}

func endpointLabel(k endpointKey) string {
	return fmt.Sprintf("%s port %d", safeAddressLabel(k.address), k.port)
}
func safeAddressLabel(a netip.Addr) string { return strings.ReplaceAll(a.String(), ":", "-") }
func nonNegative(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

func nodesForEntities(entities []model.Entity) []model.PathNode {
	out := make([]model.PathNode, 0, len(entities))
	for _, e := range entities {
		out = append(out, model.PathNode{EntityID: e.EntityID})
	}
	return out
}

func makeResolutionObservations(ids *idAllocator, f runFacts, hostID model.EntityID, vID model.VantageID, now time.Time, addressIDs map[netip.Addr]model.EntityID) []model.Observation {
	retained, _ := retainAddresses(f.resolution.addresses)
	addresses := append(append([]netip.Addr{}, retained.v4...), retained.v6...)
	out := make([]model.Observation, 0, len(addresses)+2)
	if f.resolution.completed {
		for _, a := range addresses {
			family := model.AddressFamilyIPv6
			if a.Is4() {
				family = model.AddressFamilyIPv4
			}
			addressID := addressIDs[a]
			out = append(out, model.Observation{ObservationID: ids.observationID(), Kind: model.ObservationSystemResolution, SubjectEntityIDs: []model.EntityID{hostID, addressID}, VantageID: &vID, ObservedAt: now, Payload: model.ObservationPayload{Kind: model.ObservationSystemResolution, Resolution: &model.SystemResolutionResult{HostnameEntityID: hostID, AddressEntityID: &addressID, AddressFamily: family, Result: model.ResolutionResolved}}, AcquisitionMethod: model.AcquisitionDirectProbe, SourceComponent: model.SourceSystemResolver, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}})
		}
		if len(retained.v4) == 0 {
			out = append(out, resolutionNoResult(ids, hostID, vID, now, model.AddressFamilyIPv4))
		}
		if len(retained.v6) == 0 {
			out = append(out, resolutionNoResult(ids, hostID, vID, now, model.AddressFamilyIPv6))
		}
		return out
	}
	for _, family := range []model.AddressFamily{model.AddressFamilyIPv4, model.AddressFamilyIPv6} {
		out = append(out, model.Observation{ObservationID: ids.observationID(), Kind: model.ObservationSystemResolution, SubjectEntityIDs: []model.EntityID{hostID}, VantageID: &vID, ObservedAt: now, Payload: model.ObservationPayload{Kind: model.ObservationSystemResolution, Resolution: &model.SystemResolutionResult{HostnameEntityID: hostID, AddressFamily: family, Result: model.ResolutionFailed}}, AcquisitionMethod: model.AcquisitionDirectProbe, SourceComponent: model.SourceSystemResolver, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}})
	}
	return out
}

func resolutionNoResult(ids *idAllocator, hostID model.EntityID, vID model.VantageID, now time.Time, family model.AddressFamily) model.Observation {
	return model.Observation{ObservationID: ids.observationID(), Kind: model.ObservationSystemResolution, SubjectEntityIDs: []model.EntityID{hostID}, VantageID: &vID, ObservedAt: now, Payload: model.ObservationPayload{Kind: model.ObservationSystemResolution, Resolution: &model.SystemResolutionResult{HostnameEntityID: hostID, AddressFamily: family, Result: model.ResolutionNoResult}}, AcquisitionMethod: model.AcquisitionDirectProbe, SourceComponent: model.SourceSystemResolver, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}}
}

func makeChecks(ids *idAllocator, f runFacts, plans []endpointPlan, branches []model.Branch, targetID, hostID model.EntityID, endpointIDs map[endpointKey]model.EntityID, vID model.VantageID, now time.Time, tcpFacts []tcpFact, tlsFacts []tlsFact, tcpObservationIDs, tlsObservationIDs, peerObservationIDs, certificateObservationIDs map[endpointKey][]model.ObservationID) ([]model.CheckDefinition, []model.CheckExecution) {
	defs := []model.CheckDefinition{}
	execs := []model.CheckExecution{}
	version := model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}
	deadline := func(d time.Duration) int64 { return d.Nanoseconds() }
	addDef := func(kind model.CheckKind, subject model.EntityID, deps []model.CheckID, expected string, deadlineNS int64) model.CheckID {
		id := ids.checkID()
		defs = append(defs, model.CheckDefinition{CheckID: id, Kind: kind, Version: version, Inputs: model.CheckInputs{Kind: model.CheckInputNetwork, SubjectEntityID: subject, VantageID: &vID}, DependencyCheckIDs: append([]model.CheckID{}, deps...), RequiredCapabilityIDs: []model.CapabilityID{}, ExecutionPolicy: model.ExecutionPolicy{DeadlineNS: deadlineNS, DependencyFailureReasonCode: "skipped_dependency", DeadlineIsExpectedCondition: kind == model.CheckTCPConnection}, ExpectedCondition: model.ExpectedCondition{Kind: model.ExpectedResult, Result: expected}})
		return id
	}
	addExec := func(checkID model.CheckID, branch *model.BranchID, lifecycle model.CheckLifecycle, verdict model.CheckVerdict, reason string, obs []model.ObservationID) {
		execs = append(execs, model.CheckExecution{ExecutionID: ids.executionID(), CheckID: checkID, BranchID: branch, VantageID: &vID, Lifecycle: lifecycle, Verdict: verdict, ReasonCode: reasonPtr(reason), ObservationIDs: append([]model.ObservationID{}, obs...), VisibilityAssessmentIDs: []model.VisibilityID{}})
	}
	resolutionObs := []model.ObservationID{}
	resolutionLifecycle, resolutionVerdict, resolutionReason := model.CheckCompleted, model.CheckPass, f.resolution.reason
	if !f.resolution.completed {
		resolutionLifecycle, resolutionVerdict = model.CheckError, model.CheckUnknown
	}
	resolutionID := addDef(model.CheckSystemResolution, hostID, nil, "RESOLVED", deadline(resolutionTimeout))
	addExec(resolutionID, nil, resolutionLifecycle, resolutionVerdict, resolutionReason, resolutionObs)

	normalLifecycle, normalVerdict, normalReason := model.CheckNotRun, model.CheckSkipped, "resolution_failed"
	var normalObs []model.ObservationID
	for _, fact := range tcpFacts {
		if fact.mode == modeNormal {
			normalLifecycle, normalVerdict, normalReason = tcpExecutionState(fact.result, fact.reason)
			if fact.exact {
				normalObs = append(normalObs, tcpObservationIDs[fact.endpoint]...)
			}
		}
	}
	normalID := addDef(model.CheckTCPConnection, hostID, nil, "ACCEPTED", deadline(tcpTimeout))
	addExec(normalID, nil, normalLifecycle, normalVerdict, normalReason, normalObs)

	for i, p := range plans {
		var branchID *model.BranchID
		if i < len(branches) {
			branchID = &branches[i].BranchID
		}
		endpointID := endpointIDs[p.key]
		tcpID := addDef(model.CheckTCPConnection, endpointID, nil, "ACCEPTED", deadline(tcpTimeout))
		tlsID := addDef(model.CheckTLSTransport, endpointID, []model.CheckID{tcpID}, "COMPLETED", deadline(tlsTimeout))
		peerID := addDef(model.CheckTLSPeer, endpointID, []model.CheckID{tlsID}, "PRESENTED", deadline(tlsTimeout))
		certID := addDef(model.CheckCertificateVerification, endpointID, []model.CheckID{peerID}, "VERIFIED", deadline(tlsTimeout))
		httpDeps := []model.CheckID{certID}
		if f.target.persisted.Scheme == "http" {
			httpDeps = []model.CheckID{tcpID}
		}
		httpID := addDef(model.CheckHTTP, endpointID, httpDeps, "RESPONSE", deadline(httpTimeout))

		endpointTCP := []tcpFact{}
		for _, fact := range tcpFacts {
			if fact.exact && fact.endpoint == p.key {
				endpointTCP = append(endpointTCP, fact)
			}
		}
		if len(endpointTCP) == 0 {
			reason := "probe_pending"
			if !p.pinned && p.retained {
				reason = reasonAddressAttemptCap
			}
			addExec(tcpID, branchID, model.CheckNotRun, model.CheckSkipped, reason, nil)
			addExec(tlsID, branchID, model.CheckNotRun, model.CheckSkipped, "skipped_dependency", nil)
			addExec(peerID, branchID, model.CheckNotRun, model.CheckSkipped, "skipped_dependency", nil)
			addExec(certID, branchID, model.CheckNotRun, model.CheckSkipped, "skipped_dependency", nil)
			addExec(httpID, branchID, model.CheckNotRun, model.CheckSkipped, "skipped_dependency", nil)
			continue
		}
		for _, fact := range endpointTCP {
			tcpLifecycle, tcpVerdict, tcpReason := tcpExecutionState(fact.result, fact.reason)
			addExec(tcpID, branchID, tcpLifecycle, tcpVerdict, tcpReason, tcpObservationIDs[fact.endpoint])
			matchedTLS := []tlsFact{}
			for _, tls := range tlsFacts {
				if tls.endpoint == fact.endpoint && tls.mode == fact.mode {
					matchedTLS = append(matchedTLS, tls)
				}
			}
			if fact.result != model.TCPAccepted || len(matchedTLS) == 0 {
				addExec(tlsID, branchID, model.CheckNotRun, model.CheckSkipped, "skipped_dependency", nil)
				addExec(peerID, branchID, model.CheckNotRun, model.CheckSkipped, "skipped_dependency", nil)
				addExec(certID, branchID, model.CheckNotRun, model.CheckSkipped, "skipped_dependency", nil)
				addExec(httpID, branchID, model.CheckNotRun, model.CheckSkipped, "skipped_dependency", nil)
				continue
			}
			for _, tls := range matchedTLS {
				tlsLifecycle, tlsVerdict, tlsReason := tlsExecutionState(tls.result, tls.reason)
				addExec(tlsID, branchID, tlsLifecycle, tlsVerdict, tlsReason, tlsObservationIDs[tls.endpoint])
				if tls.peer == nil {
					addExec(peerID, branchID, model.CheckNotRun, model.CheckSkipped, "tls_peer_missing", nil)
					addExec(certID, branchID, model.CheckNotRun, model.CheckSkipped, "skipped_dependency", nil)
					addExec(httpID, branchID, model.CheckNotRun, model.CheckSkipped, "tls_peer_unverified", nil)
					continue
				}
				addExec(peerID, branchID, model.CheckCompleted, model.CheckPass, "", peerObservationIDs[tls.endpoint])
				certVerdict := model.CheckFail
				certReason := certificateReasonCode(tls.verification)
				if tls.verification == model.CertVerified {
					certVerdict, certReason = model.CheckPass, ""
				}
				certLifecycle := model.CheckCompleted
				addExec(certID, branchID, certLifecycle, certVerdict, certReason, certificateObservationIDs[tls.endpoint])
				if tls.verification == model.CertVerified {
					addExec(httpID, branchID, model.CheckNotRun, model.CheckSkipped, "probe_pending", nil)
				} else {
					addExec(httpID, branchID, model.CheckNotRun, model.CheckSkipped, "tls_peer_unverified", nil)
				}
			}
		}
	}
	return defs, execs
}

func subjectWithPeer(endpointID model.EntityID, peerID *model.EntityID) []model.EntityID {
	if peerID == nil {
		return []model.EntityID{endpointID}
	}
	return []model.EntityID{endpointID, *peerID}
}

func certificateReasonCode(result model.CertificateVerificationResult) string {
	switch result {
	case model.CertHostnameMismatch:
		return "hostname_mismatch"
	case model.CertExpired:
		return "certificate_expired"
	case model.CertNotYetValid:
		return "certificate_not_yet_valid"
	case model.CertUntrustedIssuer:
		return "untrusted_issuer"
	case model.CertInvalidUsage:
		return "invalid_usage"
	case model.CertVerifierUnavailable:
		return "verifier_unavailable"
	default:
		return "certificate_failed"
	}
}

func tlsExecutionState(result model.TLSTransportResult, reason string) (model.CheckLifecycle, model.CheckVerdict, string) {
	if result == model.TLSTransportCompleted {
		return model.CheckCompleted, model.CheckPass, reason
	}
	if result == model.TLSTransportTimedOut {
		return model.CheckTimedOut, model.CheckFail, reason
	}
	return model.CheckCompleted, model.CheckFail, reason
}

func tcpExecutionState(result model.TCPResult, reason string) (model.CheckLifecycle, model.CheckVerdict, string) {
	if result == model.TCPAccepted {
		return model.CheckCompleted, model.CheckPass, reason
	}
	if result == model.TCPTimedOut {
		return model.CheckTimedOut, model.CheckFail, reason
	}
	return model.CheckCompleted, model.CheckFail, reason
}
