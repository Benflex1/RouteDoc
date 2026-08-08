package listener

import (
	"net/netip"
	"testing"
	"time"

	"routedoc/internal/model"
)

func TestNoMatchingListenerCompleteScope(t *testing.T) {
	r := listenerEvidence(model.VisibilityCompleteForScope, false)
	v, issues := model.CanonicalizeAndValidateEvidenceRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	got := NewNoMatchingListenerVisible().Evaluate(v)
	if len(got) != 1 || got[0].Claims[0].Level != model.ClaimLevelInferred {
		t.Fatalf("candidates: %#v", got)
	}
}

func TestNoMatchingListenerDoesNotTreatNonTargetEntryAsCompletedInventory(t *testing.T) {
	// The old fixture workaround put one unrelated port-80 entry under a
	// broad COMPLETE_FOR_SCOPE assessment. Architecture 1.2 requires a direct
	// zero-count LISTENER_INVENTORY_RESULT instead.
	r := listenerEvidence(model.VisibilityCompleteForScope, false)
	v := &r.Observations[0]
	v.Kind = model.ObservationListenerInventory
	v.Payload = model.ObservationPayload{Kind: model.ObservationListenerInventory, Listener: &model.ListenerInventoryEntry{ListenerEntityID: "entity-listener", NamespaceEntityID: "entity-namespace", Protocol: model.TransportTCP, AddressFamily: model.AddressFamilyIPv4, BindSemantics: model.BindWildcard, Port: 80}}
	_, issues := model.CanonicalizeAndValidateEvidenceRun(r)
	if !hasCode(issues, model.CodeVisibilityInsufficientForAbsence) {
		t.Fatalf("non-target entry did not invalidate complete visibility: %v", issues)
	}
	if model.ListenerAbsenceEvidenceValid(r, r.VisibilityAssessments[0], r.Target.EffectivePort) {
		t.Fatal("non-target entry incorrectly grounded absence")
	}
}

func TestNoMatchingListenerRejectsUnrelatedOrMismatchedInventoryBasis(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.EvidenceRun)
	}{
		{name: "tcp basis", mutate: func(r *model.EvidenceRun) {
			r.Entities = append(r.Entities, model.Entity{EntityID: "entity-endpoint", Kind: model.EntitySocketEndpoint, DisplayLabel: "endpoint", Identity: model.EntityIdentity{Kind: model.EntitySocketEndpoint, Endpoint: &model.EndpointIdentity{Address: netip.MustParseAddr("127.0.0.1"), Port: 443, Transport: model.TransportTCP}}})
			o := &r.Observations[0]
			o.Kind = model.ObservationTCPConnection
			o.Payload = model.ObservationPayload{Kind: model.ObservationTCPConnection, TCP: &model.TCPConnectionResult{EndpointEntityID: "entity-endpoint", Result: model.TCPAccepted}}
		}},
		{name: "process basis", mutate: func(r *model.EvidenceRun) {
			o := &r.Observations[0]
			o.Kind = model.ObservationProcessOwnership
			o.Payload = model.ObservationPayload{Kind: model.ObservationProcessOwnership, ProcessOwnership: &model.ProcessOwnershipEntry{ListenerEntityID: "entity-listener", Result: model.OwnershipUnresolved}}
		}},
		{name: "wrong namespace", mutate: func(r *model.EvidenceRun) {
			r.Entities = append(r.Entities, model.Entity{EntityID: "entity-other-namespace", Kind: model.EntityNetworkNamespace, DisplayLabel: "other namespace", Identity: model.EntityIdentity{Kind: model.EntityNetworkNamespace, Namespace: &model.NamespaceIdentity{NamespaceInode: 8}}})
			r.Observations[0].Payload.ListenerInventoryResult.NamespaceEntityID = "entity-other-namespace"
		}},
		{name: "wrong protocol", mutate: func(r *model.EvidenceRun) {
			r.Observations[0].Payload.ListenerInventoryResult.Protocol = model.TransportUDP
		}},
		{name: "wrong family", mutate: func(r *model.EvidenceRun) {
			r.Observations[0].Payload.ListenerInventoryResult.AddressFamily = model.AddressFamilyIPv6
		}},
		{name: "wrong bind", mutate: func(r *model.EvidenceRun) {
			r.Observations[0].Payload.ListenerInventoryResult.BindSemantics = model.BindExact
		}},
		{name: "wrong port scope", mutate: func(r *model.EvidenceRun) {
			r.Observations[0].Payload.ListenerInventoryResult.PortEnd = 100
		}},
		{name: "denied inventory basis", mutate: func(r *model.EvidenceRun) {
			r.Observations[0].Limitations = []model.Limitation{{LimitationID: "limitation-000001", Code: model.LimitationInsufficientPrivilege, Scope: model.LimitationScope{Kind: model.LimitationObservation}}}
		}},
		{name: "unavailable inventory", mutate: func(r *model.EvidenceRun) {
			r.VisibilityAssessments[0].Level = model.VisibilityUnknown
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := listenerEvidence(model.VisibilityCompleteForScope, false)
			tc.mutate(&r)
			if model.ListenerAbsenceEvidenceValid(r, r.VisibilityAssessments[0], r.Target.EffectivePort) {
				t.Fatal("mismatched basis produced absence")
			}
		})
	}
}

func TestNoMatchingListenerRejectsWrongVantageBasis(t *testing.T) {
	r := listenerEvidence(model.VisibilityCompleteForScope, false)
	other := model.VantagePoint{VantageID: "vantage-000002", Kind: model.VantageKindHostNamespace, Role: model.VantageRoleOriginHost, DisplayLabel: "other host", Identity: model.VantageIdentity{Kind: model.VantageKindHostNamespace, HostNamespace: &model.HostNamespaceIdentity{NamespaceInode: 8}}, Establishment: model.VantageDirectlyObserved, Limitations: []model.Limitation{}}
	r.VantagePoints = append(r.VantagePoints, other)
	r.Observations[0].VantageID = &other.VantageID
	if model.ListenerAbsenceEvidenceValid(r, r.VisibilityAssessments[0], r.Target.EffectivePort) {
		t.Fatal("wrong-vantage inventory basis was accepted")
	}
}

func TestNoMatchingListenerRequiresOwnershipEvidenceWhenScoped(t *testing.T) {
	r := listenerEvidence(model.VisibilityCompleteForScope, false)
	r.VisibilityAssessments[0].Scope.Listener.ProcessOwnershipRequired = true
	_, issues := model.CanonicalizeAndValidateEvidenceRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
}

func TestNoMatchingListenerDoesNotTrustCompleteLimitationsOrZeroBasis(t *testing.T) {
	r := listenerEvidence(model.VisibilityCompleteForScope, false)
	r.VisibilityAssessments[0].Limitations = []model.Limitation{{LimitationID: "limitation-000001", Code: model.LimitationPartialVisibility, Scope: model.LimitationScope{Kind: model.LimitationVisibility}}}
	_, issues := model.CanonicalizeAndValidateEvidenceRun(r)
	if !hasCode(issues, model.CodeVisibilityInsufficientForAbsence) {
		t.Fatalf("limited complete visibility was accepted: %#v", issues)
	}

	r = listenerEvidence(model.VisibilityCompleteForScope, false)
	r.VisibilityAssessments[0].BasisObservationIDs = []model.ObservationID{}
	_, issues = model.CanonicalizeAndValidateEvidenceRun(r)
	if !hasCode(issues, model.CodeVisibilityInsufficientForAbsence) {
		t.Fatalf("zero-basis complete assessment was not rejected: %v", issues)
	}
}
func TestNoMatchingListenerPartialAndPositiveDoNotFire(t *testing.T) {
	for _, level := range []model.VisibilityLevel{model.VisibilityPartial, model.VisibilityUnknown, model.VisibilityNotApplicable} {
		r := listenerEvidence(level, false)
		v, issues := model.CanonicalizeAndValidateEvidenceRun(r)
		if len(issues) != 0 {
			t.Fatal(issues)
		}
		if got := NewNoMatchingListenerVisible().Evaluate(v); len(got) != 0 {
			t.Fatalf("%s fired", level)
		}
	}
	r := listenerEvidence(model.VisibilityCompleteForScope, true)
	v, issues := model.CanonicalizeAndValidateEvidenceRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if got := NewNoMatchingListenerVisible().Evaluate(v); len(got) != 0 {
		t.Fatalf("positive listener fired: %#v", got)
	}
}

func TestNoMatchingListenerResultContainmentAndNonzeroContradictions(t *testing.T) {
	exact := listenerEvidence(model.VisibilityCompleteForScope, false)
	exact.Observations[0].Payload.ListenerInventoryResult.PortStart = 443
	exact.Observations[0].Payload.ListenerInventoryResult.PortEnd = 443
	exact.VisibilityAssessments[0].Scope.Listener.PortStart = 443
	exact.VisibilityAssessments[0].Scope.Listener.PortEnd = 443
	v, issues := model.CanonicalizeAndValidateEvidenceRun(exact)
	if len(issues) != 0 || len(NewNoMatchingListenerVisible().Evaluate(v)) != 1 {
		t.Fatalf("exact zero result did not support absence: %v", issues)
	}

	broadNonzero := listenerEvidence(model.VisibilityCompleteForScope, false)
	broadNonzero.Observations[0].Payload.ListenerInventoryResult.MatchingListenerCount = 1
	if model.ListenerAbsenceEvidenceValid(broadNonzero, broadNonzero.VisibilityAssessments[0], broadNonzero.Target.EffectivePort) {
		t.Fatal("broader nonzero aggregate was accepted as absence proof")
	}

	exactNonzero := listenerEvidence(model.VisibilityCompleteForScope, false)
	exactNonzero.Observations[0].Payload.ListenerInventoryResult.PortStart = 443
	exactNonzero.Observations[0].Payload.ListenerInventoryResult.PortEnd = 443
	exactNonzero.Observations[0].Payload.ListenerInventoryResult.MatchingListenerCount = 1
	exactNonzero.VisibilityAssessments[0].Scope.Listener.PortStart = 443
	exactNonzero.VisibilityAssessments[0].Scope.Listener.PortEnd = 443
	if model.ListenerAbsenceEvidenceValid(exactNonzero, exactNonzero.VisibilityAssessments[0], exactNonzero.Target.EffectivePort) {
		t.Fatal("exact-target nonzero result did not contradict absence")
	}
}

func TestListenerProcessOwnershipDistinctIdentityAccounting(t *testing.T) {
	r := listenerEvidence(model.VisibilityCompleteForScope, false)
	s := r.VisibilityAssessments[0].Scope.Listener
	s.PortStart, s.PortEnd, s.ProcessOwnershipRequired = 443, 443, true
	r.Observations[0].Payload.ListenerInventoryResult.PortStart = 443
	r.Observations[0].Payload.ListenerInventoryResult.PortEnd = 443
	r.Observations[0].Payload.ListenerInventoryResult.MatchingListenerCount = 2
	r.Entities = append(r.Entities,
		model.Entity{EntityID: "entity-listener-a", Kind: model.EntityListener, DisplayLabel: "listener a", Identity: model.EntityIdentity{Kind: model.EntityListener, Listener: &model.ListenerIdentity{Endpoint: model.EndpointIdentity{Address: netip.MustParseAddr("0.0.0.0"), Port: 443, Transport: model.TransportTCP}}}},
		// Distinct entity IDs remain distinct concrete listeners even when their
		// endpoint identities are equal (for example, shared-port sockets).
		model.Entity{EntityID: "entity-listener-b", Kind: model.EntityListener, DisplayLabel: "listener b", Identity: model.EntityIdentity{Kind: model.EntityListener, Listener: &model.ListenerIdentity{Endpoint: model.EndpointIdentity{Address: netip.MustParseAddr("0.0.0.0"), Port: 443, Transport: model.TransportTCP}}}},
		model.Entity{EntityID: "entity-process-a", Kind: model.EntityProcess, DisplayLabel: "process a", Identity: model.EntityIdentity{Kind: model.EntityProcess, Process: &model.ProcessIdentity{PID: 101}}},
		model.Entity{EntityID: "entity-process-b", Kind: model.EntityProcess, DisplayLabel: "process b", Identity: model.EntityIdentity{Kind: model.EntityProcess, Process: &model.ProcessIdentity{PID: 102}}},
	)
	add := func(id model.ObservationID, kind model.ObservationKind, listenerID model.EntityID, processID *model.EntityID) {
		payload := model.ObservationPayload{Kind: kind}
		if kind == model.ObservationListenerInventory {
			payload.Listener = &model.ListenerInventoryEntry{ListenerEntityID: listenerID, NamespaceEntityID: "entity-namespace", Protocol: model.TransportTCP, AddressFamily: model.AddressFamilyIPv4, BindSemantics: model.BindWildcard, Port: 443}
		} else {
			payload.ProcessOwnership = &model.ProcessOwnershipEntry{ListenerEntityID: listenerID, ProcessEntityID: processID, Result: model.OwnershipOwned}
		}
		r.Observations = append(r.Observations, model.Observation{ObservationID: id, Kind: kind, SubjectEntityIDs: []model.EntityID{listenerID, "entity-namespace"}, VantageID: r.Observations[0].VantageID, ObservedAt: r.StartedAt, Payload: payload, AcquisitionMethod: model.AcquisitionSyntheticFixture, SourceComponent: model.SourceSyntheticFixture, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}})
		r.VisibilityAssessments[0].BasisObservationIDs = append(r.VisibilityAssessments[0].BasisObservationIDs, id)
	}
	processA, processB := model.EntityID("entity-process-a"), model.EntityID("entity-process-b")
	add("observation-000002", model.ObservationListenerInventory, "entity-listener-a", nil)
	add("observation-000003", model.ObservationListenerInventory, "entity-listener-b", nil)
	add("observation-000004", model.ObservationProcessOwnership, "entity-listener-a", &processA)
	add("observation-000005", model.ObservationProcessOwnership, "entity-listener-b", &processB)
	if !model.ListenerVisibilityComplete(r, r.VisibilityAssessments[0]) {
		t.Fatal("distinct listener identities with complete ownership evidence were rejected")
	}

	duplicate := r
	duplicate.Observations = append([]model.Observation{}, r.Observations...)
	duplicate.VisibilityAssessments = append([]model.VisibilityAssessment{}, r.VisibilityAssessments...)
	duplicate.Observations[2].Payload.Listener = &model.ListenerInventoryEntry{ListenerEntityID: "entity-listener-a", NamespaceEntityID: "entity-namespace", Protocol: model.TransportTCP, AddressFamily: model.AddressFamilyIPv4, BindSemantics: model.BindWildcard, Port: 443}
	if model.ListenerVisibilityComplete(duplicate, duplicate.VisibilityAssessments[0]) {
		t.Fatal("duplicate observations of one concrete listener satisfied count two")
	}
}
func listenerEvidence(level model.VisibilityLevel, positive bool) model.EvidenceRun {
	t := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	v := model.VantagePoint{VantageID: "vantage-000001", Kind: model.VantageKindHostNamespace, Role: model.VantageRoleOriginHost, DisplayLabel: "host", Identity: model.VantageIdentity{Kind: model.VantageKindHostNamespace, HostNamespace: &model.HostNamespaceIdentity{NamespaceInode: 7}}, Establishment: model.VantageDirectlyObserved, Limitations: []model.Limitation{}}
	ns := model.Entity{EntityID: "entity-namespace", Kind: model.EntityNetworkNamespace, DisplayLabel: "namespace", Identity: model.EntityIdentity{Kind: model.EntityNetworkNamespace, Namespace: &model.NamespaceIdentity{NamespaceInode: 7}}}
	listenerEntity := model.Entity{EntityID: "entity-listener", Kind: model.EntityListener, DisplayLabel: "listener", Identity: model.EntityIdentity{Kind: model.EntityListener, Listener: &model.ListenerIdentity{Endpoint: model.EndpointIdentity{Address: netip.MustParseAddr("0.0.0.0"), Port: 80, Transport: model.TransportTCP}}}}
	obs := model.Observation{ObservationID: "observation-000001", Kind: model.ObservationListenerInventoryResult, SubjectEntityIDs: []model.EntityID{"entity-namespace"}, VantageID: &v.VantageID, ObservedAt: t, Payload: model.ObservationPayload{Kind: model.ObservationListenerInventoryResult, ListenerInventoryResult: &model.ListenerInventoryResult{NamespaceEntityID: "entity-namespace", Protocol: model.TransportTCP, AddressFamily: model.AddressFamilyIPv4, BindSemantics: model.BindWildcard, PortStart: 1, PortEnd: 65535, MatchingListenerCount: 0}}, AcquisitionMethod: model.AcquisitionSyntheticFixture, SourceComponent: model.SourceSyntheticFixture, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}}
	scope := model.VisibilityAssessment{VisibilityID: "visibility-000001", SubjectKind: model.VisibilitySubjectListener, VantageID: v.VantageID, Scope: model.VisibilityScope{Kind: "LISTENER", Listener: &model.ListenerVisibilityScope{NamespaceEntityID: "entity-namespace", Protocol: model.TransportTCP, AddressFamily: model.AddressFamilyIPv4, BindSemantics: model.BindWildcard, PortStart: 1, PortEnd: 65535, ProcessOwnershipRequired: false}}, Level: level, BasisObservationIDs: []model.ObservationID{"observation-000001"}, Limitations: []model.Limitation{}, AssessedAt: t}
	observations := []model.Observation{obs}
	if positive {
		observations = append(observations, model.Observation{ObservationID: "observation-000002", Kind: model.ObservationListenerInventory, SubjectEntityIDs: []model.EntityID{"entity-listener", "entity-namespace"}, VantageID: &v.VantageID, ObservedAt: t, Payload: model.ObservationPayload{Kind: model.ObservationListenerInventory, Listener: &model.ListenerInventoryEntry{ListenerEntityID: "entity-listener", NamespaceEntityID: "entity-namespace", Protocol: model.TransportTCP, AddressFamily: model.AddressFamilyIPv4, BindSemantics: model.BindWildcard, Port: 443}}, AcquisitionMethod: model.AcquisitionSyntheticFixture, SourceComponent: model.SourceSyntheticFixture, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}})
	}
	return model.EvidenceRun{ReportSchemaVersion: model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}, Producer: model.Producer{Name: "routedoc", Version: "0", Build: "test"}, RunID: "run-000001", Target: model.Target{Scheme: "https", Hostname: "example.test", EffectivePort: 443, Path: model.PathSummary{Present: true, IsRoot: true}}, Goal: model.Goal{Kind: model.GoalOriginPathDiagnosis}, RequestedScope: model.RequestedScope{Kind: model.ScopeLocalOrigin}, StartedAt: t, FinishedAt: t.Add(time.Second), VantagePoints: []model.VantagePoint{v}, Capabilities: []model.Capability{}, OperatorAssertions: []model.OperatorAssertion{}, Entities: []model.Entity{ns, listenerEntity}, ServicePath: model.ServicePath{Nodes: []model.PathNode{}, Edges: []model.PathEdge{}, Branches: []model.Branch{}}, CheckDefinitions: []model.CheckDefinition{}, CheckExecutions: []model.CheckExecution{}, Observations: observations, VisibilityAssessments: []model.VisibilityAssessment{scope}, Limitations: []model.Limitation{}}
}

func hasCode(issues model.ValidationIssues, code model.ValidationCode) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
