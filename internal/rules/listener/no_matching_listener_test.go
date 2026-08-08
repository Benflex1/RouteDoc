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
			r.Observations[0].Payload.Listener.NamespaceEntityID = "entity-other-namespace"
		}},
		{name: "wrong protocol", mutate: func(r *model.EvidenceRun) {
			r.Observations[0].Payload.Listener.Protocol = model.TransportUDP
		}},
		{name: "wrong family", mutate: func(r *model.EvidenceRun) {
			r.Observations[0].Payload.Listener.AddressFamily = model.AddressFamilyIPv6
		}},
		{name: "wrong bind", mutate: func(r *model.EvidenceRun) {
			r.Observations[0].Payload.Listener.BindSemantics = model.BindExact
		}},
		{name: "wrong port scope", mutate: func(r *model.EvidenceRun) {
			r.VisibilityAssessments[0].Scope.Listener.PortStart = 443
			r.VisibilityAssessments[0].Scope.Listener.PortEnd = 443
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
			v, issues := model.CanonicalizeAndValidateEvidenceRun(r)
			if len(issues) != 0 {
				t.Fatal(issues)
			}
			if got := NewNoMatchingListenerVisible().Evaluate(v); len(got) != 0 {
				t.Fatalf("unrelated basis produced absence: %#v", got)
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
	v, issues := model.CanonicalizeAndValidateEvidenceRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if got := NewNoMatchingListenerVisible().Evaluate(v); len(got) != 0 {
		t.Fatalf("absence produced without ownership evidence: %#v", got)
	}

	process := model.Observation{ObservationID: "observation-000002", Kind: model.ObservationProcessOwnership, SubjectEntityIDs: []model.EntityID{"entity-listener"}, VantageID: r.Observations[0].VantageID, ObservedAt: r.StartedAt, Payload: model.ObservationPayload{Kind: model.ObservationProcessOwnership, ProcessOwnership: &model.ProcessOwnershipEntry{ListenerEntityID: "entity-listener", Result: model.OwnershipUnresolved}}, AcquisitionMethod: model.AcquisitionSyntheticFixture, SourceComponent: model.SourceSyntheticFixture, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}}
	r.Observations = append(r.Observations, process)
	r.VisibilityAssessments[0].BasisObservationIDs = append(r.VisibilityAssessments[0].BasisObservationIDs, process.ObservationID)
	v, issues = model.CanonicalizeAndValidateEvidenceRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if got := NewNoMatchingListenerVisible().Evaluate(v); len(got) != 1 {
		t.Fatalf("complete owned inventory did not produce absence: %#v", got)
	}
}

func TestNoMatchingListenerDoesNotTrustCompleteLimitationsOrZeroBasis(t *testing.T) {
	r := listenerEvidence(model.VisibilityCompleteForScope, false)
	r.VisibilityAssessments[0].Limitations = []model.Limitation{{LimitationID: "limitation-000001", Code: model.LimitationPartialVisibility, Scope: model.LimitationScope{Kind: model.LimitationVisibility}}}
	v, issues := model.CanonicalizeAndValidateEvidenceRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if got := NewNoMatchingListenerVisible().Evaluate(v); len(got) != 0 {
		t.Fatalf("limited complete visibility produced absence: %#v", got)
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
func listenerEvidence(level model.VisibilityLevel, positive bool) model.EvidenceRun {
	t := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	v := model.VantagePoint{VantageID: "vantage-000001", Kind: model.VantageKindHostNamespace, Role: model.VantageRoleOriginHost, DisplayLabel: "host", Identity: model.VantageIdentity{Kind: model.VantageKindHostNamespace, HostNamespace: &model.HostNamespaceIdentity{NamespaceInode: 7}}, Establishment: model.VantageDirectlyObserved, Limitations: []model.Limitation{}}
	ns := model.Entity{EntityID: "entity-namespace", Kind: model.EntityNetworkNamespace, DisplayLabel: "namespace", Identity: model.EntityIdentity{Kind: model.EntityNetworkNamespace, Namespace: &model.NamespaceIdentity{NamespaceInode: 7}}}
	listenerEntity := model.Entity{EntityID: "entity-listener", Kind: model.EntityListener, DisplayLabel: "listener", Identity: model.EntityIdentity{Kind: model.EntityListener, Listener: &model.ListenerIdentity{Endpoint: model.EndpointIdentity{Address: netip.MustParseAddr("0.0.0.0"), Port: 80, Transport: model.TransportTCP}}}}
	port := uint16(80)
	if positive {
		port = 443
	}
	obs := model.Observation{ObservationID: "observation-000001", Kind: model.ObservationListenerInventory, SubjectEntityIDs: []model.EntityID{"entity-listener", "entity-namespace"}, VantageID: &v.VantageID, ObservedAt: t, Payload: model.ObservationPayload{Kind: model.ObservationListenerInventory, Listener: &model.ListenerInventoryEntry{ListenerEntityID: "entity-listener", NamespaceEntityID: "entity-namespace", Protocol: model.TransportTCP, AddressFamily: model.AddressFamilyIPv4, BindSemantics: model.BindWildcard, Port: port}}, AcquisitionMethod: model.AcquisitionSyntheticFixture, SourceComponent: model.SourceSyntheticFixture, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}}
	scope := model.VisibilityAssessment{VisibilityID: "visibility-000001", SubjectKind: model.VisibilitySubjectListener, VantageID: v.VantageID, Scope: model.VisibilityScope{Kind: "LISTENER", Listener: &model.ListenerVisibilityScope{NamespaceEntityID: "entity-namespace", Protocol: model.TransportTCP, AddressFamily: model.AddressFamilyIPv4, BindSemantics: model.BindWildcard, PortStart: 1, PortEnd: 65535, ProcessOwnershipRequired: false}}, Level: level, BasisObservationIDs: []model.ObservationID{"observation-000001"}, Limitations: []model.Limitation{}, AssessedAt: t}
	return model.EvidenceRun{ReportSchemaVersion: model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}, Producer: model.Producer{Name: "routedoc", Version: "0", Build: "test"}, RunID: "run-000001", Target: model.Target{Scheme: "https", Hostname: "example.test", EffectivePort: 443, Path: model.PathSummary{Present: true, IsRoot: true}}, Goal: model.Goal{Kind: model.GoalOriginPathDiagnosis}, RequestedScope: model.RequestedScope{Kind: model.ScopeLocalOrigin}, StartedAt: t, FinishedAt: t.Add(time.Second), VantagePoints: []model.VantagePoint{v}, Capabilities: []model.Capability{}, OperatorAssertions: []model.OperatorAssertion{}, Entities: []model.Entity{ns, listenerEntity}, ServicePath: model.ServicePath{Nodes: []model.PathNode{}, Edges: []model.PathEdge{}, Branches: []model.Branch{}}, CheckDefinitions: []model.CheckDefinition{}, CheckExecutions: []model.CheckExecution{}, Observations: []model.Observation{obs}, VisibilityAssessments: []model.VisibilityAssessment{scope}, Limitations: []model.Limitation{}}
}

func hasCode(issues model.ValidationIssues, code model.ValidationCode) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
