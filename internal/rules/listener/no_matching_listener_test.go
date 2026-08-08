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
	scope := model.VisibilityAssessment{VisibilityID: "visibility-000001", SubjectKind: model.VisibilitySubjectListener, VantageID: v.VantageID, Scope: model.VisibilityScope{Kind: "LISTENER", Listener: &model.ListenerVisibilityScope{NamespaceEntityID: "entity-namespace", Protocol: model.TransportTCP, AddressFamily: model.AddressFamilyIPv4, BindSemantics: model.BindWildcard, PortStart: 443, PortEnd: 443, ProcessOwnershipRequired: false}}, Level: level, BasisObservationIDs: []model.ObservationID{"observation-000001"}, Limitations: []model.Limitation{}, AssessedAt: t}
	return model.EvidenceRun{ReportSchemaVersion: model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}, Producer: model.Producer{Name: "routedoc", Version: "0", Build: "test"}, RunID: "run-000001", Target: model.Target{Scheme: "https", Hostname: "example.test", EffectivePort: 443, Path: model.PathSummary{Present: true, IsRoot: true}}, Goal: model.Goal{Kind: model.GoalOriginPathDiagnosis}, RequestedScope: model.RequestedScope{Kind: model.ScopeLocalOrigin}, StartedAt: t, FinishedAt: t.Add(time.Second), VantagePoints: []model.VantagePoint{v}, Capabilities: []model.Capability{}, OperatorAssertions: []model.OperatorAssertion{}, Entities: []model.Entity{ns, listenerEntity}, ServicePath: model.ServicePath{Nodes: []model.PathNode{}, Edges: []model.PathEdge{}, Branches: []model.Branch{}}, CheckDefinitions: []model.CheckDefinition{}, CheckExecutions: []model.CheckExecution{}, Observations: []model.Observation{obs}, VisibilityAssessments: []model.VisibilityAssessment{scope}, Limitations: []model.Limitation{}}
}
