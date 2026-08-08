package tcp

import (
	"net/netip"
	"testing"
	"time"

	"routedoc/internal/model"
)

func TestConnectionRefusedExactVantage(t *testing.T) {
	r := tcpEvidence(model.TCPRefused, "vantage-000001")
	v, issues := model.CanonicalizeAndValidateEvidenceRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	got := NewConnectionRefused().Evaluate(v)
	if len(got) != 1 || got[0].Claims[0].Parameters.TCPRefused == nil {
		t.Fatalf("candidates: %#v", got)
	}
}
func TestConnectionRefusedDoesNotOverclaim(t *testing.T) {
	r := tcpEvidence(model.TCPTimedOut, "vantage-000001")
	v, issues := model.CanonicalizeAndValidateEvidenceRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if got := NewConnectionRefused().Evaluate(v); len(got) != 0 {
		t.Fatalf("timeout fired: %#v", got)
	}
}
func tcpEvidence(result model.TCPResult, vantage string) model.EvidenceRun {
	t := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	v := model.VantagePoint{VantageID: model.VantageID(vantage), Kind: model.VantageKindClientNetwork, Role: model.VantageRoleClient, DisplayLabel: "client", Identity: model.VantageIdentity{Kind: model.VantageKindClientNetwork, ClientNetwork: &model.ClientNetworkIdentity{Label: "client"}}, Establishment: model.VantageDirectlyObserved, Limitations: []model.Limitation{}}
	ep := model.Entity{EntityID: "entity-endpoint", Kind: model.EntitySocketEndpoint, DisplayLabel: "endpoint", Identity: model.EntityIdentity{Kind: model.EntitySocketEndpoint, Endpoint: &model.EndpointIdentity{Address: netip.MustParseAddr("192.0.2.1"), Port: 443, Transport: model.TransportTCP}}}
	o := model.Observation{ObservationID: "observation-000001", Kind: model.ObservationTCPConnection, SubjectEntityIDs: []model.EntityID{"entity-endpoint"}, VantageID: &v.VantageID, ObservedAt: t, Payload: model.ObservationPayload{Kind: model.ObservationTCPConnection, TCP: &model.TCPConnectionResult{EndpointEntityID: "entity-endpoint", Result: result, DurationNS: 1}}, AcquisitionMethod: model.AcquisitionSyntheticFixture, SourceComponent: model.SourceSyntheticFixture, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}}
	return model.EvidenceRun{ReportSchemaVersion: model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}, Producer: model.Producer{Name: "routedoc", Version: "0", Build: "test"}, RunID: "run-000001", Target: model.Target{Scheme: "https", Hostname: "example.test", EffectivePort: 443, Path: model.PathSummary{Present: true, IsRoot: true}}, Goal: model.Goal{Kind: model.GoalHTTPResponse}, RequestedScope: model.RequestedScope{Kind: model.ScopeClientOnly}, StartedAt: t, FinishedAt: t.Add(time.Second), VantagePoints: []model.VantagePoint{v}, Capabilities: []model.Capability{}, OperatorAssertions: []model.OperatorAssertion{}, Entities: []model.Entity{ep}, ServicePath: model.ServicePath{Nodes: []model.PathNode{}, Edges: []model.PathEdge{}, Branches: []model.Branch{}}, CheckDefinitions: []model.CheckDefinition{}, CheckExecutions: []model.CheckExecution{}, Observations: []model.Observation{o}, VisibilityAssessments: []model.VisibilityAssessment{}, Limitations: []model.Limitation{}}
}
