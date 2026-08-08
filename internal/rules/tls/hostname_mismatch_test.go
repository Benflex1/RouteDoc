package tls

import (
	"net/netip"
	"testing"
	"time"

	"routedoc/internal/model"
)

func TestHostnameMismatchRule(t *testing.T) {
	r := tlsEvidence(model.CertHostnameMismatch)
	v, issues := model.CanonicalizeAndValidateEvidenceRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	got := NewHostnameMismatch().Evaluate(v)
	if len(got) != 1 || got[0].CandidateKey == "" {
		t.Fatalf("candidates: %#v", got)
	}
	if len(got[0].Claims) != 1 || got[0].Claims[0].Level != model.ClaimLevelObserved {
		t.Fatalf("claims: %#v", got[0].Claims)
	}
}
func TestHostnameMismatchDoesNotUseTransportOrSkippedHTTP(t *testing.T) {
	r := tlsEvidence(model.CertVerified)
	v, issues := model.CanonicalizeAndValidateEvidenceRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if got := NewHostnameMismatch().Evaluate(v); len(got) != 0 {
		t.Fatalf("verified certificate fired: %#v", got)
	}
}
func tlsEvidence(result model.CertificateVerificationResult) model.EvidenceRun {
	t := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	v := model.VantagePoint{VantageID: "vantage-000001", Kind: model.VantageKindClientNetwork, Role: model.VantageRoleClient, DisplayLabel: "client", Identity: model.VantageIdentity{Kind: model.VantageKindClientNetwork, ClientNetwork: &model.ClientNetworkIdentity{Label: "client"}}, Establishment: model.VantageDirectlyObserved, Limitations: []model.Limitation{}}
	peer := model.Entity{EntityID: "entity-peer", Kind: model.EntityTLSPeer, DisplayLabel: "peer", Identity: model.EntityIdentity{Kind: model.EntityTLSPeer, TLSPeer: &model.TLSPeerIdentity{Fingerprint: "sha256:synthetic"}}}
	obs := model.Observation{ObservationID: "observation-000001", Kind: model.ObservationCertificateVerification, SubjectEntityIDs: []model.EntityID{"entity-peer"}, VantageID: &v.VantageID, ObservedAt: t, Payload: model.ObservationPayload{Kind: model.ObservationCertificateVerification, CertificateVerification: &model.CertificateVerificationResultPayload{PeerEntityID: "entity-peer", VerifiedHostname: "example.test", VerificationTime: t, TrustSource: model.TrustSystem, Result: result}}, AcquisitionMethod: model.AcquisitionSyntheticFixture, SourceComponent: model.SourceSyntheticFixture, Sensitivity: model.SensitivitySanitizedDerived, Limitations: []model.Limitation{}}
	return model.EvidenceRun{ReportSchemaVersion: model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}, Producer: model.Producer{Name: "routedoc", Version: "0", Build: "test"}, RunID: "run-000001", Target: model.Target{Scheme: "https", Hostname: "example.test", EffectivePort: 443, Path: model.PathSummary{Present: true, IsRoot: true}}, Goal: model.Goal{Kind: model.GoalHTTPResponse}, RequestedScope: model.RequestedScope{Kind: model.ScopeClientOnly}, StartedAt: t, FinishedAt: t.Add(time.Second), VantagePoints: []model.VantagePoint{v}, Capabilities: []model.Capability{}, OperatorAssertions: []model.OperatorAssertion{}, Entities: []model.Entity{peer}, ServicePath: model.ServicePath{Nodes: []model.PathNode{}, Edges: []model.PathEdge{}, Branches: []model.Branch{}}, CheckDefinitions: []model.CheckDefinition{}, CheckExecutions: []model.CheckExecution{}, Observations: []model.Observation{obs}, VisibilityAssessments: []model.VisibilityAssessment{}, Limitations: []model.Limitation{}}
}

var _ = netip.Addr{}
