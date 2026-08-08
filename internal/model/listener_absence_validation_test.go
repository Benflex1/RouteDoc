package model

import (
	"net/netip"
	"testing"
	"time"
)

func TestPersistedListenerAbsenceClaimUsesVisibilityContract(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*EvaluatedRun)
		valid  bool
	}{
		{name: "complete zero target matches", valid: true},
		{name: "partial visibility", mutate: func(r *EvaluatedRun) {
			r.Evidence.VisibilityAssessments[0].Level = VisibilityPartial
		}},
		{name: "wrong basis kind", mutate: func(r *EvaluatedRun) {
			r.Evidence.Observations[0].Kind = ObservationProcessOwnership
			r.Evidence.Observations[0].Payload = ObservationPayload{Kind: ObservationProcessOwnership, ProcessOwnership: &ProcessOwnershipEntry{ListenerEntityID: "entity-listener", Result: OwnershipUnresolved}}
		}},
		{name: "positive matching listener", mutate: func(r *EvaluatedRun) {
			r.Evidence.Observations[0].Payload.Listener.Port = 443
		}},
		{name: "wrong port scope", mutate: func(r *EvaluatedRun) {
			r.Evidence.VisibilityAssessments[0].Scope.Listener.PortStart = 443
			r.Evidence.VisibilityAssessments[0].Scope.Listener.PortEnd = 443
		}},
		{name: "zero basis", mutate: func(r *EvaluatedRun) {
			r.Evidence.VisibilityAssessments[0].BasisObservationIDs = nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := listenerAbsenceEvaluatedRun()
			if tc.mutate != nil {
				tc.mutate(&r)
			}
			_, issues := ValidatePersistedEvaluatedRun(r)
			if tc.valid && len(issues) != 0 {
				t.Fatalf("valid claim rejected: %v", issues)
			}
			if !tc.valid && !hasValidationCode(issues, CodeVisibilityInsufficientForAbsence) {
				t.Fatalf("invalid claim was accepted or wrong error: %v", issues)
			}
		})
	}
}

func listenerAbsenceEvaluatedRun() EvaluatedRun {
	t := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	vantage := VantagePoint{VantageID: "vantage-000001", Kind: VantageKindHostNamespace, Role: VantageRoleOriginHost, DisplayLabel: "host", Identity: VantageIdentity{Kind: VantageKindHostNamespace, HostNamespace: &HostNamespaceIdentity{NamespaceInode: 7}}, Establishment: VantageDirectlyObserved, Limitations: []Limitation{}}
	ns := Entity{EntityID: "entity-namespace", Kind: EntityNetworkNamespace, DisplayLabel: "namespace", Identity: EntityIdentity{Kind: EntityNetworkNamespace, Namespace: &NamespaceIdentity{NamespaceInode: 7}}}
	listener := Entity{EntityID: "entity-listener", Kind: EntityListener, DisplayLabel: "listener", Identity: EntityIdentity{Kind: EntityListener, Listener: &ListenerIdentity{Endpoint: EndpointIdentity{Address: netip.MustParseAddr("0.0.0.0"), Port: 80, Transport: TransportTCP}}}}
	vantageID := vantage.VantageID
	obs := Observation{ObservationID: "observation-000001", Kind: ObservationListenerInventory, SubjectEntityIDs: []EntityID{"entity-listener", "entity-namespace"}, VantageID: &vantageID, ObservedAt: t, Payload: ObservationPayload{Kind: ObservationListenerInventory, Listener: &ListenerInventoryEntry{ListenerEntityID: "entity-listener", NamespaceEntityID: "entity-namespace", Protocol: TransportTCP, AddressFamily: AddressFamilyIPv4, BindSemantics: BindWildcard, Port: 80}}, AcquisitionMethod: AcquisitionSyntheticFixture, SourceComponent: SourceSyntheticFixture, Sensitivity: SensitivitySanitizedDerived, Limitations: []Limitation{}}
	vis := VisibilityAssessment{VisibilityID: "visibility-000001", SubjectKind: VisibilitySubjectListener, VantageID: vantage.VantageID, Scope: VisibilityScope{Kind: "LISTENER", Listener: &ListenerVisibilityScope{NamespaceEntityID: "entity-namespace", Protocol: TransportTCP, AddressFamily: AddressFamilyIPv4, BindSemantics: BindWildcard, PortStart: 1, PortEnd: 65535}}, Level: VisibilityCompleteForScope, BasisObservationIDs: []ObservationID{obs.ObservationID}, Limitations: []Limitation{}, AssessedAt: t}
	evidence := EvidenceRun{ReportSchemaVersion: SchemaVersion{Major: 1, Minor: 0, Patch: 0}, Producer: Producer{Name: "routedoc", Version: "0", Build: "test"}, RunID: "run-000001", Target: Target{Scheme: "https", Hostname: "example.test", EffectivePort: 443, Path: PathSummary{Present: true, IsRoot: true}}, Goal: Goal{Kind: GoalOriginPathDiagnosis}, RequestedScope: RequestedScope{Kind: ScopeLocalOrigin}, StartedAt: t, FinishedAt: t.Add(time.Second), VantagePoints: []VantagePoint{vantage}, Capabilities: []Capability{}, OperatorAssertions: []OperatorAssertion{}, Entities: []Entity{listener, ns}, ServicePath: ServicePath{Nodes: []PathNode{}, Edges: []PathEdge{}, Branches: []Branch{}}, CheckDefinitions: []CheckDefinition{}, CheckExecutions: []CheckExecution{}, Observations: []Observation{obs}, VisibilityAssessments: []VisibilityAssessment{vis}, Limitations: []Limitation{}}
	claim := Claim{ClaimID: "claim-000001", StatementCode: StatementNoMatchingListenerVisible, Level: ClaimLevelInferred, SubjectEntityIDs: []EntityID{"entity-namespace"}, BranchIDs: []BranchID{}, Parameters: ClaimParameters{Kind: StatementNoMatchingListenerVisible, ListenerAbsent: &ListenerAbsentClaimParameters{NamespaceEntityID: "entity-namespace", VantageID: vantage.VantageID, Protocol: TransportTCP, AddressFamily: AddressFamilyIPv4, BindSemantics: BindWildcard, Port: 443}}, SupportingEvidence: []EvidenceRef{ObservationRef(obs.ObservationID), VisibilityRef(vis.VisibilityID)}, ContradictingEvidence: []EvidenceRef{}, RequiredMissingEvidence: []MissingEvidenceRequirement{}, RuleID: "listener.no_matching_listener_visible/v1"}
	return EvaluatedRun{Evidence: evidence, Evaluation: Evaluation{EvaluatedAt: t.Add(time.Second), OrderedRuleIDs: []RuleID{"listener.no_matching_listener_visible/v1"}}, Claims: []Claim{claim}, Findings: []Finding{}}
}

func hasValidationCode(issues ValidationIssues, code ValidationCode) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
