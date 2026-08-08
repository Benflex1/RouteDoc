package model

import (
	"math/rand"
	"reflect"
	"testing"
)

func TestRequiredMissingEvidenceCanonicalOrder(t *testing.T) {
	vantage := VantageID("vantage-000001")
	r := listenerAbsenceEvaluatedRun()
	r.Claims[0].RequiredMissingEvidence = []MissingEvidenceRequirement{
		{Kind: MissingVantageRequired, VantageID: &vantage},
		{Kind: MissingObservationRequired, ObservationKind: ptrObservationKind(ObservationListenerInventory)},
	}
	canonical, issues := CanonicalizeEvaluated(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if len(canonical.Claims[0].RequiredMissingEvidence) != 2 || canonical.Claims[0].RequiredMissingEvidence[0].Kind != MissingObservationRequired || canonical.Claims[0].RequiredMissingEvidence[1].Kind != MissingVantageRequired {
		t.Fatalf("required missing evidence was not sorted: %#v", canonical.Claims[0].RequiredMissingEvidence)
	}
}

func TestPersistedNoncanonicalRequiredMissingEvidenceRejected(t *testing.T) {
	vantage := VantageID("vantage-000001")
	r := listenerAbsenceEvaluatedRun()
	r.Claims[0].RequiredMissingEvidence = []MissingEvidenceRequirement{
		{Kind: MissingVantageRequired, VantageID: &vantage},
		{Kind: MissingObservationRequired, ObservationKind: ptrObservationKind(ObservationListenerInventory)},
	}
	_, issues := ValidatePersistedEvaluatedRun(r)
	if !hasValidationCode(issues, CodeOrderingNoncanonical) {
		t.Fatalf("noncanonical required-missing evidence accepted: %v", issues)
	}
}

func TestPersistedMissingEvidenceRequiresItsDiscriminatedFields(t *testing.T) {
	r := listenerAbsenceEvaluatedRun()
	r.Claims[0].RequiredMissingEvidence = []MissingEvidenceRequirement{{Kind: MissingObservationRequired}}
	if _, issues := ValidatePersistedEvaluatedRun(r); !hasValidationCode(issues, CodeUnknownUnionKind) {
		t.Fatalf("missing observation kind was accepted: %v", issues)
	}

	r = listenerAbsenceEvaluatedRun()
	r.Claims[0].RequiredMissingEvidence = []MissingEvidenceRequirement{{Kind: MissingVantageRequired, VantageID: ptrVantageID("vantage-000001"), ObservationKind: ptrObservationKind(ObservationTCPConnection)}}
	if _, issues := ValidatePersistedEvaluatedRun(r); !hasValidationCode(issues, CodeInvalidValue) {
		t.Fatalf("cross-kind missing-evidence field was accepted: %v", issues)
	}
}

func TestRequiredMissingEvidenceRandomInsertionOrdersCanonicalizeIdentically(t *testing.T) {
	vantageA := VantageID("vantage-000001")
	vantageB := VantageID("vantage-000002")
	observationA := ObservationKind(ObservationListenerInventory)
	observationB := ObservationKind(ObservationProcessOwnership)
	scopeA := VisibilityScope{Kind: "LISTENER", Listener: &ListenerVisibilityScope{NamespaceEntityID: "entity-namespace", Protocol: TransportTCP, AddressFamily: AddressFamilyIPv4, BindSemantics: BindWildcard, PortStart: 443, PortEnd: 443}}
	scopeB := VisibilityScope{Kind: "LISTENER", Listener: &ListenerVisibilityScope{NamespaceEntityID: "entity-namespace", Protocol: TransportTCP, AddressFamily: AddressFamilyIPv4, BindSemantics: BindWildcard, PortStart: 80, PortEnd: 80, ProcessOwnershipRequired: true}}
	requirements := []MissingEvidenceRequirement{
		{Kind: MissingVantageRequired, VantageID: &vantageB},
		{Kind: MissingObservationRequired, ObservationKind: &observationB},
		{Kind: MissingVisibilityRequired, VisibilitySubjectKind: ptrVisibilitySubjectKind(VisibilitySubjectListener), VisibilityScope: &scopeB},
		{Kind: MissingVantageRequired, VantageID: &vantageA},
		{Kind: MissingObservationRequired, ObservationKind: &observationA},
		{Kind: MissingVisibilityRequired, VisibilitySubjectKind: ptrVisibilitySubjectKind(VisibilitySubjectListener), VisibilityScope: &scopeA},
	}
	base := listenerAbsenceEvaluatedRun()
	base.Claims[0].RequiredMissingEvidence = append([]MissingEvidenceRequirement{}, requirements...)
	want, issues := CanonicalizeEvaluated(base)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	for seed := int64(0); seed < 32; seed++ {
		r := listenerAbsenceEvaluatedRun()
		r.Claims[0].RequiredMissingEvidence = append([]MissingEvidenceRequirement{}, requirements...)
		rand.New(rand.NewSource(seed)).Shuffle(len(r.Claims[0].RequiredMissingEvidence), func(i, j int) {
			r.Claims[0].RequiredMissingEvidence[i], r.Claims[0].RequiredMissingEvidence[j] = r.Claims[0].RequiredMissingEvidence[j], r.Claims[0].RequiredMissingEvidence[i]
		})
		got, issues := CanonicalizeEvaluated(r)
		if len(issues) != 0 {
			t.Fatalf("seed %d: %v", seed, issues)
		}
		if !reflect.DeepEqual(got.Claims[0].RequiredMissingEvidence, want.Claims[0].RequiredMissingEvidence) {
			t.Fatalf("seed %d produced a different order: %#v vs %#v", seed, got.Claims[0].RequiredMissingEvidence, want.Claims[0].RequiredMissingEvidence)
		}
	}
}

func ptrObservationKind(v ObservationKind) *ObservationKind                   { return &v }
func ptrVisibilitySubjectKind(v VisibilitySubjectKind) *VisibilitySubjectKind { return &v }
func ptrVantageID(v VantageID) *VantageID                                     { return &v }
