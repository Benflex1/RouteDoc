package model

import (
	"reflect"
	"testing"
)

func TestEvidenceAndEvaluatedAreDistinct(t *testing.T) {
	e := reflect.TypeOf(EvidenceRun{})
	if _, ok := e.FieldByName("Claims"); ok {
		t.Fatal("evidence contains claims")
	}
	if _, ok := e.FieldByName("Findings"); ok {
		t.Fatal("evidence contains findings")
	}
	if reflect.TypeOf(EvaluatedRun{}).Field(0).Name != "Evidence" {
		t.Fatal("evaluated shape")
	}
}

func TestBaseModelShape(t *testing.T) {
	if !ObservationSystemResolution.Valid() || !CheckSystemResolution.Valid() {
		t.Fatal("closed vocabulary")
	}
	if reflect.TypeOf(ObservationPayload{}).NumField() < 10 {
		t.Fatal("payload union incomplete")
	}
}

func TestClosedUnionShape(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(AssertionParameters{}), reflect.TypeOf(VantageIdentity{}), reflect.TypeOf(EntityIdentity{}), reflect.TypeOf(CheckInputs{}), reflect.TypeOf(ExpectedCondition{}), reflect.TypeOf(ObservationPayload{}), reflect.TypeOf(VisibilityScope{})} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.Type.Kind() == reflect.Map || f.Type.Kind() == reflect.Interface {
				t.Errorf("%v has open field %s", typ, f.Name)
			}
		}
	}
}

func TestListenerInventoryResultIsClosedModelCase(t *testing.T) {
	if !ObservationKind("LISTENER_INVENTORY_RESULT").Valid() {
		t.Fatal("listener inventory result is not a closed observation kind")
	}
	if _, ok := reflect.TypeOf(ObservationPayload{}).FieldByName("ListenerInventoryResult"); !ok {
		t.Fatal("listener inventory result payload case is missing")
	}
	typ := reflect.TypeOf(ListenerInventoryResult{})
	want := []string{"NamespaceEntityID", "Protocol", "AddressFamily", "BindSemantics", "PortStart", "PortEnd", "MatchingListenerCount"}
	if typ.NumField() != len(want) {
		t.Fatalf("listener inventory result payload has %d fields, want %d", typ.NumField(), len(want))
	}
	for i, name := range want {
		if typ.Field(i).Name != name {
			t.Fatalf("listener inventory result field %d is %s, want %s", i, typ.Field(i).Name, name)
		}
	}
}

func TestTLSTransportPayloadHasRequiredEndpointAndOptionalPeer(t *testing.T) {
	typ := reflect.TypeOf(TLSTransportResultPayload{})
	want := []string{"EndpointEntityID", "PeerEntityID", "Result", "ProtocolVersion", "CipherSuite", "NegotiatedALPN", "SNISent", "AlertCode", "DurationNS"}
	if typ.NumField() != len(want) {
		t.Fatalf("TLS transport payload has %d fields, want %d", typ.NumField(), len(want))
	}
	for i, name := range want {
		if typ.Field(i).Name != name {
			t.Fatalf("TLS transport field %d is %s, want %s", i, typ.Field(i).Name, name)
		}
	}
	endpoint, ok := typ.FieldByName("EndpointEntityID")
	if !ok || endpoint.Type != reflect.TypeOf(EntityID("")) {
		t.Fatal("endpoint reference is not required EntityID")
	}
	peer, ok := typ.FieldByName("PeerEntityID")
	if !ok || peer.Type != reflect.TypeOf((*EntityID)(nil)) {
		t.Fatal("peer reference is not optional *EntityID")
	}
}

func TestEvidenceRefConstructors(t *testing.T) {
	r := ObservationRef(ObservationID("observation-000001"))
	if r.Kind != EvidenceKindObservation || r.ObservationID == nil || r.ClaimID != nil {
		t.Fatalf("bad observation ref: %#v", r)
	}
}
