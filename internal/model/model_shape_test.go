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

func TestEvidenceRefConstructors(t *testing.T) {
	r := ObservationRef(ObservationID("observation-000001"))
	if r.Kind != EvidenceKindObservation || r.ObservationID == nil || r.ClaimID != nil {
		t.Fatalf("bad observation ref: %#v", r)
	}
}
