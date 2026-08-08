package model

import "testing"

func FuzzIDReferences(f *testing.F) {
	f.Add("claim-000001", "finding-000001", "tcp.connection_refused/v1")
	f.Add("observation-000001", "claim-000002", "listener.no_matching_listener_visible/v1")
	f.Fuzz(func(t *testing.T, first, second, rule string) {
		if len(first) > 256 || len(second) > 256 || len(rule) > 256 {
			t.Skip()
		}
		_, _ = ParseRunID(first)
		_, _ = ParseVantageID(first)
		_, _ = ParseEntityID(first)
		_, _ = ParseObservationID(first)
		_, _ = ParseVisibilityID(first)
		_, _ = ParseClaimID(first)
		_, _ = ParseFindingID(second)
		_, _ = ParseRuleID(rule)
		refs := []EvidenceRef{ObservationRef(ObservationID(first)), ClaimRef(ClaimID(second))}
		for _, ref := range refs {
			if !ref.Kind.Valid() {
				t.Fatal("typed reference lost its domain")
			}
		}
		if ClaimID(first).Valid() && ObservationID(first).Valid() {
			t.Fatal("one typed ID accepted two generated domains")
		}
	})
}
