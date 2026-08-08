package model

type EvidenceRef struct {
	Kind          EvidenceKind
	ObservationID *ObservationID
	ClaimID       *ClaimID
	VisibilityID  *VisibilityID
	AssertionID   *AssertionID
}

func ObservationRef(id ObservationID) EvidenceRef {
	return EvidenceRef{Kind: EvidenceKindObservation, ObservationID: &id}
}
func ClaimRef(id ClaimID) EvidenceRef { return EvidenceRef{Kind: EvidenceKindClaim, ClaimID: &id} }
func VisibilityRef(id VisibilityID) EvidenceRef {
	return EvidenceRef{Kind: EvidenceKindVisibility, VisibilityID: &id}
}
func AssertionRef(id AssertionID) EvidenceRef {
	return EvidenceRef{Kind: EvidenceKindAssertion, AssertionID: &id}
}
