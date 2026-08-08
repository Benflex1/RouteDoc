package rules

import (
	"strings"
	"unicode/utf8"

	"routedoc/internal/model"
)

func validCandidateKey(s string) bool {
	if s == "" || !utf8.ValidString(s) || strings.ContainsAny(s, "/\\\r\n\t") {
		return false
	}
	for _, r := range s {
		if r < '!' || r > '~' {
			return false
		}
	}
	return true
}
func evidenceFromTemplate(x EvidenceTemplate, local map[string]model.ClaimID) model.EvidenceRef {
	switch x.Kind {
	case model.EvidenceKindObservation:
		return model.ObservationRef(x.ObservationID)
	case model.EvidenceKindClaim:
		return model.ClaimRef(local[x.ClaimLocalKey])
	case model.EvidenceKindVisibility:
		return model.VisibilityRef(x.VisibilityID)
	case model.EvidenceKindAssertion:
		return model.AssertionRef(x.AssertionID)
	}
	return model.EvidenceRef{}
}
