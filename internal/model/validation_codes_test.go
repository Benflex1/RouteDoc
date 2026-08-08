package model

import "testing"

func TestStableValidationCodesHaveDirectCoverage(t *testing.T) {
	codes := []ValidationCode{
		CodeUnsupportedMajor, CodeMissingRequiredField, CodeUnknownField, CodeNewerMinorFieldIgnored, CodeUnknownEnumValue, CodeUnknownUnionKind, CodeExactVersionRequired,
		CodeDuplicateID, CodeInvalidGeneratedSequence, CodeReferenceMissing, CodeReferenceKindMismatch, CodeReferenceForwardClaim, CodeReferenceCrossRuleClaim,
		CodeVantageRequired, CodeVantageMismatch, CodeInvalidExecutionState, CodeJustificationMissing, CodeJustificationCycle, CodeVisibilityScopeMismatch, CodeVisibilityInsufficientForAbsence,
		CodeInvalidAssertionSource, CodeDuplicateCandidateKey, CodeUnlistedProvenance, CodeClaimRuleRequired, CodeClaimInvalidSupportLevel, CodeFindingRuleRequired, CodeFindingClaimRequired, CodeFindingRuleMismatch, CodeFindingInvalidGlobalPrimary,
		CodeSensitiveDisallowedField, CodeOrderingNoncanonical, CodeInvalidJSON, CodeDuplicateField, CodeInvalidValue, CodeRegistryDuplicate,
	}
	seen := map[ValidationCode]bool{}
	for _, code := range codes {
		if code == "" || seen[code] {
			t.Fatalf("invalid or duplicate stable validation code %q", code)
		}
		seen[code] = true
	}
}
