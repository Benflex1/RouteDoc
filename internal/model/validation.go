package model

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type ValidationCode string

const (
	CodeUnsupportedMajor                 ValidationCode = "schema.unsupported_major"
	CodeMissingRequiredField             ValidationCode = "schema.missing_required_field"
	CodeUnknownField                     ValidationCode = "schema.unknown_field"
	CodeNewerMinorFieldIgnored           ValidationCode = "schema.newer_minor_field_ignored"
	CodeUnknownEnumValue                 ValidationCode = "schema.unknown_enum_value"
	CodeUnknownUnionKind                 ValidationCode = "schema.unknown_union_kind"
	CodeExactVersionRequired             ValidationCode = "schema.exact_version_required"
	CodeDuplicateID                      ValidationCode = "id.duplicate"
	CodeInvalidGeneratedSequence         ValidationCode = "id.invalid_generated_sequence"
	CodeReferenceMissing                 ValidationCode = "reference.missing"
	CodeReferenceKindMismatch            ValidationCode = "reference.kind_mismatch"
	CodeReferenceForwardClaim            ValidationCode = "reference.forward_claim"
	CodeReferenceCrossRuleClaim          ValidationCode = "reference.cross_rule_claim"
	CodeVantageRequired                  ValidationCode = "vantage.required"
	CodeVantageMismatch                  ValidationCode = "vantage.mismatch"
	CodeInvalidExecutionState            ValidationCode = "execution.invalid_state"
	CodeJustificationMissing             ValidationCode = "justification.missing"
	CodeJustificationCycle               ValidationCode = "justification.cycle"
	CodeVisibilityScopeMismatch          ValidationCode = "visibility.scope_mismatch"
	CodeVisibilityInsufficientForAbsence ValidationCode = "visibility.insufficient_for_absence"
	CodeInvalidAssertionSource           ValidationCode = "assertion.invalid_source"
	CodeDuplicateCandidateKey            ValidationCode = "rule.duplicate_candidate_key"
	CodeUnlistedProvenance               ValidationCode = "rule.unlisted_provenance"
	CodeClaimRuleRequired                ValidationCode = "claim.rule_required"
	CodeClaimInvalidSupportLevel         ValidationCode = "claim.invalid_support_level"
	CodeFindingRuleRequired              ValidationCode = "finding.rule_required"
	CodeFindingClaimRequired             ValidationCode = "finding.claim_required"
	CodeFindingRuleMismatch              ValidationCode = "finding.rule_mismatch"
	CodeFindingInvalidGlobalPrimary      ValidationCode = "finding.invalid_global_primary"
	CodeSensitiveDisallowedField         ValidationCode = "sensitive.disallowed_field"
	CodeOrderingNoncanonical             ValidationCode = "ordering.noncanonical"
	CodeInvalidJSON                      ValidationCode = "schema.invalid_json"
	CodeDuplicateField                   ValidationCode = "schema.duplicate_field"
	CodeInvalidValue                     ValidationCode = "schema.invalid_value"
	CodeRegistryDuplicate                ValidationCode = "rule.registry_duplicate"
)

func (v ValidationCode) String() string { return string(v) }

type ValidationIssue struct {
	Code             ValidationCode
	Pointer, Message string
}
type ValidationIssues []ValidationIssue

func (v ValidationIssues) Err() error {
	if len(v) == 0 {
		return nil
	}
	return validationError(v)
}

type validationError ValidationIssues

func (e validationError) Error() string {
	var b strings.Builder
	for i, x := range e {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(string(x.Code))
		if x.Pointer != "" {
			b.WriteString(" ")
			b.WriteString(x.Pointer)
		}
		if x.Message != "" {
			b.WriteString(": ")
			b.WriteString(x.Message)
		}
	}
	return b.String()
}
func SortValidationIssues(v ValidationIssues) {
	sort.SliceStable(v, func(i, j int) bool {
		if v[i].Pointer != v[j].Pointer {
			return v[i].Pointer < v[j].Pointer
		}
		if v[i].Code != v[j].Code {
			return v[i].Code < v[j].Code
		}
		return v[i].Message < v[j].Message
	})
}
func ValidateUTF8(s string) error {
	if !utf8.ValidString(s) {
		return errors.New("invalid UTF-8")
	}
	return nil
}
func ValidateScalar(s string) error {
	if err := ValidateUTF8(s); err != nil {
		return err
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("control character %U", r)
		}
	}
	return nil
}

func validateHostname(s string) error {
	if address, err := netip.ParseAddr(s); err == nil {
		if address.String() == s {
			return nil
		}
		return errors.New("IP literal must be normalized")
	}
	if s == "" || len(s) > 253 || strings.ToLower(s) != s {
		return errors.New("hostname must be a normalized lowercase hostname")
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("hostname has an invalid label")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return errors.New("hostname has an invalid character")
			}
		}
	}
	return nil
}

func validateReasonCode(s string) error {
	if s == "" {
		return nil
	}
	if len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return errors.New("reason code must be bounded lowercase snake case")
	}
	for _, r := range s[1:] {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return errors.New("reason code must be bounded lowercase snake case")
		}
	}
	return nil
}

func validateFingerprint(s string) error {
	if len(s) != len("sha256:")+64 || !strings.HasPrefix(s, "sha256:") {
		return errors.New("fingerprint must be a SHA-256 hex fingerprint")
	}
	for _, r := range s[len("sha256:"):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return errors.New("fingerprint must be a SHA-256 hex fingerprint")
		}
	}
	return nil
}

func validateSafeIdentifier(s string) error {
	if s == "" || len(s) > 128 {
		return errors.New("identifier must be bounded")
	}
	for i, r := range s {
		if (i == 0 && !isASCIIAlphaNumeric(r)) || (i > 0 && !isASCIIAlphaNumeric(r) && r != '-' && r != '_' && r != '.') {
			return errors.New("identifier has an invalid character")
		}
	}
	return nil
}

func isASCIIAlphaNumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

func validateDisplayLabel(s string) error {
	if s == "" || len(s) > 128 || strings.TrimSpace(s) != s {
		return errors.New("display label must be bounded and sanitized")
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || r == '.' || r == '_' || r == '-' || r == '(' || r == ')' {
			continue
		}
		return errors.New("display label contains an unsafe character")
	}
	return nil
}

func validateSafeToken(s string, max int) error {
	if s == "" || len(s) > max {
		return errors.New("token must be bounded")
	}
	for i, r := range s {
		if (i == 0 && !unicode.IsLetter(r) && !unicode.IsDigit(r)) || (!unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("_.:+/-", r)) {
			return errors.New("token contains an unsafe character")
		}
	}
	return nil
}

func validateHeaderName(s string) error {
	if s == "" || len(s) > 128 {
		return errors.New("header name must be bounded")
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return errors.New("header name contains an unsafe character")
	}
	return nil
}
