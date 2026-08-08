package model

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

type RunID string
type VantageID string
type CapabilityID string
type AssertionID string
type EntityID string
type EdgeID string
type BranchID string
type CheckID string
type ExecutionID string
type ObservationID string
type VisibilityID string
type ClaimID string
type FindingID string
type LimitationID string
type RuleID string

const (
	runPrefix         = "run-"
	vantagePrefix     = "vantage-"
	capabilityPrefix  = "capability-"
	assertionPrefix   = "assertion-"
	entityPrefix      = "entity-"
	edgePrefix        = "edge-"
	branchPrefix      = "branch-"
	checkPrefix       = "check-"
	executionPrefix   = "execution-"
	observationPrefix = "observation-"
	visibilityPrefix  = "visibility-"
	claimPrefix       = "claim-"
	findingPrefix     = "finding-"
	limitationPrefix  = "limitation-"
)

func validID(s, prefix string, generated bool) error {
	if !utf8.ValidString(s) || !strings.HasPrefix(s, prefix) || len(s) == len(prefix) {
		return fmt.Errorf("invalid %s ID", prefix[:len(prefix)-1])
	}
	rest := s[len(prefix):]
	if strings.IndexFunc(rest, func(r rune) bool {
		return r < 0x21 || r > 0x7e || strings.ContainsRune("\"'\\/", r)
	}) >= 0 {
		return fmt.Errorf("invalid character in %s ID", prefix[:len(prefix)-1])
	}
	if generated {
		if len(rest) < 6 {
			return fmt.Errorf("generated ID is not canonically padded")
		}
		for _, r := range rest {
			if r < '0' || r > '9' {
				return fmt.Errorf("generated ID is not numeric")
			}
		}
		if n, err := strconv.ParseUint(rest, 10, 64); err != nil || n == 0 {
			return fmt.Errorf("generated ID must be positive")
		}
	} else {
		allDigits := true
		for _, r := range rest {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(rest) > 1 && rest[0] == '0' && len(rest) < 6 {
			return fmt.Errorf("leading zero in numeric ID")
		}
	}
	return nil
}

func parseID[T ~string](s, prefix string, generated bool) (T, error) {
	var zero T
	if err := validID(s, prefix, generated); err != nil {
		return zero, err
	}
	return T(s), nil
}

func ParseRunID(s string) (RunID, error)         { return parseID[RunID](s, runPrefix, false) }
func ParseVantageID(s string) (VantageID, error) { return parseID[VantageID](s, vantagePrefix, false) }
func ParseCapabilityID(s string) (CapabilityID, error) {
	return parseID[CapabilityID](s, capabilityPrefix, false)
}
func ParseAssertionID(s string) (AssertionID, error) {
	return parseID[AssertionID](s, assertionPrefix, false)
}
func ParseEntityID(s string) (EntityID, error) { return parseID[EntityID](s, entityPrefix, false) }
func ParseEdgeID(s string) (EdgeID, error)     { return parseID[EdgeID](s, edgePrefix, false) }
func ParseBranchID(s string) (BranchID, error) { return parseID[BranchID](s, branchPrefix, false) }
func ParseCheckID(s string) (CheckID, error)   { return parseID[CheckID](s, checkPrefix, false) }
func ParseExecutionID(s string) (ExecutionID, error) {
	return parseID[ExecutionID](s, executionPrefix, false)
}
func ParseObservationID(s string) (ObservationID, error) {
	return parseID[ObservationID](s, observationPrefix, false)
}
func ParseVisibilityID(s string) (VisibilityID, error) {
	return parseID[VisibilityID](s, visibilityPrefix, false)
}
func ParseClaimID(s string) (ClaimID, error)     { return parseID[ClaimID](s, claimPrefix, true) }
func ParseFindingID(s string) (FindingID, error) { return parseID[FindingID](s, findingPrefix, true) }
func ParseLimitationID(s string) (LimitationID, error) {
	return parseID[LimitationID](s, limitationPrefix, false)
}
func ParseRuleID(s string) (RuleID, error) {
	var zero RuleID
	if !utf8.ValidString(s) || len(s) == 0 {
		return zero, fmt.Errorf("invalid rule ID")
	}
	parts := strings.Split(s, "/v")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || parts[1][0] == '0' {
		return zero, fmt.Errorf("invalid rule ID")
	}
	for _, r := range parts[1] {
		if r < '0' || r > '9' {
			return zero, fmt.Errorf("invalid rule ID")
		}
	}
	for _, r := range parts[0] {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && !strings.ContainsRune("_.-", r) {
			return zero, fmt.Errorf("invalid rule ID")
		}
	}
	return RuleID(s), nil
}

func generatedNumber(s, prefix string) (uint64, error) {
	if err := validID(s, prefix, true); err != nil {
		return 0, err
	}
	return strconv.ParseUint(s[len(prefix):], 10, 64)
}

func CompareClaimID(a, b ClaimID) int     { return compareUintIDs(string(a), string(b), claimPrefix) }
func CompareFindingID(a, b FindingID) int { return compareUintIDs(string(a), string(b), findingPrefix) }
func compareUintIDs(a, b, prefix string) int {
	av, ae := generatedNumber(a, prefix)
	bv, be := generatedNumber(b, prefix)
	if ae != nil || be != nil {
		return strings.Compare(a, b)
	}
	if av < bv {
		return -1
	}
	if av > bv {
		return 1
	}
	return 0
}

func (v RunID) Valid() bool         { return validID(string(v), runPrefix, false) == nil }
func (v VantageID) Valid() bool     { return validID(string(v), vantagePrefix, false) == nil }
func (v CapabilityID) Valid() bool  { return validID(string(v), capabilityPrefix, false) == nil }
func (v AssertionID) Valid() bool   { return validID(string(v), assertionPrefix, false) == nil }
func (v EntityID) Valid() bool      { return validID(string(v), entityPrefix, false) == nil }
func (v EdgeID) Valid() bool        { return validID(string(v), edgePrefix, false) == nil }
func (v BranchID) Valid() bool      { return validID(string(v), branchPrefix, false) == nil }
func (v CheckID) Valid() bool       { return validID(string(v), checkPrefix, false) == nil }
func (v ExecutionID) Valid() bool   { return validID(string(v), executionPrefix, false) == nil }
func (v ObservationID) Valid() bool { return validID(string(v), observationPrefix, false) == nil }
func (v VisibilityID) Valid() bool  { return validID(string(v), visibilityPrefix, false) == nil }
func (v ClaimID) Valid() bool       { return validID(string(v), claimPrefix, true) == nil }
func (v FindingID) Valid() bool     { return validID(string(v), findingPrefix, true) == nil }
func (v LimitationID) Valid() bool  { return validID(string(v), limitationPrefix, false) == nil }
func (v RuleID) Valid() bool        { _, err := ParseRuleID(string(v)); return err == nil }
