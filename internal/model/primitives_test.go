package model

import (
	"strings"
	"testing"
)

func TestIDPrefixesAndCharacters(t *testing.T) {
	cases := []struct {
		name  string
		parse func(string) error
		valid string
	}{
		{"run", func(s string) error { _, err := ParseRunID(s); return err }, "run-000001"},
		{"vantage", func(s string) error { _, err := ParseVantageID(s); return err }, "vantage-000001"},
		{"claim", func(s string) error { _, err := ParseClaimID(s); return err }, "claim-000001"},
		{"finding", func(s string) error { _, err := ParseFindingID(s); return err }, "finding-000001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.parse(tc.valid); err != nil {
				t.Fatalf("valid: %v", err)
			}
			for _, bad := range []string{"", "other-1", tc.valid + "\n", tc.valid + "\x00", "run-01", "claim-abc"} {
				if err := tc.parse(bad); err == nil {
					t.Errorf("%q accepted", bad)
				}
			}
		})
	}
}

func TestGeneratedIDNumericOrdering(t *testing.T) {
	low, err := ParseClaimID("claim-999999")
	if err != nil {
		t.Fatal(err)
	}
	high, err := ParseClaimID("claim-1000000")
	if err != nil {
		t.Fatal(err)
	}
	if CompareClaimID(high, low) <= 0 {
		t.Fatalf("numeric order not preserved")
	}
	if _, err := ParseClaimID("claim-000000"); err == nil {
		t.Fatal("zero accepted")
	}
}

func TestSchemaVersionStrictParsing(t *testing.T) {
	v, err := ParseSchemaVersion("1.0.0")
	if err != nil || v.String() != "1.0.0" {
		t.Fatalf("got %v, %v", v, err)
	}
	for _, s := range []string{"", "1", "1.0", "01.0.0", "1.00.0", "+1.0.0", "1.0.0\n", "1.0.0.0", "1.a.0"} {
		if _, err := ParseSchemaVersion(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestEnumsAcceptedTokens(t *testing.T) {
	if !VantageKindClientNetwork.Valid() || VantageKind("bad").Valid() {
		t.Fatal("vantage enum")
	}
	if !EvidenceKindObservation.Valid() || EvidenceKind("bad").Valid() {
		t.Fatal("evidence enum")
	}
	if !ClaimLevelObserved.Valid() || ClaimLevel("bad").Valid() {
		t.Fatal("claim level")
	}
}

func TestValidationIssueOrder(t *testing.T) {
	issues := ValidationIssues{
		{Code: ValidationCode("z"), Pointer: "/b"},
		{Code: ValidationCode("a"), Pointer: "/a"},
		{Code: ValidationCode("a"), Pointer: "/b"},
	}
	SortValidationIssues(issues)
	if issues[0].Pointer != "/a" || issues[1].Pointer != "/b" || issues[1].Code != "a" || issues[2].Code != "z" {
		t.Fatalf("unexpected order: %#v", issues)
	}
}

func TestInvalidUTF8(t *testing.T) {
	if err := ValidateUTF8("ok"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateUTF8(strings.ToValidUTF8("\xff", "")); err != nil {
		t.Fatal(err)
	}
	if err := ValidateUTF8(string([]byte{0xff})); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

// These declarations intentionally must not compile if ID domains are aliases.
var _ RunID = RunID("run-000001")
var _ ClaimID = ClaimID("claim-000001")
