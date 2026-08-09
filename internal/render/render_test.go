package render

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"routedoc/internal/model"
)

func TestReportPathSummaryAndNoRootCause(t *testing.T) {
	v, issues := model.CanonicalizeAndValidateEvaluatedRun(emptyRenderRun())
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	var b bytes.Buffer
	if err := Report(&b, v, Options{}); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.Contains(s, "example.test") || strings.Contains(s, "secret-segment") || strings.Contains(s, "root cause") {
		t.Fatalf("render: %q", s)
	}
}
func TestExplainMissingFinding(t *testing.T) {
	v, issues := model.CanonicalizeAndValidateEvaluatedRun(emptyRenderRun())
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if _, err := BuildExplanation(v, "finding-000001"); err == nil {
		t.Fatal("missing finding accepted")
	}
}
func TestVerboseIncludesContractLabels(t *testing.T) {
	v, issues := model.CanonicalizeAndValidateEvaluatedRun(emptyRenderRun())
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	var b bytes.Buffer
	if err := Report(&b, v, Options{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "VANTAGE") || !strings.Contains(b.String(), "PathSummary") {
		t.Fatalf("verbose: %q", b.String())
	}
}

func TestClientReportUsesSafeBranchSummary(t *testing.T) {
	r := emptyRenderRun()
	r.Evidence.Producer.Version = "0.0.0-milestone1"
	r.Evidence.Capabilities = []model.Capability{{CapabilityID: "capability-000001", Kind: model.CapabilityHTTPProbe, State: model.CapabilityAvailable, ReasonCode: "proxy_environment_detected_ignored"}}
	v, issues := model.CanonicalizeAndValidateEvaluatedRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	var concise bytes.Buffer
	if err := Report(&concise, v, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(concise.String(), "Proxy environment detected and ignored; direct path probed.") || strings.Contains(concise.String(), "HTTP_PROXY") {
		t.Fatalf("client concise = %q", concise.String())
	}
}

func TestClientReportExplainsPartialVisibility(t *testing.T) {
	r := emptyRenderRun()
	r.Evidence.Producer.Version = "0.0.0-milestone1"
	r.Evidence.Limitations = []model.Limitation{{LimitationID: "limitation-000001", Code: model.LimitationPartialVisibility, Scope: model.LimitationScope{Kind: model.LimitationRun}}}
	v, issues := model.CanonicalizeAndValidateEvaluatedRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	var concise bytes.Buffer
	if err := Report(&concise, v, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(concise.String(), "Partial visibility: additional resolved addresses were not retained/probed.") {
		t.Fatalf("partial visibility was not explained: %q", concise.String())
	}
	var verbose bytes.Buffer
	if err := Report(&verbose, v, Options{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verbose.String(), "Partial visibility: additional resolved addresses were not retained/probed.") {
		t.Fatalf("verbose partial visibility was not explained: %q", verbose.String())
	}
}
func emptyRenderRun() model.EvaluatedRun {
	r := model.EvidenceRun{ReportSchemaVersion: model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}, Producer: model.Producer{Name: "routedoc", Version: "0", Build: "test"}, RunID: "run-000001", Target: model.Target{Scheme: "https", Hostname: "example.test", EffectivePort: 443, Path: model.PathSummary{Present: true, IsRoot: false, SegmentCount: 2, TrailingSlash: true, QueryPresent: true}}, Goal: model.Goal{Kind: model.GoalHTTPResponse}, RequestedScope: model.RequestedScope{Kind: model.ScopeClientOnly}, StartedAt: timeForRender(), FinishedAt: timeForRender(), VantagePoints: []model.VantagePoint{}, Capabilities: []model.Capability{}, OperatorAssertions: []model.OperatorAssertion{}, Entities: []model.Entity{}, ServicePath: model.ServicePath{Nodes: []model.PathNode{}, Edges: []model.PathEdge{}, Branches: []model.Branch{}}, CheckDefinitions: []model.CheckDefinition{}, CheckExecutions: []model.CheckExecution{}, Observations: []model.Observation{}, VisibilityAssessments: []model.VisibilityAssessment{}, Limitations: []model.Limitation{}}
	return model.EvaluatedRun{Evidence: r, Evaluation: model.Evaluation{EvaluatedAt: timeForRender(), OrderedRuleIDs: []model.RuleID{}}, Claims: []model.Claim{}, Findings: []model.Finding{}}
}
func timeForRender() time.Time { return time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC) }
