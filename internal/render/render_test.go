package render

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"routedoc/internal/model"
	"routedoc/internal/schema/v1"
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

func TestClientReportExplainsUntrustedCertificateWithoutPrimaryFinding(t *testing.T) {
	v := loadRenderFixture(t, "client-probe-tls-untrusted")
	var concise bytes.Buffer
	if err := Report(&concise, v, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(concise.String(), "TLS certificate is untrusted (issuer not trusted).") {
		t.Fatalf("untrusted certificate diagnosis missing: %q", concise.String())
	}
	if strings.Contains(concise.String(), "No rule-produced primary finding.") {
		t.Fatalf("direct diagnosis was overshadowed by no-finding message: %q", concise.String())
	}
}

func TestClientReportLabelsRedirectWithSanitizedDestination(t *testing.T) {
	r := loadRenderFixtureRun(t, "client-probe-http-success")
	for i := range r.Evidence.Observations {
		if r.Evidence.Observations[i].Payload.HTTP == nil {
			continue
		}
		r.Evidence.Observations[i].Payload.HTTP.ResultKind = model.HTTPRedirect
		r.Evidence.Observations[i].Payload.HTTP.StatusCode = 302
		r.Evidence.Observations[i].Payload.HTTP.RedirectTarget = &model.Target{
			Scheme:        "https",
			Hostname:      "example.test",
			EffectivePort: 443,
			Path: model.PathSummary{
				Present:       true,
				SegmentCount:  2,
				QueryPresent:  true,
				TrailingSlash: true,
			},
		}
		break
	}
	v, issues := model.ValidatePersistedEvaluatedRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	var concise bytes.Buffer
	if err := Report(&concise, v, Options{}); err != nil {
		t.Fatal(err)
	}
	output := concise.String()
	if !strings.Contains(output, "status=302 redirect → https://example.test:443/...") {
		t.Fatalf("redirect diagnosis missing: %q", output)
	}
	for _, sensitive := range []string{"/private/path", "token=secret"} {
		if strings.Contains(output, sensitive) {
			t.Fatalf("redirect output exposed %q: %q", sensitive, output)
		}
	}
}

func loadRenderFixture(t *testing.T, name string) model.ValidatedEvaluatedRun {
	t.Helper()
	v, issues := model.ValidatePersistedEvaluatedRun(loadRenderFixtureRun(t, name))
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	return v
}

func loadRenderFixtureRun(t *testing.T, name string) model.EvaluatedRun {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "reports", "v1", name, "report.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d, issues := v1.Decode(data, v1.ReadRender)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	return d.Run
}

func emptyRenderRun() model.EvaluatedRun {
	r := model.EvidenceRun{ReportSchemaVersion: model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}, Producer: model.Producer{Name: "routedoc", Version: "0", Build: "test"}, RunID: "run-000001", Target: model.Target{Scheme: "https", Hostname: "example.test", EffectivePort: 443, Path: model.PathSummary{Present: true, IsRoot: false, SegmentCount: 2, TrailingSlash: true, QueryPresent: true}}, Goal: model.Goal{Kind: model.GoalHTTPResponse}, RequestedScope: model.RequestedScope{Kind: model.ScopeClientOnly}, StartedAt: timeForRender(), FinishedAt: timeForRender(), VantagePoints: []model.VantagePoint{}, Capabilities: []model.Capability{}, OperatorAssertions: []model.OperatorAssertion{}, Entities: []model.Entity{}, ServicePath: model.ServicePath{Nodes: []model.PathNode{}, Edges: []model.PathEdge{}, Branches: []model.Branch{}}, CheckDefinitions: []model.CheckDefinition{}, CheckExecutions: []model.CheckExecution{}, Observations: []model.Observation{}, VisibilityAssessments: []model.VisibilityAssessment{}, Limitations: []model.Limitation{}}
	return model.EvaluatedRun{Evidence: r, Evaluation: model.Evaluation{EvaluatedAt: timeForRender(), OrderedRuleIDs: []model.RuleID{}}, Claims: []model.Claim{}, Findings: []model.Finding{}}
}
func timeForRender() time.Time { return time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC) }
