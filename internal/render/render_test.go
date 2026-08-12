package render

import (
	"bytes"
	"fmt"
	"net/netip"
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
	if !strings.Contains(concise.String(), "Proxy environment detected; direct path probed.") || strings.Contains(concise.String(), "HTTP_PROXY") {
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
	if !strings.Contains(concise.String(), "IPv4   ✗ TCP → TLS → certificate (not trusted)") || !strings.Contains(concise.String(), "Blocked at certificate verification.") {
		t.Fatalf("untrusted certificate diagnosis missing: %q", concise.String())
	}
	if strings.Contains(concise.String(), "No rule-produced primary finding.") || strings.Contains(concise.String(), "UNTRUSTED_ISSUER") {
		t.Fatalf("internal certificate vocabulary leaked: %q", concise.String())
	}
}

func TestClientReportConcludesReachableHTTP200(t *testing.T) {
	v := loadRenderFixture(t, "client-probe-http-success")
	var concise bytes.Buffer
	if err := Report(&concise, v, Options{}); err != nil {
		t.Fatal(err)
	}
	output := concise.String()
	if !strings.Contains(output, "Service is reachable.\nHTTP 200 received.") {
		t.Fatalf("reachable conclusion missing: %q", output)
	}
	if strings.Contains(output, "No rule-produced primary finding.") {
		t.Fatalf("internal no-finding conclusion remained: %q", output)
	}
}

func TestClientReportConcludesReachableHTTP401WithoutClaimingApplicationHealth(t *testing.T) {
	r := loadRenderFixtureRun(t, "client-probe-http-success")
	for i := range r.Evidence.Observations {
		if r.Evidence.Observations[i].Payload.HTTP != nil {
			r.Evidence.Observations[i].Payload.HTTP.StatusCode = 401
		}
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
	if !strings.Contains(output, "Service is reachable.\nHTTP 401 received.") {
		t.Fatalf("reachable 401 conclusion missing: %q", output)
	}
	if strings.Contains(output, "healthy") || strings.Contains(output, "successful") {
		t.Fatalf("application health was overstated: %q", output)
	}
}

func TestClientReportCompactSummaryHidesEvidenceVocabulary(t *testing.T) {
	v := loadRenderFixture(t, "client-probe-http-success")
	var concise bytes.Buffer
	if err := Report(&concise, v, Options{}); err != nil {
		t.Fatal(err)
	}
	output := concise.String()
	for _, internal := range []string{"ENDPOINT BRANCHES", "CHECK ", "UNATTRIBUTED CHECK", "branch-", "address_attempt_cap", "skipped_dependency"} {
		if strings.Contains(output, internal) {
			t.Fatalf("concise output exposed %q: %q", internal, output)
		}
	}
	for _, expected := range []string{
		"RouteDoctor — http://example.test/",
		"DNS    ✓ 1 IPv4 address",
		"IPv4   ✓ TCP → HTTP 200",
		"Service is reachable.",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("concise output missing %q: %q", expected, output)
		}
	}
}

func TestClientReportCompactHTTP401ShowsReachabilityOnly(t *testing.T) {
	r := loadRenderFixtureRun(t, "client-probe-http-success")
	for i := range r.Evidence.Observations {
		if r.Evidence.Observations[i].Payload.HTTP != nil {
			r.Evidence.Observations[i].Payload.HTTP.StatusCode = 401
		}
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
	if !strings.Contains(output, "IPv4   ✓ TCP → HTTP 401") || !strings.Contains(output, "Service is reachable.") || !strings.Contains(output, "HTTP 401 received.") {
		t.Fatalf("compact 401 conclusion missing: %q", output)
	}
	if strings.Contains(output, "healthy") || strings.Contains(output, "successful") {
		t.Fatalf("application health was overstated: %q", output)
	}
}

func TestClientReportCompactConnectionRefused(t *testing.T) {
	v := loadRenderFixture(t, "client-probe-unattempted-address")
	var concise bytes.Buffer
	if err := Report(&concise, v, Options{}); err != nil {
		t.Fatal(err)
	}
	output := concise.String()
	if !strings.Contains(output, "IPv4   ✗ TCP: Connection refused") || !strings.Contains(output, "Blocked at TCP: the target refused the connection.") {
		t.Fatalf("compact refusal conclusion missing: %q", output)
	}
	if strings.Contains(output, "GLOBAL_PRIMARY") || strings.Contains(output, "BRANCH_PRIMARY") || strings.Contains(output, "connection_refused") {
		t.Fatalf("internal refusal vocabulary leaked: %q", output)
	}
}

func TestClientReportCompactCertificateFailure(t *testing.T) {
	v := loadRenderFixture(t, "client-probe-tls-untrusted")
	var concise bytes.Buffer
	if err := Report(&concise, v, Options{}); err != nil {
		t.Fatal(err)
	}
	output := concise.String()
	if !strings.Contains(output, "IPv4   ✗ TCP → TLS → certificate (not trusted)") || !strings.Contains(output, "Blocked at certificate verification.") {
		t.Fatalf("compact certificate conclusion missing: %q", output)
	}
	if strings.Contains(output, "UNTRUSTED_ISSUER") || strings.Contains(output, "CERTIFICATE_VERIFICATION") {
		t.Fatalf("internal certificate vocabulary leaked: %q", output)
	}
}

func TestClientReportCompactRedirectKeepsSanitizedDestination(t *testing.T) {
	r := loadRenderFixtureRun(t, "client-probe-http-success")
	for i := range r.Evidence.Observations {
		if r.Evidence.Observations[i].Payload.HTTP == nil {
			continue
		}
		r.Evidence.Observations[i].Payload.HTTP.ResultKind = model.HTTPRedirect
		r.Evidence.Observations[i].Payload.HTTP.StatusCode = 302
		r.Evidence.Observations[i].Payload.HTTP.RedirectTarget = &model.Target{Scheme: "https", Hostname: "example.test", EffectivePort: 443, Path: model.PathSummary{Present: true, SegmentCount: 2, QueryPresent: true, TrailingSlash: true}}
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
	if !strings.Contains(output, "IPv4   ✓ TCP → HTTP 302 redirect → https://example.test:443/...") {
		t.Fatalf("compact redirect missing: %q", output)
	}
	for _, sensitive := range []string{"/private/path", "token=secret"} {
		if strings.Contains(output, sensitive) {
			t.Fatalf("redirect output exposed %q: %q", sensitive, output)
		}
	}
}

func TestClientReportCompactAggregatesDuplicateSuccessfulExecutions(t *testing.T) {
	r := loadRenderFixtureRun(t, "client-probe-http-success")
	duplicates := make([]model.CheckExecution, 0, 5)
	for _, execution := range r.Evidence.CheckExecutions {
		if execution.BranchID == nil {
			continue
		}
		copy := execution
		copy.ExecutionID = model.ExecutionID(fmt.Sprintf("execution-%06d", 8+len(duplicates)))
		duplicates = append(duplicates, copy)
	}
	r.Evidence.CheckExecutions = append(r.Evidence.CheckExecutions, duplicates...)
	v, issues := model.ValidatePersistedEvaluatedRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	var concise bytes.Buffer
	if err := Report(&concise, v, Options{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(concise.String(), "IPv4   ✓ TCP → HTTP 200"); got != 1 {
		t.Fatalf("duplicate successful path was not aggregated, count=%d output=%q", got, concise.String())
	}
}

func TestClientReportCompactSummarizesHealthyDualStackHTTPS(t *testing.T) {
	definitions := map[model.CheckID]model.CheckDefinition{}
	entities := map[model.EntityID]model.Entity{}
	observations := map[model.ObservationID]model.Observation{}
	executions := []model.CheckExecution{}
	for _, family := range []struct {
		name    string
		address string
		branch  model.BranchID
	}{
		{name: "v4", address: "192.0.2.1", branch: "branch-000001"},
		{name: "v6", address: "2001:db8::1", branch: "branch-000002"},
	} {
		endpointID := model.EntityID("entity-" + family.name)
		entities[endpointID] = model.Entity{EntityID: endpointID, Identity: model.EntityIdentity{Endpoint: &model.EndpointIdentity{Address: netip.MustParseAddr(family.address), Port: 443, Transport: model.TransportTCP}}}
		branch := family.branch
		checks := []struct {
			kind model.CheckKind
			obs  model.Observation
		}{
			{kind: model.CheckTCPConnection, obs: model.Observation{ObservationID: model.ObservationID(family.name + "-tcp"), Payload: model.ObservationPayload{TCP: &model.TCPConnectionResult{Result: model.TCPAccepted}}}},
			{kind: model.CheckTLSTransport, obs: model.Observation{ObservationID: model.ObservationID(family.name + "-tls"), Payload: model.ObservationPayload{TLSTransport: &model.TLSTransportResultPayload{Result: model.TLSTransportCompleted}}}},
			{kind: model.CheckCertificateVerification, obs: model.Observation{ObservationID: model.ObservationID(family.name + "-cert"), Payload: model.ObservationPayload{CertificateVerification: &model.CertificateVerificationResultPayload{Result: model.CertVerified}}}},
			{kind: model.CheckHTTP, obs: model.Observation{ObservationID: model.ObservationID(family.name + "-http"), Payload: model.ObservationPayload{HTTP: &model.HTTPResult{ResultKind: model.HTTPResponse, StatusCode: 200}}}},
		}
		for i, check := range checks {
			checkID := model.CheckID(fmt.Sprintf("check-%s-%d", family.name, i))
			definitions[checkID] = model.CheckDefinition{CheckID: checkID, Kind: check.kind, Inputs: model.CheckInputs{SubjectEntityID: endpointID}}
			observations[check.obs.ObservationID] = check.obs
			executions = append(executions, model.CheckExecution{ExecutionID: model.ExecutionID(fmt.Sprintf("execution-%s-%d", family.name, i)), CheckID: checkID, BranchID: &branch, ObservationIDs: []model.ObservationID{check.obs.ObservationID}})
		}
		if family.name == "v6" {
			for i, check := range checks {
				checkID := model.CheckID(fmt.Sprintf("check-%s-%d", family.name, i))
				executions = append(executions, model.CheckExecution{ExecutionID: model.ExecutionID(fmt.Sprintf("duplicate-v6-%d", i)), CheckID: checkID, BranchID: &branch, ObservationIDs: []model.ObservationID{check.obs.ObservationID}})
			}
		}
	}

	lines := clientPathSummaryLines(model.Target{Scheme: "https"}, definitions, entities, executions, observations)
	if got, want := strings.Join(lines, "\n"), "IPv4   ✓ TCP → TLS → certificate → HTTP 200\nIPv6   ✓ TCP → TLS → certificate → HTTP 200"; got != want {
		t.Fatalf("dual-stack summary = %q, want %q", got, want)
	}
}

func TestClientReportVerboseRetainsTechnicalEvidence(t *testing.T) {
	v := loadRenderFixture(t, "client-probe-http-success")
	var verbose bytes.Buffer
	if err := Report(&verbose, v, Options{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	output := verbose.String()
	for _, detail := range []string{"CLIENT CHECK EVIDENCE", "execution-000001", "CHECK TCP_CONNECTION", "UNATTRIBUTED CHECK"} {
		if !strings.Contains(output, detail) {
			t.Fatalf("verbose output missing %q: %q", detail, output)
		}
	}
}

func TestClientReportHidesTargetMetadataInConciseAndRetainsItInVerbose(t *testing.T) {
	v := loadRenderFixture(t, "client-probe-http-success")
	var concise bytes.Buffer
	if err := Report(&concise, v, Options{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(concise.String(), "path_present=") || strings.Contains(concise.String(), "segment_count=") || strings.Contains(concise.String(), "trailing_slash=") {
		t.Fatalf("internal target metadata leaked into concise output: %q", concise.String())
	}
	if !strings.Contains(concise.String(), "RouteDoctor — http://example.test/") {
		t.Fatalf("human target missing: %q", concise.String())
	}

	var verbose bytes.Buffer
	if err := Report(&verbose, v, Options{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verbose.String(), "PathSummary") && !strings.Contains(verbose.String(), "path_present=") {
		t.Fatalf("verbose target detail missing: %q", verbose.String())
	}
}

func TestClientReportUsesBracketedIPv6Endpoint(t *testing.T) {
	r := loadRenderFixtureRun(t, "client-probe-http-success")
	for i := range r.Evidence.Entities {
		if r.Evidence.Entities[i].Identity.Endpoint != nil {
			r.Evidence.Entities[i].Identity.Endpoint.Address = netip.MustParseAddr("2001:db8::1")
		}
	}
	v, issues := model.ValidatePersistedEvaluatedRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	var concise bytes.Buffer
	if err := Report(&concise, v, Options{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	output := concise.String()
	if !strings.Contains(output, "endpoint=[2001:db8::1]:80") {
		t.Fatalf("bracketed IPv6 endpoint missing: %q", output)
	}
	if strings.Contains(output, "endpoint=2001:db8::1:80") {
		t.Fatalf("ambiguous IPv6 endpoint remained: %q", output)
	}
}

func TestClientReportKeepsConnectionRefusedFinding(t *testing.T) {
	v := loadRenderFixture(t, "client-probe-unattempted-address")
	var concise bytes.Buffer
	if err := Report(&concise, v, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(concise.String(), "IPv4   ✗ TCP: Connection refused") || !strings.Contains(concise.String(), "Blocked at TCP: the target refused the connection.") {
		t.Fatalf("connection-refused conclusion changed: %q", concise.String())
	}
}

func TestClientReportDetectionDoesNotDependOnProducerVersion(t *testing.T) {
	r := loadRenderFixtureRun(t, "client-probe-http-success")
	r.Evidence.Producer.Version = "0.1.0"
	v, issues := model.ValidatePersistedEvaluatedRun(r)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	var concise bytes.Buffer
	if err := Report(&concise, v, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(concise.String(), "RouteDoctor — http://example.test/") {
		t.Fatalf("release-version client report used the wrong renderer: %q", concise.String())
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
	if !strings.Contains(output, "IPv4   ✓ TCP → HTTP 302 redirect → https://example.test:443/...") {
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
