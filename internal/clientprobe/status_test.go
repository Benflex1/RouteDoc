package clientprobe

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"routedoc/internal/model"
	"routedoc/internal/rules"
)

func TestStatusZeroValidatedReportIsIndeterminate(t *testing.T) {
	if got := Status(model.ValidatedEvaluatedRun{}); got != StatusIndeterminate {
		t.Fatalf("status = %v", got)
	}
}

func TestDiagnoseReturnsSafeInputError(t *testing.T) {
	_, err := diagnose(context.Background(), "https://user:secret@example.test/private?token=secret", model.Producer{Name: "routedoc", Version: "test", Build: "test"}, testDependencies())
	var input *InputError
	if !errors.As(err, &input) || input.Code != "url_credentials_disallowed" {
		t.Fatalf("error = %#v", err)
	}
}

func TestDiagnoseBuildsValidatedReportFromFakeDependencies(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	_, err := diagnose(context.Background(), "http://example.test", model.Producer{Name: "routedoc", Version: "test", Build: "test"}, dependencies{
		now: func() time.Time { return now },
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		},
		dialContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") },
		systemRoots: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil },
		lookupEnv:   func(string) (string, bool) { return "", false },
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestStatusUsesOnlyValidatedReportForHostnameMismatch(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	fixture := newTLSFixtureWithValidity(t, "other.test", true, now, now.Add(-time.Hour), now.Add(time.Hour))
	client, server := net.Pipe()
	go fixture.serve(server)
	observedTLS := executeTLS(context.Background(), endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 443}, "example.test", client, fixture.roots, model.TrustExplicit, func() time.Time { return now })
	facts := topologyFacts([]netip.Addr{netip.MustParseAddr("192.0.2.1")})
	facts.started, facts.finished = now, now.Add(time.Second)
	facts.tcp = []tcpFact{{mode: modePinned, endpoint: observedTLS.endpoint, result: model.TCPAccepted, exact: true, finished: now}}
	facts.tls = []tlsFact{observedTLS}
	evaluated := evaluateClientFacts(t, facts)
	if Status(evaluated) != StatusBlocked {
		t.Fatalf("hostname mismatch status = %v, findings = %#v", Status(evaluated), evaluated.Value().Findings)
	}
}

func TestStatusUsesOnlyValidatedReportForUnattemptedBranch(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	facts := topologyFacts(addresses)
	facts.started, facts.finished = now, now.Add(time.Second)
	endpoint := endpointKey{address: addresses[0], port: 443}
	facts.tcp = []tcpFact{{mode: modePinned, endpoint: endpoint, result: model.TCPRefused, exact: true, finished: now}}
	facts.target.persisted.Scheme = "http"
	facts.target.persisted.EffectivePort = 80
	facts.target.requestURL = mustParseTargetForTest(t, "http://example.test/").requestURL
	facts.endpoints = planEndpoints(addresses, 80)
	facts.tcp[0].endpoint.port = 80
	evaluated := evaluateClientFacts(t, facts)
	if Status(evaluated) != StatusIndeterminate {
		t.Fatalf("unattempted branch status = %v", Status(evaluated))
	}
}

func TestStatusUsesOnlyValidatedReportForResolverTruncation(t *testing.T) {
	addresses := make([]netip.Addr, 0, maxRetainedPerFamily+1)
	for i := 1; i <= maxRetainedPerFamily+1; i++ {
		addresses = append(addresses, netip.MustParseAddr("192.0.2."+itoaTest(i)))
	}
	evaluated := evaluateClientFacts(t, topologyFacts(addresses))
	if Status(evaluated) != StatusIndeterminate {
		t.Fatalf("resolver truncation status = %v", Status(evaluated))
	}
}

func evaluateClientFacts(t *testing.T, facts runFacts) model.ValidatedEvaluatedRun {
	t.Helper()
	validated, issues := model.CanonicalizeAndValidateEvidenceRun(assembleEvidence(facts))
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	evaluated, issues := rules.NewEvaluator(rules.DefaultRegistry()).Evaluate(validated, facts.finished)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	return evaluated
}

func mustParseTargetForTest(t *testing.T, raw string) requestTarget {
	t.Helper()
	target, err := parseTarget(raw)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func testDependencies() dependencies {
	return dependencies{
		now: time.Now,
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("resolution failed")
		},
		dialContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("dial failed") },
		systemRoots: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil },
		lookupEnv:   func(string) (string, bool) { return "", false },
	}
}
