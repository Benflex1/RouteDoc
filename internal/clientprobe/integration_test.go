package clientprobe

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"routedoc/internal/model"
	"routedoc/internal/render"
	"routedoc/internal/rules"
	"routedoc/internal/schema/v1"
)

func TestDiagnoseHTTPResponseAndStatus(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	port := serverPort(context.Background(), server)
	dialer := &net.Dialer{}
	v, err := diagnose(context.Background(), "http://example.test:"+port+"/", model.Producer{Name: "routedoc", Version: "test", Build: "test"}, dependencies{
		now: func() time.Time { return time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC) },
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if strings.HasPrefix(address, "example.test:") || strings.HasPrefix(address, "127.0.0.1:") {
				return dialer.DialContext(ctx, network, "127.0.0.1:"+port)
			}
			return nil, errors.New("unexpected address")
		},
		systemRoots: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil },
		lookupEnv:   func(string) (string, bool) { return "", false },
	})
	if err != nil {
		t.Fatal(err)
	}
	if Status(v) != StatusSatisfied || requests == 0 {
		t.Fatalf("status=%v requests=%d", Status(v), requests)
	}
	if len(v.Value().Findings) != 0 {
		t.Fatalf("unexpected findings = %#v", v.Value().Findings)
	}
}

func serverPort(_ context.Context, server *httptest.Server) string {
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	return port
}

func TestCanonicalReportCompletionOrderDoesNotAffectEvidenceIDs(t *testing.T) {
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1")}
	a := assembleEvidence(topologyFacts(addresses))
	b := assembleEvidence(topologyFacts([]netip.Addr{addresses[1], addresses[0]}))
	ca, ia := model.CanonicalizeAndValidateEvidenceRun(a)
	cb, ib := model.CanonicalizeAndValidateEvidenceRun(b)
	if len(ia) != 0 || len(ib) != 0 {
		t.Fatalf("validation issues: %v / %v", ia, ib)
	}
	if len(ca.Value().Entities) != len(cb.Value().Entities) || len(ca.Value().ServicePath.Branches) != len(cb.Value().ServicePath.Branches) {
		t.Fatal("canonical topology changed with resolver completion order")
	}
}

func TestStatusBlockedByTCPRefusalCoverage(t *testing.T) {
	v, err := diagnose(context.Background(), "http://example.test", model.Producer{Name: "routedoc", Version: "test", Build: "test"}, dependencies{
		now: func() time.Time { return time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC) },
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		},
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, &net.OpError{Err: syscall.ECONNREFUSED}
		},
		systemRoots: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil },
		lookupEnv:   func(string) (string, bool) { return "", false },
	})
	if err != nil {
		t.Fatal(err)
	}
	if Status(v) != StatusBlocked {
		t.Fatalf("status = %v, findings = %#v", Status(v), v.Value().Findings)
	}
}

func TestStatusIndeterminateForDirectFailureAndCap(t *testing.T) {
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	v, err := diagnose(context.Background(), "http://example.test", model.Producer{Name: "routedoc", Version: "test", Build: "test"}, dependencies{
		now:         func() time.Time { return time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC) },
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) { return addresses, nil },
		dialContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("opaque failure") },
		systemRoots: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil },
		lookupEnv:   func(string) (string, bool) { return "", false },
	})
	if err != nil {
		t.Fatal(err)
	}
	if Status(v) != StatusIndeterminate {
		t.Fatalf("status = %v, findings = %#v", Status(v), v.Value().Findings)
	}
}

func TestEquivalentNormalAndPinnedBlockersKeepObservationsButSelectOnePrimary(t *testing.T) {
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
	facts := topologyFacts(addresses)
	facts.started, facts.finished = now, now.Add(time.Second)
	endpoint := endpointKey{address: addresses[0], port: 443}
	facts.tcp = []tcpFact{
		{mode: modeNormal, endpoint: endpoint, result: model.TCPRefused, exact: true, finished: now},
		{mode: modePinned, endpoint: endpoint, result: model.TCPRefused, exact: true, finished: now.Add(time.Nanosecond)},
	}
	evidence := assembleEvidence(facts)
	validated, validationIssues := model.CanonicalizeAndValidateEvidenceRun(evidence)
	if len(validationIssues) != 0 {
		t.Fatal(validationIssues)
	}
	evaluated, evaluationIssues := rules.NewEvaluator(rules.DefaultRegistry()).Evaluate(validated, facts.finished)
	if len(evaluationIssues) != 0 {
		t.Fatal(evaluationIssues)
	}
	refusedObservations := 0
	for _, observation := range evaluated.Value().Evidence.Observations {
		if observation.Payload.TCP != nil && observation.Payload.TCP.Result == model.TCPRefused {
			refusedObservations++
		}
	}
	if refusedObservations != 2 {
		t.Fatalf("refused observations = %d, want both direct attempts", refusedObservations)
	}
	primary, additional := 0, 0
	for _, finding := range evaluated.Value().Findings {
		if finding.TitleCode != model.TitleTCPConnectionRefused {
			continue
		}
		switch finding.Selection {
		case model.SelectionBranchPrimary:
			primary++
		case model.SelectionAdditional:
			additional++
		}
	}
	if primary != 1 || primary+additional < 1 {
		t.Fatalf("refused finding selections = %d primary, %d additional", primary, additional)
	}
}

func TestClientProbePrivacyDoesNotPersistTransientURLOrResponseData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Leak", "response-header-secret")
		_, _ = w.Write([]byte("response-body-secret Authorization Cookie Set-Cookie"))
	}))
	defer server.Close()
	port := serverPort(context.Background(), server)
	dialer := &net.Dialer{}
	v, err := diagnose(context.Background(), "http://example.test:"+port+"/private/segment?token=do-not-persist#fragment", model.Producer{Name: "routedoc", Version: "0.0.0-milestone1", Build: "test"}, dependencies{
		now: func() time.Time { return time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC) },
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, "127.0.0.1:"+port)
		},
		systemRoots: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil },
		lookupEnv:   func(string) (string, bool) { return "", false },
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, issues := v1.EncodeCanonical(v)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	var concise, verbose bytes.Buffer
	if err := render.Report(&concise, v, render.Options{}); err != nil {
		t.Fatal(err)
	}
	if err := render.Report(&verbose, v, render.Options{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	all := string(encoded) + concise.String() + verbose.String()
	for _, secret := range []string{"private", "private/segment", "token", "do-not-persist", "response-header-secret", "response-body-secret", "Authorization", "Cookie", "Set-Cookie"} {
		if strings.Contains(all, secret) {
			t.Fatalf("output leaked %q", secret)
		}
	}
}

func TestProxyEnvironmentPersistsOnlyApprovedSafeCapability(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	v, err := diagnose(context.Background(), "http://example.test", model.Producer{Name: "routedoc", Version: "0.0.0-milestone1", Build: "test"}, dependencies{
		now:         nowFunc(now),
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) { return nil, errors.New("no resolution") },
		dialContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("must not dial") },
		systemRoots: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil },
		lookupEnv: func(name string) (string, bool) {
			if name == "HTTPS_PROXY" {
				return "https://proxy-user:proxy-secret@proxy.example.invalid:4567", true
			}
			return "", false
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Value().Evidence.Capabilities) != 1 || v.Value().Evidence.Capabilities[0].ReasonCode != reasonProxyEnvironmentIgnored {
		t.Fatalf("capabilities = %#v", v.Value().Evidence.Capabilities)
	}
	b, issues := v1.EncodeCanonical(v)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if strings.Contains(string(b), "proxy-user") || strings.Contains(string(b), "proxy-secret") || strings.Contains(string(b), "proxy.example.invalid") || strings.Contains(string(b), "HTTPS_PROXY") {
		t.Fatal("proxy configuration leaked")
	}
}

func nowFunc(now time.Time) func() time.Time { return func() time.Time { return now } }
