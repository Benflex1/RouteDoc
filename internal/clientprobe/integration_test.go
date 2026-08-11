package clientprobe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
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

func TestPinnedActualPeerFeedsDownstreamHTTPAtSameEndpoint(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	port := serverPort(context.Background(), server)
	dialer := &net.Dialer{}
	v, err := diagnose(context.Background(), "http://example.test:"+port+"/", model.Producer{Name: "routedoc", Version: "0.0.0-milestone1", Build: "test"}, dependencies{
		now: nowFunc(time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)),
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		},
		dialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, "127.0.0.1:"+port)
		},
		lookupEnv: func(string) (string, bool) { return "", false },
	})
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("target requests = %d, want ordinary plus pinned", requests)
	}
	report := v.Value().Evidence
	requestedID := endpointEntityID(report, endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: parsePortForTest(t, port)})
	actualID := endpointEntityID(report, endpointKey{address: netip.MustParseAddr("127.0.0.1"), port: parsePortForTest(t, port)})
	if requestedID == "" || actualID == "" || requestedID == actualID {
		t.Fatalf("requested=%q actual=%q endpoint attribution", requestedID, actualID)
	}
	tcpAccepted, httpResponses := 0, 0
	for _, observation := range report.Observations {
		if observation.Payload.TCP != nil && observation.Payload.TCP.Result == model.TCPAccepted {
			if observation.Payload.TCP.EndpointEntityID != actualID {
				t.Fatal("accepted TCP evidence remained on requested pinned endpoint")
			}
			tcpAccepted++
		}
		if observation.Payload.HTTP != nil && observation.Payload.HTTP.ResultKind == model.HTTPResponse {
			if len(observation.SubjectEntityIDs) == 0 || observation.SubjectEntityIDs[0] != actualID {
				t.Fatal("HTTP evidence was not attached to actual peer endpoint")
			}
			httpResponses++
		}
	}
	if tcpAccepted != 2 || httpResponses != 2 {
		t.Fatalf("actual endpoint observations tcp=%d http=%d", tcpAccepted, httpResponses)
	}
}

func serverPort(_ context.Context, server *httptest.Server) string {
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	return port
}

func parsePortForTest(t *testing.T, value string) uint16 {
	t.Helper()
	_, port, err := net.SplitHostPort("127.0.0.1:" + value)
	if err != nil {
		t.Fatal(err)
	}
	var parsed uint64
	if _, err := fmt.Sscanf(port, "%d", &parsed); err != nil || parsed > 65535 {
		t.Fatalf("invalid test port %q", value)
	}
	return uint16(parsed)
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

func TestHTTPHeaderAndBodyBoundsAcceptance(t *testing.T) {
	tests := []struct {
		name, header, body string
		wantResponse       bool
	}{
		{name: "headers and body within bounds", header: "header-secret", body: "body-secret" + strings.Repeat("b", maxResponseBodyPrefix-11), wantResponse: true},
		{name: "header at bounded limit", header: strings.Repeat("h", maxResponseHeaderBytes-2048), body: "body-secret", wantResponse: true},
		{name: "header exceeds bound", header: strings.Repeat("h", maxResponseHeaderBytes), body: "ignored", wantResponse: false},
		{name: "body exceeds retained prefix", header: "header-secret", body: "body-secret" + strings.Repeat("b", maxResponseBodyPrefix+1024), wantResponse: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				_, _ = http.ReadRequest(bufio.NewReader(server))
				_, _ = fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nX-Bounded: %s\r\nContent-Length: %d\r\n\r\n%s", tc.header, len(tc.body), tc.body)
			}()
			target, err := parseTarget("http://example.test/")
			if err != nil {
				t.Fatal(err)
			}
			endpoint := endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 80}
			fact := executeHTTP(context.Background(), target, endpoint, client, nil, time.Now)
			if fact.completed != tc.wantResponse {
				t.Fatalf("bounded HTTP fact = %#v, want completed=%t", fact, tc.wantResponse)
			}
			if !fact.completed {
				return
			}
			facts := topologyFacts([]netip.Addr{endpoint.address})
			facts.target = target
			facts.target.persisted.EffectivePort = 80
			facts.endpoints = planEndpoints([]netip.Addr{endpoint.address}, 80)
			facts.tcp = []tcpFact{{mode: modePinned, endpoint: endpoint, result: model.TCPAccepted, exact: true, finished: time.Now().UTC()}}
			fact.mode = modePinned
			facts.http = []httpFact{fact}
			validated, issues := model.CanonicalizeAndValidateEvidenceRun(assembleEvidence(facts))
			if len(issues) != 0 {
				t.Fatal(issues)
			}
			evaluated, issues := rules.NewEvaluator(rules.DefaultRegistry()).Evaluate(validated, time.Now().UTC())
			if len(issues) != 0 {
				t.Fatal(issues)
			}
			encoded, issues := v1.EncodeCanonical(evaluated)
			if len(issues) != 0 {
				t.Fatal(issues)
			}
			var concise, verbose bytes.Buffer
			if err := render.Report(&concise, evaluated, render.Options{}); err != nil {
				t.Fatal(err)
			}
			if err := render.Report(&verbose, evaluated, render.Options{Verbose: true}); err != nil {
				t.Fatal(err)
			}
			all := string(encoded) + concise.String() + verbose.String()
			if strings.Contains(all, "header-secret") || strings.Contains(all, "body-secret") {
				t.Fatal("bounded response content leaked into report output")
			}
		})
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

func TestProxyEnvironmentIsDetectedButReceivesZeroContact(t *testing.T) {
	var requests int
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer targetServer.Close()
	port := serverPort(context.Background(), targetServer)
	trap, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer trap.Close()
	trapURL := "http://proxy-user:proxy-secret@127.0.0.1:" + strings.TrimPrefix(trap.Addr().String(), "127.0.0.1:")
	dialer := &net.Dialer{}
	v, err := diagnose(context.Background(), "http://example.test:"+port+"/", model.Producer{Name: "routedoc", Version: "0.0.0-milestone1", Build: "test"}, dependencies{
		now: nowFunc(time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)),
		lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		dialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, "127.0.0.1:"+port)
		},
		systemRoots: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil },
		lookupEnv: func(name string) (string, bool) {
			if name == "HTTP_PROXY" {
				return trapURL, true
			}
			return "", false
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if requests == 0 {
		t.Fatal("direct target received no request")
	}
	if len(v.Value().Evidence.Capabilities) != 1 || v.Value().Evidence.Capabilities[0].ReasonCode != reasonProxyEnvironmentIgnored {
		t.Fatalf("proxy capability = %#v", v.Value().Evidence.Capabilities)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := trap.Accept()
		accepted <- conn
	}()
	select {
	case conn := <-accepted:
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("proxy trap received a connection")
	case <-time.After(100 * time.Millisecond):
	}
	encoded, issues := v1.EncodeCanonical(v)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if strings.Contains(string(encoded), "proxy-user") || strings.Contains(string(encoded), "proxy-secret") || strings.Contains(string(encoded), trapURL) || strings.Contains(string(encoded), "HTTP_PROXY") {
		t.Fatal("proxy configuration leaked")
	}
}

func TestStrategyCompletionOrderProducesCanonicalEquivalentReports(t *testing.T) {
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	run := func(reverse bool) []byte {
		facts := topologyFacts(addresses)
		dial := func(_ context.Context, _, address string) (net.Conn, error) {
			delay := 10 * time.Millisecond
			if strings.HasPrefix(address, "example.test") {
				delay = 30 * time.Millisecond
			} else if strings.HasPrefix(address, "192.0.2.1") {
				delay = 20 * time.Millisecond
			}
			if reverse {
				delay = 40*time.Millisecond - delay
			}
			time.Sleep(delay)
			remote := netip.MustParseAddr("198.51.100.9")
			if strings.HasPrefix(address, "192.0.2.1") {
				remote = netip.MustParseAddr("192.0.2.1")
			} else if strings.HasPrefix(address, "[2001:db8::1]") {
				remote = netip.MustParseAddr("2001:db8::1")
			}
			return &testConn{remote: &net.TCPAddr{IP: net.ParseIP(remote.String()), Port: 443}}, nil
		}
		facts.tcp = executeTCPStrategies(context.Background(), context.Background(), facts.target, facts.endpoints, dial, nowFunc(facts.started))
		evaluatedEvidence, issues := model.CanonicalizeAndValidateEvidenceRun(assembleEvidence(facts))
		if len(issues) != 0 {
			t.Fatal(issues)
		}
		evaluated, issues := rules.NewEvaluator(rules.DefaultRegistry()).Evaluate(evaluatedEvidence, facts.finished)
		if len(issues) != 0 {
			t.Fatal(issues)
		}
		encoded, issues := v1.EncodeCanonical(evaluated)
		if len(issues) != 0 {
			t.Fatal(issues)
		}
		return encoded
	}
	first, second := run(false), run(true)
	if !bytes.Equal(first, second) {
		t.Fatalf("completion order changed canonical report")
	}
}

func nowFunc(now time.Time) func() time.Time { return func() time.Time { return now } }
