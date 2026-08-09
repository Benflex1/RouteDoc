package clientprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"routedoc/internal/model"
)

func TestPinnedTCPUsesOneAddressPerFamily(t *testing.T) {
	facts := topologyFacts([]netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")})
	var mu sync.Mutex
	var calls []string
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		calls = append(calls, network+":"+address)
		mu.Unlock()
		return nil, errors.New("synthetic failure")
	}
	facts.tcp = executeTCPStrategies(context.Background(), context.Background(), facts.target, facts.endpoints, dial, time.Now)
	if len(facts.tcp) != 3 {
		t.Fatalf("strategy facts = %d, want normal plus two pinned", len(facts.tcp))
	}
	if len(calls) != 3 {
		t.Fatalf("dial calls = %d, want 3: %v", len(calls), calls)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "192.0.2.1:443") || !strings.Contains(joined, "[2001:db8::1]:443") {
		t.Fatalf("calls did not contain first deterministic address per family: %v", calls)
	}
}

func TestPinnedTCPAcceptedIsExactEndpoint(t *testing.T) {
	facts := topologyFacts([]netip.Addr{netip.MustParseAddr("192.0.2.1")})
	fake := &testConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}}
	facts.tcp = executeTCPStrategies(context.Background(), context.Background(), facts.target, facts.endpoints, func(_ context.Context, _, address string) (net.Conn, error) {
		if address == "192.0.2.1:443" {
			return fake, nil
		}
		return nil, errors.New("normal failed")
	}, time.Now)
	if len(facts.tcp) != 2 {
		t.Fatalf("facts = %#v", facts.tcp)
	}
	var accepted bool
	for _, fact := range facts.tcp {
		if fact.mode == modePinned && fact.result == model.TCPAccepted && fact.exact && fact.endpoint.address == netip.MustParseAddr("192.0.2.1") {
			accepted = true
		}
	}
	if !accepted {
		t.Fatal("accepted pinned fact was not exact")
	}
}

func TestNormalSuccessOutsideRetainedIsDirectlyAttributed(t *testing.T) {
	facts := topologyFacts([]netip.Addr{netip.MustParseAddr("192.0.2.1")})
	facts.tcp = executeTCPStrategies(context.Background(), context.Background(), facts.target, facts.endpoints, func(_ context.Context, _, address string) (net.Conn, error) {
		if address == "example.test:443" {
			return &testConn{remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 443}}, nil
		}
		return nil, errors.New("pinned failed")
	}, time.Now)
	r := assembleEvidence(facts)
	if branchForEndpoint(r, endpointKey{address: netip.MustParseAddr("198.51.100.9"), port: 443}) == nil {
		t.Fatal("normal outside endpoint did not become a direct branch")
	}
}

func TestNormalFailureWithoutRemoteEndpointIsUnscoped(t *testing.T) {
	facts := topologyFacts([]netip.Addr{netip.MustParseAddr("192.0.2.1")})
	facts.tcp = executeTCPStrategies(context.Background(), context.Background(), facts.target, facts.endpoints, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("synthetic opaque failure")
	}, time.Now)
	r := assembleEvidence(facts)
	for _, b := range r.ServicePath.Branches {
		if len(b.OrderedEdgeIDs) == 0 {
			t.Fatal("empty branch was fabricated for normal failure")
		}
	}
	if len(r.Observations) == 0 {
		t.Fatal("pinned endpoint evidence was lost")
	}
	var found bool
	for _, e := range r.CheckExecutions {
		if e.BranchID == nil && e.CheckID == "check-000002" && e.ReasonCode != nil && *e.ReasonCode == "connection_failed" {
			found = true
		}
	}
	if !found {
		t.Fatal("unscoped normal execution not retained")
	}
}

type testConn struct{ remote net.Addr }

func (c *testConn) Read([]byte) (int, error)         { return 0, errors.New("closed") }
func (c *testConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *testConn) Close() error                     { return nil }
func (c *testConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4zero, Port: 1} }
func (c *testConn) RemoteAddr() net.Addr             { return c.remote }
func (c *testConn) SetDeadline(time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(time.Time) error { return nil }

func TestTCPFactEndpointFormatting(t *testing.T) {
	if got := net.JoinHostPort("example.test", strconv.Itoa(443)); got != "example.test:443" {
		t.Fatal(got)
	}
}

func TestTLSValidatesPresentedLeafAndIntermediates(t *testing.T) {
	fixture := newTLSFixture(t, "example.test", true)
	client, server := net.Pipe()
	go fixture.serve(server)
	fact := executeTLS(context.Background(), endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 443}, "example.test", client, fixture.roots, model.TrustExplicit, time.Now)
	if fact.result != model.TLSTransportCompleted || fact.peer == nil || fact.verification != model.CertVerified || fact.tlsConn == nil {
		t.Fatalf("TLS fact = %#v", fact)
	}
	if !strings.HasPrefix(fact.peer.fingerprint, "sha256:") || fact.peer.dnsSANCount == 0 {
		t.Fatalf("peer summary = %#v", fact.peer)
	}
	_ = fact.tlsConn.Close()
}

func TestTLSPreCertificateFailureHasNoPeer(t *testing.T) {
	client, server := net.Pipe()
	_ = server.Close()
	fact := executeTLS(context.Background(), endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 443}, "example.test", client, nil, model.TrustSystem, time.Now)
	if fact.result != model.TLSTransportFailed || fact.peer != nil || fact.tlsConn != nil {
		t.Fatalf("pre-certificate TLS fact = %#v", fact)
	}
}

func TestTLSVerificationSeparatesHostnameAndTrust(t *testing.T) {
	fixture := newTLSFixture(t, "other.test", true)
	client, server := net.Pipe()
	go fixture.serve(server)
	fact := executeTLS(context.Background(), endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 443}, "example.test", client, fixture.roots, model.TrustExplicit, time.Now)
	if fact.peer == nil || fact.verification != model.CertHostnameMismatch || fact.tlsConn != nil {
		t.Fatalf("hostname verification fact = %#v", fact)
	}
}

func TestTLSAssemblyPassesArchitecture13Validation(t *testing.T) {
	fixture := newTLSFixture(t, "example.test", true)
	client, server := net.Pipe()
	go fixture.serve(server)
	fact := executeTLS(context.Background(), endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 443}, "example.test", client, fixture.roots, model.TrustExplicit, time.Now)
	facts := topologyFacts([]netip.Addr{netip.MustParseAddr("192.0.2.1")})
	facts.tcp = []tcpFact{{mode: modePinned, endpoint: fact.endpoint, result: model.TCPAccepted, exact: true, finished: time.Now().UTC()}}
	facts.tls = []tlsFact{fact}
	r := assembleEvidence(facts)
	if _, issues := model.ValidateEvidenceRun(r); len(issues) != 0 {
		t.Fatalf("TLS evidence is invalid: %v", issues)
	}
	if fact.tlsConn != nil {
		_ = fact.tlsConn.Close()
	}
}
