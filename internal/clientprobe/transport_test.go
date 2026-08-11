package clientprobe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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

func TestPinnedTCPSuccessUsesActualRemotePeer(t *testing.T) {
	requested := netip.MustParseAddr("192.0.2.1")
	actual := netip.MustParseAddr("198.51.100.9")
	facts := topologyFacts([]netip.Addr{requested})
	facts.tcp = executeTCPStrategies(context.Background(), context.Background(), facts.target, facts.endpoints, func(_ context.Context, _, address string) (net.Conn, error) {
		if address == net.JoinHostPort(requested.String(), "443") {
			return &testConn{remote: &net.TCPAddr{IP: net.ParseIP(actual.String()), Port: 443}}, nil
		}
		return nil, errors.New("normal failed")
	}, time.Now)
	var pinned tcpFact
	for _, fact := range facts.tcp {
		if fact.mode == modePinned {
			pinned = fact
		}
	}
	if pinned.result != model.TCPAccepted || !pinned.exact || pinned.endpoint.address != actual {
		t.Fatalf("pinned fact = %#v, want accepted actual endpoint", pinned)
	}
	r := assembleEvidence(facts)
	requestedID := endpointEntityID(r, endpointKey{address: requested, port: 443})
	actualID := endpointEntityID(r, endpointKey{address: actual, port: 443})
	if requestedID == "" || actualID == "" || requestedID == actualID {
		t.Fatalf("endpoint entities requested=%q actual=%q", requestedID, actualID)
	}
	var acceptedActual bool
	for _, observation := range r.Observations {
		if observation.Payload.TCP == nil || observation.Payload.TCP.Result != model.TCPAccepted {
			continue
		}
		if observation.Payload.TCP.EndpointEntityID == requestedID {
			t.Fatal("requested endpoint received false accepted evidence")
		}
		if observation.Payload.TCP.EndpointEntityID == actualID {
			acceptedActual = true
		}
	}
	if !acceptedActual || branchForEndpoint(r, endpointKey{address: actual, port: 443}) == nil {
		t.Fatal("actual peer did not receive accepted evidence and a direct branch")
	}
	actualAddressID := endpointAddressEntity(r, endpointKey{address: actual, port: 443})
	for _, edge := range r.ServicePath.Edges {
		if edge.Relation == model.RelationResolvesTo && edge.To == actualAddressID {
			t.Fatal("differing pinned peer received fabricated RESOLVES_TO edge")
		}
	}
}

func TestPinnedTCPUnknownRemoteCannotFabricateEndpointEvidence(t *testing.T) {
	requested := netip.MustParseAddr("192.0.2.1")
	facts := topologyFacts([]netip.Addr{requested})
	facts.tcp = executeTCPStrategies(context.Background(), context.Background(), facts.target, facts.endpoints, func(_ context.Context, _, address string) (net.Conn, error) {
		if address == "192.0.2.1:443" {
			return &testConn{remote: nil}, nil
		}
		return nil, errors.New("normal failed")
	}, time.Now)
	for _, fact := range facts.tcp {
		if fact.mode == modePinned && (fact.result == model.TCPAccepted || fact.exact) {
			t.Fatalf("unknown pinned peer fabricated success: %#v", fact)
		}
	}
	r := assembleEvidence(facts)
	requestedID := endpointEntityID(r, endpointKey{address: requested, port: 443})
	for _, observation := range r.Observations {
		if observation.Payload.TCP != nil && observation.Payload.TCP.EndpointEntityID == requestedID && observation.Payload.TCP.Result == model.TCPAccepted {
			t.Fatal("unknown pinned peer became accepted endpoint evidence")
		}
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
	if fixture.root == nil || fixture.intermediate == nil || fixture.leaf == nil {
		t.Fatal("TLS fixture did not retain root, intermediate, and leaf certificates")
	}
	if err := fixture.root.CheckSignatureFrom(fixture.root); err != nil || !fixture.root.IsCA || !fixture.root.BasicConstraintsValid {
		t.Fatalf("root is not a trusted self-signed CA: signature=%v is_ca=%t constraints=%t", err, fixture.root.IsCA, fixture.root.BasicConstraintsValid)
	}
	if err := fixture.intermediate.CheckSignatureFrom(fixture.root); err != nil {
		t.Fatalf("intermediate is not signed by root: %v", err)
	}
	if !fixture.intermediate.IsCA || !fixture.intermediate.BasicConstraintsValid || !fixture.intermediate.MaxPathLenZero || fixture.intermediate.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("intermediate lacks valid CA constraints/key usage: %#v", fixture.intermediate)
	}
	if err := fixture.leaf.CheckSignatureFrom(fixture.intermediate); err != nil {
		t.Fatalf("leaf is not signed by intermediate: %v", err)
	}
	if err := fixture.leaf.CheckSignatureFrom(fixture.root); err == nil {
		t.Fatal("leaf is directly signed by root; fixture must contain a real intermediate")
	}
	if len(fixture.certificate.Certificate) != 2 ||
		!bytes.Equal(fixture.certificate.Certificate[0], fixture.leaf.Raw) ||
		!bytes.Equal(fixture.certificate.Certificate[1], fixture.intermediate.Raw) {
		t.Fatal("server must present leaf followed by intermediate, without root")
	}
	if bytes.Equal(fixture.certificate.Certificate[1], fixture.root.Raw) {
		t.Fatal("server must not present the trusted root")
	}
	if subjects := fixture.roots.Subjects(); len(subjects) != 1 || !bytes.Equal(subjects[0], fixture.root.RawSubject) {
		t.Fatal("verification roots must contain only the trusted root")
	}
	if len(fixture.leaf.ExtKeyUsage) != 1 || fixture.leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(fixture.leaf.DNSNames) != 1 || fixture.leaf.DNSNames[0] != "example.test" {
		t.Fatal("leaf is not a server-auth certificate for example.test")
	}
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

func TestTLSFailureAcceptanceHasNoPeerOrHTTP(t *testing.T) {
	tests := []struct {
		name  string
		serve func(net.Conn)
		want  model.TLSTransportResult
	}{
		{name: "peer reset", serve: func(conn net.Conn) { _ = conn.Close() }, want: model.TLSTransportFailed},
		{name: "plaintext server", serve: func(conn net.Conn) {
			buf := make([]byte, 4096)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			_ = conn.Close()
		}, want: model.TLSTransportFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			go tc.serve(server)
			fact := executeTLS(context.Background(), endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 443}, "example.test", client, nil, model.TrustSystem, time.Now)
			if fact.result != tc.want || fact.peer != nil || fact.tlsConn != nil {
				t.Fatalf("TLS failure fact = %#v", fact)
			}
			target, err := parseTarget("https://example.test/")
			if err != nil {
				t.Fatal(err)
			}
			httpFact := executeHTTP(context.Background(), target, fact.endpoint, nil, fact.tlsConn, time.Now)
			if httpFact.completed || httpFact.requestCalls != 0 || httpFact.reason != "tls_peer_unverified" {
				t.Fatalf("HTTP was not suppressed after TLS failure: %#v", httpFact)
			}
		})
	}
}

func TestTLSHandshakeTimeoutAcceptanceIsNormalized(t *testing.T) {
	client, server := net.Pipe()
	hold := make(chan struct{})
	go func() {
		defer server.Close()
		buf := make([]byte, 4096)
		_, _ = server.Read(buf)
		<-hold
	}()
	parent, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	fact := executeTLS(parent, endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 443}, "example.test", client, nil, model.TrustSystem, time.Now)
	if fact.result != model.TLSTransportTimedOut || fact.reason != "tls_timeout" || fact.peer != nil || fact.tlsConn != nil {
		t.Fatalf("TLS timeout fact = %#v", fact)
	}
	close(hold)
	_ = server.Close()
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

func TestCertificateVerificationEnumsAcceptance(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name, serverName string
		roots            bool
		before, after    time.Time
		want             model.CertificateVerificationResult
	}{
		{name: "valid chain", serverName: "example.test", roots: true, before: now.Add(-time.Hour), after: now.Add(time.Hour), want: model.CertVerified},
		{name: "untrusted issuer", serverName: "example.test", roots: false, before: now.Add(-time.Hour), after: now.Add(time.Hour), want: model.CertUntrustedIssuer},
		{name: "expired leaf", serverName: "example.test", roots: true, before: now.Add(-2 * time.Hour), after: now.Add(-time.Hour), want: model.CertExpired},
		{name: "not yet valid leaf", serverName: "example.test", roots: true, before: now.Add(time.Hour), after: now.Add(2 * time.Hour), want: model.CertNotYetValid},
		{name: "hostname mismatch", serverName: "other.test", roots: true, before: now.Add(-time.Hour), after: now.Add(time.Hour), want: model.CertHostnameMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newTLSFixtureWithValidity(t, tc.serverName, tc.roots, now, tc.before, tc.after)
			client, server := net.Pipe()
			go fixture.serve(server)
			fact := executeTLS(context.Background(), endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 443}, "example.test", client, fixture.roots, model.TrustExplicit, func() time.Time { return now })
			if fact.result != model.TLSTransportCompleted || fact.peer == nil || fact.verification != tc.want || (tc.want != model.CertVerified && fact.tlsConn != nil) {
				t.Fatalf("TLS fact = %#v, want verification %s", fact, tc.want)
			}
			facts := topologyFacts([]netip.Addr{netip.MustParseAddr("192.0.2.1")})
			facts.started, facts.finished = now, now.Add(time.Second)
			facts.tcp = []tcpFact{{mode: modePinned, endpoint: fact.endpoint, result: model.TCPAccepted, exact: true, finished: now}}
			facts.tls = []tlsFact{fact}
			r := assembleEvidence(facts)
			found := false
			for _, observation := range r.Observations {
				if observation.Payload.CertificateVerification != nil {
					if observation.Payload.CertificateVerification.Result != tc.want {
						t.Fatalf("persisted certificate result = %s, want %s", observation.Payload.CertificateVerification.Result, tc.want)
					}
					found = true
				}
			}
			if !found {
				t.Fatal("certificate result was not persisted")
			}
			if fact.tlsConn != nil {
				_ = fact.tlsConn.Close()
			}
		})
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

func TestHTTPReusesExactEstablishedConnection(t *testing.T) {
	client, server := net.Pipe()
	var requests int
	go func() {
		defer server.Close()
		req, err := http.ReadRequest(bufio.NewReader(server))
		if err == nil && req.Host == "example.test:80" && req.Header.Get("User-Agent") == "RouteDoctor/1" {
			requests++
		}
		_, _ = server.Write([]byte("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"))
	}()
	target := requestTarget{requestURL: &url.URL{Scheme: "http", Host: "example.test:80", Path: "/"}, persisted: model.Target{Scheme: "http", Hostname: "example.test", EffectivePort: 80, Path: model.PathSummary{Present: true, IsRoot: true}}}
	fact := executeHTTP(context.Background(), target, endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 80}, client, nil, time.Now)
	if fact.resultKind != model.HTTPResponse || fact.statusCode != 401 || requests != 1 || fact.dialCalls != 1 {
		t.Fatalf("HTTP fact = %#v requests=%d", fact, requests)
	}
}

func TestHTTPSConnectionOwnershipAcceptance(t *testing.T) {
	fixture := newTLSFixture(t, "example.test", true)
	client, server := net.Pipe()
	var handshakes, requests int
	serverDone := make(chan error, 1)
	go func() {
		defer server.Close()
		serverTLS := tls.Server(server, &tls.Config{
			Certificates: []tls.Certificate{fixture.certificate},
			NextProtos:   []string{"http/1.1"},
			VerifyConnection: func(tls.ConnectionState) error {
				handshakes++
				return nil
			},
		})
		if err := serverTLS.Handshake(); err != nil {
			serverDone <- err
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(serverTLS))
		if err != nil {
			serverDone <- err
			return
		}
		if req.Host != "example.test" {
			serverDone <- fmt.Errorf("Host = %q, want example.test", req.Host)
			return
		}
		requests++
		_, _ = serverTLS.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		serverDone <- nil
	}()

	target, err := parseTarget("https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 443}
	tlsFact := executeTLS(context.Background(), endpoint, target.persisted.Hostname, client, fixture.roots, model.TrustExplicit, time.Now)
	if tlsFact.tlsConn == nil || tlsFact.verification != model.CertVerified {
		t.Fatalf("TLS fact = %#v", tlsFact)
	}
	httpFact := executeHTTP(context.Background(), target, endpoint, nil, tlsFact.tlsConn, time.Now)
	if httpFact.resultKind != model.HTTPResponse || httpFact.dialCalls != 1 || httpFact.requestCalls != 1 {
		t.Fatalf("HTTP ownership fact = %#v", httpFact)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if handshakes != 1 || requests != 1 {
		t.Fatalf("server handshakes=%d requests=%d, want one each", handshakes, requests)
	}
	_ = tlsFact.tlsConn.Close()
}

func TestLocalServersObserveImplicitAndExplicitHostAuthority(t *testing.T) {
	tests := []struct {
		name, raw, wantHost string
		secure              bool
	}{
		{name: "http implicit", raw: "http://example.test/", wantHost: "example.test"},
		{name: "http explicit", raw: "http://example.test:8080/", wantHost: "example.test:8080"},
		{name: "https implicit", raw: "https://example.test/", wantHost: "example.test", secure: true},
		{name: "https explicit", raw: "https://example.test:8443/", wantHost: "example.test:8443", secure: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			fixture := newTLSFixture(t, "example.test", true)
			hostSeen := make(chan string, 1)
			serverErr := make(chan error, 1)
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					serverErr <- acceptErr
					return
				}
				defer conn.Close()
				var serverConn net.Conn = conn
				if tc.secure {
					server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{fixture.certificate}, NextProtos: []string{"http/1.1"}})
					if handshakeErr := server.Handshake(); handshakeErr != nil {
						serverErr <- handshakeErr
						return
					}
					serverConn = server
					defer server.Close()
				}
				req, readErr := http.ReadRequest(bufio.NewReader(serverConn))
				if readErr != nil {
					serverErr <- readErr
					return
				}
				hostSeen <- req.Host
				_, _ = serverConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			}()

			target, err := parseTarget(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			var rawConn net.Conn = conn
			var tlsConn *tls.Conn
			if tc.secure {
				tlsConn = tls.Client(conn, &tls.Config{ServerName: target.persisted.Hostname, InsecureSkipVerify: true})
				if err := tlsConn.Handshake(); err != nil {
					t.Fatal(err)
				}
				rawConn = nil
			}
			fact := executeHTTP(context.Background(), target, endpointKey{address: netip.MustParseAddr("127.0.0.1"), port: target.persisted.EffectivePort}, rawConn, tlsConn, time.Now)
			if fact.resultKind != model.HTTPResponse {
				t.Fatalf("HTTP fact = %#v", fact)
			}
			select {
			case err := <-serverErr:
				t.Fatal(err)
			case got := <-hostSeen:
				if got != tc.wantHost {
					t.Fatalf("server observed Host %q, want %q", got, tc.wantHost)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for local server")
			}
		})
	}
}

func TestRedirectIsObservedButNotFollowed(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = http.ReadRequest(bufio.NewReader(server))
		_, _ = server.Write([]byte("HTTP/1.1 302 Found\r\nLocation: /private/path?token=secret\r\nContent-Length: 0\r\n\r\n"))
	}()
	target := requestTarget{requestURL: &url.URL{Scheme: "http", Host: "example.test:80", Path: "/"}, persisted: model.Target{Scheme: "http", Hostname: "example.test", EffectivePort: 80, Path: model.PathSummary{Present: true, IsRoot: true}}}
	fact := executeHTTP(context.Background(), target, endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 80}, client, nil, time.Now)
	if fact.resultKind != model.HTTPRedirect || fact.redirectTarget == nil || fact.redirectTarget.Path.QueryPresent != true {
		t.Fatalf("redirect fact = %#v", fact)
	}
	if fact.requestCalls != 1 {
		t.Fatalf("redirect request calls = %d, want 1", fact.requestCalls)
	}
	if strings.Contains(fmt.Sprint(fact), "private") || strings.Contains(fmt.Sprint(fact), "secret") {
		t.Fatal("redirect fact retained raw URL data")
	}
}

func TestHTTPCancellationAcceptance(t *testing.T) {
	client, server := net.Pipe()
	serverDone := make(chan struct{})
	go func() {
		defer server.Close()
		_, _ = http.ReadRequest(bufio.NewReader(server))
		<-serverDone
	}()
	target, err := parseTarget("http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	fact := executeHTTP(parent, target, endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 80}, client, nil, time.Now)
	close(serverDone)
	if fact.completed || fact.reason != "http_canceled" || fact.requestCalls != 1 {
		t.Fatalf("HTTP cancellation fact = %#v", fact)
	}
}

func TestHTTPStageTimeoutAcceptance(t *testing.T) {
	client, server := net.Pipe()
	serverDone := make(chan struct{})
	go func() {
		defer server.Close()
		_, _ = http.ReadRequest(bufio.NewReader(server))
		<-serverDone
	}()
	target, err := parseTarget("http://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	fact := executeHTTP(context.Background(), target, endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 80}, client, nil, time.Now)
	close(serverDone)
	if fact.completed || fact.reason != "http_timeout" || fact.requestCalls != 1 {
		t.Fatalf("HTTP stage timeout fact = %#v", fact)
	}
}

func TestHTTPSVerificationFailureSuppressesHTTP(t *testing.T) {
	client, server := net.Pipe()
	_ = server.Close()
	target := requestTarget{requestURL: &url.URL{Scheme: "https", Host: "example.test:443", Path: "/"}, persisted: model.Target{Scheme: "https", Hostname: "example.test", EffectivePort: 443, Path: model.PathSummary{Present: true, IsRoot: true}}}
	fact := executeHTTP(context.Background(), target, endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 443}, client, nil, time.Now)
	if fact.dialCalls != 0 || fact.reason != "tls_peer_unverified" || fact.completed {
		t.Fatalf("suppressed HTTPS fact = %#v", fact)
	}
}

func TestHTTPAssemblyPassesEvidenceValidation(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_, _ = http.ReadRequest(bufio.NewReader(server))
		_, _ = server.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
	}()
	facts := topologyFacts([]netip.Addr{netip.MustParseAddr("192.0.2.1")})
	facts.target.persisted.Scheme = "http"
	facts.target.persisted.EffectivePort = 80
	facts.target.requestURL = &url.URL{Scheme: "http", Host: "example.test:80", Path: "/"}
	endpoint := endpointKey{address: netip.MustParseAddr("192.0.2.1"), port: 80}
	facts.endpoints = planEndpoints([]netip.Addr{endpoint.address}, endpoint.port)
	facts.tcp = []tcpFact{{mode: modePinned, endpoint: endpoint, result: model.TCPAccepted, exact: true, finished: time.Now().UTC()}}
	facts.http = []httpFact{executeHTTP(context.Background(), facts.target, endpoint, client, nil, time.Now)}
	facts.http[0].mode = modePinned
	r := assembleEvidence(facts)
	if _, issues := model.ValidateEvidenceRun(r); len(issues) != 0 {
		t.Fatalf("HTTP evidence is invalid: %v", issues)
	}
}
