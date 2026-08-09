package clientprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"routedoc/internal/model"
)

func executeTCPStrategies(totalCtx, _ context.Context, target requestTarget, plans []endpointPlan, dial func(context.Context, string, string) (net.Conn, error), now func() time.Time) []tcpFact {
	if len(plans) == 0 {
		return []tcpFact{}
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	if now == nil {
		now = time.Now
	}
	type strategy struct {
		mode     attemptMode
		endpoint endpointKey
		address  string
	}
	strategies := []strategy{{mode: modeNormal, endpoint: endpointKey{port: target.persisted.EffectivePort}, address: net.JoinHostPort(target.persisted.Hostname, strconv.Itoa(int(target.persisted.EffectivePort)))}}
	for _, family := range []bool{true, false} {
		for _, p := range plans {
			if p.pinned && p.key.address.Is4() == family {
				strategies = append(strategies, strategy{mode: modePinned, endpoint: p.key, address: net.JoinHostPort(p.key.address.String(), strconv.Itoa(int(p.key.port)))})
				break
			}
		}
	}
	if len(strategies) > maxConcurrentStrategies {
		strategies = strategies[:maxConcurrentStrategies]
	}
	results := make(chan tcpFact, len(strategies))
	for _, s := range strategies {
		go func(s strategy) {
			started := now().UTC()
			ctx, cancel := context.WithTimeout(totalCtx, tcpTimeout)
			conn, err := dial(ctx, "tcp", s.address)
			cancel()
			finished := now().UTC()
			if finished.Before(started) {
				finished = started
			}
			if err != nil {
				result, reason := normalizeTCPError(err)
				results <- tcpFact{mode: s.mode, endpoint: s.endpoint, result: result, reason: reason, durationNS: finished.Sub(started).Nanoseconds(), started: started, finished: finished, exact: s.mode == modePinned}
				return
			}
			if s.mode == modePinned {
				results <- tcpFact{mode: s.mode, endpoint: s.endpoint, result: model.TCPAccepted, durationNS: finished.Sub(started).Nanoseconds(), started: started, finished: finished, exact: true, conn: conn}
				return
			}
			remote, ok := exactRemoteEndpoint(conn)
			if !ok {
				_ = conn.Close()
				results <- tcpFact{mode: s.mode, endpoint: s.endpoint, result: model.TCPFailed, reason: "normal_endpoint_unknown", durationNS: finished.Sub(started).Nanoseconds(), started: started, finished: finished, exact: false}
				return
			}
			results <- tcpFact{mode: s.mode, endpoint: remote, result: model.TCPAccepted, durationNS: finished.Sub(started).Nanoseconds(), started: started, finished: finished, exact: true, conn: conn}
		}(s)
	}
	out := make([]tcpFact, 0, len(strategies))
	for range strategies {
		out = append(out, <-results)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].endpoint.address.Is4() != out[j].endpoint.address.Is4() {
			return out[i].endpoint.address.Is4()
		}
		if c := out[i].endpoint.address.Compare(out[j].endpoint.address); c != 0 {
			return c < 0
		}
		if out[i].endpoint.port != out[j].endpoint.port {
			return out[i].endpoint.port < out[j].endpoint.port
		}
		return out[i].mode < out[j].mode
	})
	return out
}

func exactRemoteEndpoint(conn net.Conn) (endpointKey, bool) {
	if conn == nil {
		return endpointKey{}, false
	}
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || remote == nil || remote.Port <= 0 || remote.Port > 65535 {
		return endpointKey{}, false
	}
	address, ok := netip.AddrFromSlice(remote.IP)
	if !ok || !address.IsValid() {
		return endpointKey{}, false
	}
	return endpointKey{address: address.Unmap(), port: uint16(remote.Port)}, true
}

type peerFact struct {
	fingerprint string
	count       uint64
	notBefore   time.Time
	notAfter    time.Time
	sanType     model.SANType
	sanCount    uint64
	dnsSANCount uint64
}

type tlsFact struct {
	mode             attemptMode
	endpoint         endpointKey
	result           model.TLSTransportResult
	reason           string
	protocolVersion  string
	cipherSuite      string
	negotiatedALPN   string
	sniSent          string
	durationNS       int64
	peer             *peerFact
	verification     model.CertificateVerificationResult
	verificationTime time.Time
	trustSource      model.TrustSource
	tlsConn          *tls.Conn
}

func executeTLS(parent context.Context, endpoint endpointKey, hostname string, conn net.Conn, roots *x509.CertPool, trustSource model.TrustSource, now func() time.Time) tlsFact {
	if parent == nil {
		parent = context.Background()
	}
	if now == nil {
		now = time.Now
	}
	started := now().UTC()
	fact := tlsFact{endpoint: endpoint, result: model.TLSTransportFailed, reason: "tls_failed", trustSource: trustSource, verification: model.CertVerifierUnavailable, verificationTime: started}
	if conn == nil {
		return fact
	}
	ctx, cancel := context.WithTimeout(parent, tlsTimeout)
	tlsConn := tls.Client(conn, &tls.Config{ServerName: hostname, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) // explicit verification follows below
	err := tlsConn.HandshakeContext(ctx)
	cancel()
	finished := now().UTC()
	if finished.Before(started) {
		finished = started
	}
	fact.durationNS = finished.Sub(started).Nanoseconds()
	state := tlsConn.ConnectionState()
	if err != nil {
		_, fact.reason = normalizeTLSError(err)
	} else {
		fact.result = model.TLSTransportCompleted
		fact.reason = ""
		fact.protocolVersion = tlsVersionToken(state.Version)
		fact.cipherSuite = tls.CipherSuiteName(state.CipherSuite)
		fact.negotiatedALPN = state.NegotiatedProtocol
		fact.sniSent = hostname
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		fact.peer = summarizePeer(leaf, uint64(len(state.PeerCertificates)))
		fact.verificationTime = started.UTC()
		selectedRoots := roots
		if selectedRoots == nil {
			selectedRoots, err = x509.SystemCertPool()
			fact.trustSource = model.TrustSystem
		}
		if selectedRoots == nil {
			fact.verification = model.CertVerifierUnavailable
		} else {
			intermediates := x509.NewCertPool()
			for _, certificate := range state.PeerCertificates[1:] {
				intermediates.AddCert(certificate)
			}
			_, verifyErr := leaf.Verify(x509.VerifyOptions{DNSName: hostname, Roots: selectedRoots, Intermediates: intermediates, CurrentTime: fact.verificationTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			fact.verification = normalizeVerification(leaf, verifyErr, fact.verificationTime)
		}
		if fact.verification == model.CertVerified && fact.result == model.TLSTransportCompleted {
			fact.tlsConn = tlsConn
			return fact
		}
	}
	_ = tlsConn.Close()
	return fact
}

func tlsVersionToken(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return ""
	}
}

func summarizePeer(leaf *x509.Certificate, count uint64) *peerFact {
	digest := sha256.Sum256(leaf.Raw)
	peer := &peerFact{fingerprint: "sha256:" + hex.EncodeToString(digest[:]), count: count, notBefore: leaf.NotBefore.UTC(), notAfter: leaf.NotAfter.UTC()}
	if len(leaf.DNSNames) > 0 {
		peer.sanType, peer.sanCount, peer.dnsSANCount = model.SANDNS, uint64(len(leaf.DNSNames)), uint64(len(leaf.DNSNames))
	} else if len(leaf.IPAddresses) > 0 {
		peer.sanType, peer.sanCount = model.SANIP, uint64(len(leaf.IPAddresses))
	} else {
		peer.sanType, peer.sanCount = model.SANOther, uint64(len(leaf.EmailAddresses)+len(leaf.URIs))
	}
	return peer
}
