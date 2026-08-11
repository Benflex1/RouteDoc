package clientprobe

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"routedoc/internal/model"
)

func TestNormalizeTCPError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		got    model.TCPResult
		reason string
	}{
		{"timeout", timeoutError{}, model.TCPTimedOut, "connection_timeout"},
		{"refused", &net.OpError{Err: syscall.ECONNREFUSED}, model.TCPRefused, "connection_refused"},
		{"unreachable", &net.OpError{Err: syscall.ENETUNREACH}, model.TCPFailed, "network_unreachable"},
		{"host unreachable", &net.OpError{Err: syscall.EHOSTUNREACH}, model.TCPFailed, "host_unreachable"},
		{"generic", errors.New("opaque raw OS detail"), model.TCPFailed, "connection_failed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := normalizeTCPError(tc.err)
			if got != tc.got || reason != tc.reason {
				t.Fatalf("got %s/%s, want %s/%s", got, reason, tc.got, tc.reason)
			}
		})
	}
}

func TestNormalizeTLSAndHTTPError(t *testing.T) {
	if got, reason := normalizeTLSError(timeoutError{}); got != model.TLSTransportTimedOut || reason != "tls_timeout" {
		t.Fatalf("TLS timeout = %s/%s", got, reason)
	}
	if got, reason := normalizeTLSError(errors.New("tls alert raw detail")); got != model.TLSTransportFailed || reason != "tls_failed" {
		t.Fatalf("TLS failure = %s/%s", got, reason)
	}
	if got := normalizeHTTPError(timeoutError{}); got != "http_timeout" {
		t.Fatalf("HTTP timeout = %s", got)
	}
	if got := normalizeHTTPError(context.Canceled); got != "http_canceled" {
		t.Fatalf("HTTP cancel = %s", got)
	}
	if got := normalizeHTTPError(errors.New("Authorization: secret")); got != "http_failed" {
		t.Fatalf("HTTP failure = %s", got)
	}
}

func TestNormalizeVerification(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if got := normalizeVerification(leaf, nil, now); got != model.CertVerified {
		t.Fatalf("verified = %s", got)
	}
	if got := normalizeVerification(leaf, &x509.HostnameError{}, now); got != model.CertHostnameMismatch {
		t.Fatalf("hostname = %s", got)
	}
	if got := normalizeVerification(leaf, &x509.UnknownAuthorityError{}, now); got != model.CertUntrustedIssuer {
		t.Fatalf("issuer = %s", got)
	}
	if got := normalizeVerification(&x509.Certificate{NotBefore: now.Add(time.Hour), NotAfter: now.Add(2 * time.Hour)}, errors.New("generic"), now); got != model.CertNotYetValid {
		t.Fatalf("not yet valid = %s", got)
	}
	if got := normalizeVerification(&x509.Certificate{NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)}, errors.New("generic"), now); got != model.CertExpired {
		t.Fatalf("expired = %s", got)
	}
	if got := normalizeVerification(leaf, &x509.CertificateInvalidError{Reason: x509.IncompatibleUsage}, now); got != model.CertInvalidUsage {
		t.Fatalf("usage = %s", got)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "opaque timeout detail" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
