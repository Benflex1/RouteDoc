package clientprobe

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"syscall"
	"time"

	"routedoc/internal/model"
)

func normalizeTCPError(err error) (model.TCPResult, string) {
	if isTimeout(err) {
		return model.TCPTimedOut, "connection_timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return model.TCPRefused, "connection_refused"
	}
	if errors.Is(err, syscall.ENETUNREACH) {
		return model.TCPFailed, "network_unreachable"
	}
	if errors.Is(err, syscall.EHOSTUNREACH) {
		return model.TCPFailed, "host_unreachable"
	}
	return model.TCPFailed, "connection_failed"
}

func normalizeTLSError(err error) (model.TLSTransportResult, string) {
	if isTimeout(err) {
		return model.TLSTransportTimedOut, "tls_timeout"
	}
	return model.TLSTransportFailed, "tls_failed"
}

func normalizeHTTPError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "http_canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return "http_timeout"
	}
	return "http_failed"
}

func normalizeVerification(leaf *x509.Certificate, err error, now time.Time) model.CertificateVerificationResult {
	if err == nil {
		return model.CertVerified
	}
	var hostnameErr x509.HostnameError
	var hostnamePtr *x509.HostnameError
	if errors.As(err, &hostnameErr) || errors.As(err, &hostnamePtr) {
		return model.CertHostnameMismatch
	}
	var authorityErr x509.UnknownAuthorityError
	var authorityPtr *x509.UnknownAuthorityError
	if errors.As(err, &authorityErr) || errors.As(err, &authorityPtr) {
		return model.CertUntrustedIssuer
	}
	var invalidErr x509.CertificateInvalidError
	var invalidPtr *x509.CertificateInvalidError
	if errors.As(err, &invalidErr) || errors.As(err, &invalidPtr) {
		if invalidErr.Reason == x509.IncompatibleUsage {
			return model.CertInvalidUsage
		}
		if invalidPtr != nil && invalidPtr.Reason == x509.IncompatibleUsage {
			return model.CertInvalidUsage
		}
	}
	if leaf == nil {
		return model.CertVerifierUnavailable
	}
	now = now.UTC()
	if now.Before(leaf.NotBefore) {
		return model.CertNotYetValid
	}
	if now.After(leaf.NotAfter) {
		return model.CertExpired
	}
	if invalidErr.Reason == x509.IncompatibleUsage {
		return model.CertInvalidUsage
	}
	return model.CertVerifierUnavailable
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
