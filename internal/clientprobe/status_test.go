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
