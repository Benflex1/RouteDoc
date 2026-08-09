package clientprobe

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"routedoc/internal/model"
)

func TestParseTargetSanitizesPersistedTarget(t *testing.T) {
	got, err := parseTarget("https://Example.Test/a/secret/?token=do-not-store#fragment")
	if err != nil {
		t.Fatal(err)
	}
	if got.persisted.Hostname != "example.test" || got.persisted.EffectivePort != 443 {
		t.Fatalf("target = %#v", got.persisted)
	}
	if got.persisted.Path != (model.PathSummary{Present: true, IsRoot: false, SegmentCount: 2, TrailingSlash: true, QueryPresent: true}) {
		t.Fatalf("path summary = %#v", got.persisted.Path)
	}
	if got.requestURL.Fragment != "" || got.requestURL.Path != "/a/secret/" || got.requestURL.RawQuery != "token=do-not-store" {
		t.Fatalf("transient request URL was not preserved safely: %#v", got.requestURL)
	}
	if strings.Contains(fmt.Sprint(got.persisted), "secret") {
		t.Fatal("persisted target leaked transient path data")
	}
}

func TestParseTargetDefaultsAndNormalizes(t *testing.T) {
	tests := []struct {
		name, raw, scheme, host string
		port                    uint16
		path                    model.PathSummary
	}{
		{name: "http root", raw: "http://EXAMPLE.TEST", scheme: "http", host: "example.test", port: 80, path: model.PathSummary{Present: true, IsRoot: true}},
		{name: "https explicit", raw: "https://example.test:8443/x", scheme: "https", host: "example.test", port: 8443, path: model.PathSummary{Present: true, SegmentCount: 1}},
		{name: "trailing dot", raw: "http://Example.Test./x/", scheme: "http", host: "example.test", port: 80, path: model.PathSummary{Present: true, SegmentCount: 1, TrailingSlash: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTarget(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.persisted.Scheme != tc.scheme || got.persisted.Hostname != tc.host || got.persisted.EffectivePort != tc.port || got.persisted.Path != tc.path {
				t.Fatalf("persisted target = %#v", got.persisted)
			}
			if got.requestURL.Path == "" {
				t.Fatal("request path must be /, not empty")
			}
		})
	}
}

func TestParseTargetPreservesRequestAuthoritySeparatelyFromEffectivePort(t *testing.T) {
	tests := []struct {
		name, raw, authority string
		port                 uint16
	}{
		{name: "http implicit", raw: "http://example.test/", authority: "example.test", port: 80},
		{name: "https implicit", raw: "https://example.test/", authority: "example.test", port: 443},
		{name: "http explicit", raw: "http://example.test:8080/", authority: "example.test:8080", port: 8080},
		{name: "https explicit", raw: "https://example.test:8443/", authority: "example.test:8443", port: 8443},
		{name: "ipv6 implicit", raw: "http://[2001:db8::1]/", authority: "[2001:db8::1]", port: 80},
		{name: "ipv6 explicit", raw: "https://[2001:db8::1]:8443/", authority: "[2001:db8::1]:8443", port: 8443},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTarget(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.requestURL.Host != tc.authority {
				t.Fatalf("request authority = %q, want %q", got.requestURL.Host, tc.authority)
			}
			if got.persisted.EffectivePort != tc.port {
				t.Fatalf("effective port = %d, want %d", got.persisted.EffectivePort, tc.port)
			}
		})
	}
}

func TestParseTargetRejectsUnsafeInputWithoutEcho(t *testing.T) {
	tests := []struct {
		name, raw, code string
	}{
		{"credentials", "https://user:password@example.test/private?token=secret", "url_credentials_disallowed"},
		{"scheme", "ftp://example.test/private", "unsupported_scheme"},
		{"host", "https:///private?token=secret", "missing_host"},
		{"port", "https://example.test:99999/private", "invalid_port"},
		{"control", "https://example.test/\x00secret", "invalid_url"},
		{"unicode", "https://éxample.test/private", "invalid_hostname"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseTarget(tc.raw)
			var input *InputError
			if !errors.As(err, &input) || input.Code != tc.code {
				t.Fatalf("err = %#v, want code %q", err, tc.code)
			}
			if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "password") {
				t.Fatalf("input error leaked URL data: %q", err)
			}
		})
	}
}

func TestM1Policy(t *testing.T) {
	if resolutionTimeout.String() != "5s" || tcpTimeout.String() != "5s" || tlsTimeout.String() != "5s" || httpTimeout.String() != "10s" || totalRunTimeout.String() != "30s" || coherenceWindow.String() != "1m0s" {
		t.Fatal("timeout policy changed")
	}
	if maxResponseHeaderBytes != 64<<10 || maxResponseBodyPrefix != 32<<10 || maxRetainedPerFamily != 8 || maxPinnedPerFamily != 1 || maxConcurrentStrategies != 3 || redirectFollowCap != 0 {
		t.Fatal("bounded client probe policy changed")
	}
}
