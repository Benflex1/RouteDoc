package clientprobe

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"routedoc/internal/model"
)

type InputError struct{ Code string }

func (e *InputError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code
}

type requestTarget struct {
	requestURL *url.URL
	persisted  model.Target
}

// ParseTarget exposes the same normalization used by the client probe to
// callers that need only the effective target, such as local inspection.
// It intentionally returns the persisted target and does not create a second
// URL parsing policy.
func ParseTarget(raw string) (model.Target, error) {
	target, err := parseTarget(raw)
	if err != nil {
		return model.Target{}, err
	}
	return target.persisted, nil
}

func parseTarget(raw string) (requestTarget, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.IsAbs() == false {
		return requestTarget{}, &InputError{Code: "invalid_url"}
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return requestTarget{}, &InputError{Code: "unsupported_scheme"}
	}
	if u.User != nil {
		return requestTarget{}, &InputError{Code: "url_credentials_disallowed"}
	}
	if u.Host == "" || u.Hostname() == "" {
		return requestTarget{}, &InputError{Code: "missing_host"}
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		host = address.String()
	} else if !validTargetHostname(host) {
		return requestTarget{}, &InputError{Code: "invalid_hostname"}
	}
	explicitPort := u.Port() != ""
	port := uint16(0)
	if explicitPort {
		parsed, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || parsed == 0 {
			return requestTarget{}, &InputError{Code: "invalid_port"}
		}
		port = uint16(parsed)
	} else if strings.Contains(u.Host, ":") && !strings.Contains(u.Host, "]") {
		return requestTarget{}, &InputError{Code: "invalid_port"}
	}
	if port == 0 {
		if scheme == "http" {
			port = 80
		} else {
			port = 443
		}
	}
	if u.Path == "" {
		u.Path = "/"
	}
	// Fragments are never sent by HTTP and are not part of the transient request.
	u.Fragment = ""
	u.RawFragment = ""
	u.Scheme = scheme
	u.Host = formatRequestAuthority(host, port, explicitPort)
	return requestTarget{
		requestURL: u,
		persisted: model.Target{
			Scheme: scheme, Hostname: host, EffectivePort: port,
			Path: summarizePath(u.Path, u.RawQuery),
		},
	}, nil
}

func formatRequestAuthority(host string, port uint16, explicitPort bool) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if !explicitPort {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func summarizePath(path, query string) model.PathSummary {
	if path == "" {
		path = "/"
	}
	trimmed := strings.TrimPrefix(path, "/")
	root := path == "/"
	segments := uint64(0)
	if !root {
		for _, segment := range strings.Split(trimmed, "/") {
			if segment != "" {
				segments++
			}
		}
	}
	return model.PathSummary{
		Present: true, IsRoot: root, SegmentCount: segments,
		TrailingSlash: !root && strings.HasSuffix(path, "/"), QueryPresent: query != "",
	}
}

func validTargetHostname(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String() == host
	}
	if host == "" || len(host) > 253 || strings.ToLower(host) != host {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
