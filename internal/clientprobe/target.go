package clientprobe

import (
	"fmt"
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
	if !validTargetHostname(host) {
		return requestTarget{}, &InputError{Code: "invalid_hostname"}
	}
	port := uint16(0)
	if u.Port() != "" {
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
	u.Host = formatRequestHost(host, port, u.Hostname())
	return requestTarget{
		requestURL: u,
		persisted: model.Target{
			Scheme: scheme, Hostname: host, EffectivePort: port,
			Path: summarizePath(u.Path, u.RawQuery),
		},
	}, nil
}

func formatRequestHost(host string, port uint16, original string) string {
	if strings.Contains(original, ":") {
		return fmt.Sprintf("[%s]:%d", host, port)
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
