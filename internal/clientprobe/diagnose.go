package clientprobe

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"time"

	"routedoc/internal/model"
	"routedoc/internal/rules"
)

var errClientProbeInternal = errors.New("client_probe_internal")

func Diagnose(ctx context.Context, rawURL string, producer model.Producer) (model.ValidatedEvaluatedRun, error) {
	return diagnose(ctx, rawURL, producer, defaultDependencies())
}

func diagnose(ctx context.Context, rawURL string, producer model.Producer, d dependencies) (model.ValidatedEvaluatedRun, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.lookupNetIP == nil {
		d.lookupNetIP = net.DefaultResolver.LookupNetIP
	}
	if d.dialContext == nil {
		d.dialContext = (&net.Dialer{}).DialContext
	}
	customRoots := d.systemRoots != nil
	if d.systemRoots == nil {
		d.systemRoots = x509.SystemCertPool
	}
	if d.lookupEnv == nil {
		d.lookupEnv = func(string) (string, bool) { return "", false }
	}
	target, err := parseTarget(rawURL)
	if err != nil {
		return model.ValidatedEvaluatedRun{}, err
	}
	started := d.now().UTC()
	if started.IsZero() {
		started = time.Now().UTC()
	}
	totalCtx, totalCancel := context.WithTimeout(ctx, totalRunTimeout)
	defer totalCancel()
	facts := runFacts{target: target, producer: producer, started: started, capabilities: detectProxyEnvironment(d.lookupEnv), limitations: []model.Limitation{}}
	resolutionCtx, resolutionCancel := context.WithTimeout(totalCtx, resolutionTimeout)
	addresses, lookupErr := d.lookupNetIP(resolutionCtx, "ip", target.persisted.Hostname)
	resolutionCancel()
	facts.resolution = resolutionFacts{completed: lookupErr == nil, addresses: normalizeAddresses(addresses)}
	if lookupErr != nil {
		facts.resolution.reason = normalizeResolutionError(resolutionCtx, lookupErr)
	} else {
		_, facts.resolution.truncated = retainAddresses(facts.resolution.addresses)
		facts.endpoints = planEndpoints(facts.resolution.addresses, target.persisted.EffectivePort)
	}
	if facts.resolution.completed && len(facts.endpoints) > 0 {
		facts.tcp = executeTCPStrategies(totalCtx, totalCtx, target, facts.endpoints, d.dialContext, d.now)
		for _, tcp := range facts.tcp {
			if tcp.result != model.TCPAccepted || tcp.conn == nil || !tcp.exact {
				continue
			}
			if target.persisted.Scheme == "http" {
				httpFact := executeHTTP(totalCtx, target, tcp.endpoint, tcp.conn, nil, d.now)
				httpFact.mode = tcp.mode
				facts.http = append(facts.http, httpFact)
				_ = tcp.conn.Close()
				continue
			}
			roots, rootsErr := d.systemRoots()
			trustSource := model.TrustSystem
			if customRoots {
				trustSource = model.TrustExplicit
			}
			if rootsErr != nil {
				roots = nil
			}
			tlsFact := executeTLS(totalCtx, tcp.endpoint, target.persisted.Hostname, tcp.conn, roots, trustSource, d.now)
			tlsFact.mode = tcp.mode
			facts.tls = append(facts.tls, tlsFact)
			if tlsFact.tlsConn == nil {
				continue
			}
			httpFact := executeHTTP(totalCtx, target, tcp.endpoint, nil, tlsFact.tlsConn, d.now)
			httpFact.mode = tcp.mode
			facts.http = append(facts.http, httpFact)
		}
	}
	facts.finished = d.now().UTC()
	if facts.finished.IsZero() || facts.finished.Before(facts.started) {
		facts.finished = facts.started
	}
	evidence := assembleEvidence(facts)
	validated, issues := model.CanonicalizeAndValidateEvidenceRun(evidence)
	if len(issues) != 0 {
		return model.ValidatedEvaluatedRun{}, errClientProbeInternal
	}
	evaluated, issues := rules.NewEvaluator(rules.DefaultRegistry()).Evaluate(validated, facts.finished)
	if len(issues) != 0 {
		return model.ValidatedEvaluatedRun{}, errClientProbeInternal
	}
	return evaluated, nil
}

func normalizeAddresses(addresses []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address.IsValid() {
			out = append(out, address.Unmap())
		}
	}
	return out
}

func normalizeResolutionError(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return "resolution_timeout"
	}
	return "resolution_failed"
}
