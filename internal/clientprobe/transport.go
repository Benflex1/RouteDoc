package clientprobe

import (
	"context"
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
