package clientprobe

import (
	"context"
	"crypto/x509"
	"net"
	"net/netip"
	"os"
	"sort"
	"time"

	"routedoc/internal/model"
)

type dependencies struct {
	now         func() time.Time
	lookupNetIP func(context.Context, string, string) ([]netip.Addr, error)
	dialContext func(context.Context, string, string) (net.Conn, error)
	systemRoots func() (*x509.CertPool, error)
	lookupEnv   func(string) (string, bool)
}

type endpointKey struct {
	address netip.Addr
	port    uint16
}

type endpointPlan struct {
	key      endpointKey
	retained bool
	pinned   bool
	resolved bool
}

type retainedAddresses struct {
	v4 []netip.Addr
	v6 []netip.Addr
}

type resolutionFacts struct {
	completed bool
	addresses []netip.Addr
	reason    string
	truncated bool
}

type attemptMode uint8

const (
	modeNormal attemptMode = iota
	modePinned
)

type tcpFact struct {
	mode       attemptMode
	endpoint   endpointKey
	result     model.TCPResult
	reason     string
	durationNS int64
	started    time.Time
	finished   time.Time
	exact      bool
	conn       net.Conn
}

type normalFact struct {
	endpoint   endpointKey
	tcpResult  model.TCPResult
	reason     string
	durationNS int64
	started    time.Time
	finished   time.Time
	exact      bool
	conn       net.Conn
}

type runFacts struct {
	target       requestTarget
	started      time.Time
	finished     time.Time
	resolution   resolutionFacts
	endpoints    []endpointPlan
	tcp          []tcpFact
	tls          []tlsFact
	normal       *normalFact
	capabilities []model.Capability
	limitations  []model.Limitation
}

func defaultDependencies() dependencies {
	return dependencies{
		now:         time.Now,
		lookupNetIP: net.DefaultResolver.LookupNetIP,
		dialContext: (&net.Dialer{}).DialContext,
		lookupEnv:   os.LookupEnv,
	}
}

func retainAddresses(addrs []netip.Addr) (retainedAddresses, bool) {
	seen := make(map[netip.Addr]bool, len(addrs))
	var out retainedAddresses
	for _, raw := range addrs {
		if !raw.IsValid() {
			continue
		}
		a := raw.Unmap()
		if seen[a] {
			continue
		}
		seen[a] = true
		if a.Is4() {
			out.v4 = append(out.v4, a)
		} else if a.Is6() {
			out.v6 = append(out.v6, a)
		}
	}
	sort.Slice(out.v4, func(i, j int) bool { return out.v4[i].Compare(out.v4[j]) < 0 })
	sort.Slice(out.v6, func(i, j int) bool { return out.v6[i].Compare(out.v6[j]) < 0 })
	truncated := len(out.v4) > maxRetainedPerFamily || len(out.v6) > maxRetainedPerFamily
	if len(out.v4) > maxRetainedPerFamily {
		out.v4 = out.v4[:maxRetainedPerFamily]
	}
	if len(out.v6) > maxRetainedPerFamily {
		out.v6 = out.v6[:maxRetainedPerFamily]
	}
	return out, truncated
}

func planEndpoints(addrs []netip.Addr, port uint16) []endpointPlan {
	retained, _ := retainAddresses(addrs)
	out := make([]endpointPlan, 0, len(retained.v4)+len(retained.v6))
	for i, address := range retained.v4 {
		out = append(out, endpointPlan{key: endpointKey{address: address, port: port}, retained: true, pinned: i < maxPinnedPerFamily, resolved: true})
	}
	for i, address := range retained.v6 {
		out = append(out, endpointPlan{key: endpointKey{address: address, port: port}, retained: true, pinned: i < maxPinnedPerFamily, resolved: true})
	}
	return out
}

func detectProxyEnvironment(lookup func(string) (string, bool)) []model.Capability {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"} {
		if value, ok := lookup(name); ok && value != "" {
			return []model.Capability{{CapabilityID: "capability-000001", Kind: model.CapabilityHTTPProbe, State: model.CapabilityAvailable, ReasonCode: reasonProxyEnvironmentIgnored}}
		}
	}
	return []model.Capability{}
}

func endpointSort(a, b endpointKey) bool {
	if a.address.Is4() != b.address.Is4() {
		return a.address.Is4()
	}
	if c := a.address.Compare(b.address); c != 0 {
		return c < 0
	}
	return a.port < b.port
}

func (m attemptMode) String() string {
	if m == modePinned {
		return "pinned"
	}
	return "normal"
}

func mergeEndpointPlans(f runFacts) []endpointPlan {
	plans := append([]endpointPlan{}, f.endpoints...)
	seen := map[endpointKey]bool{}
	for _, p := range plans {
		seen[p.key] = true
	}
	if f.normal != nil && f.normal.exact && !seen[f.normal.endpoint] {
		plans = append(plans, endpointPlan{key: f.normal.endpoint})
		seen[f.normal.endpoint] = true
	}
	if f.normal == nil {
		for _, fact := range f.tcp {
			if fact.mode == modeNormal && fact.exact && !seen[fact.endpoint] {
				plans = append(plans, endpointPlan{key: fact.endpoint})
				seen[fact.endpoint] = true
			}
		}
	}
	sort.Slice(plans, func(i, j int) bool { return endpointSort(plans[i].key, plans[j].key) })
	return plans
}

func reasonPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}

func targetEntityID() model.EntityID   { return "entity-000001" }
func hostnameEntityID() model.EntityID { return "entity-000002" }
func vantageID() model.VantageID       { return "vantage-000001" }
