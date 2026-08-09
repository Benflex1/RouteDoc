package clientprobe

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"routedoc/internal/model"
)

func TestRetainedAddressesAllBecomeBranches(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.30")}
	facts := topologyFacts(addrs)
	r := assembleEvidence(facts)
	if len(r.ServicePath.Branches) != 3 {
		t.Fatalf("branches = %d, want 3", len(r.ServicePath.Branches))
	}
	if len(endpointEntities(r)) != 3 {
		t.Fatalf("endpoint entities = %d, want 3", len(endpointEntities(r)))
	}
	for _, p := range facts.endpoints {
		if p.pinned {
			continue
		}
		branch := branchForEndpoint(r, p.key)
		if branch == nil || !hasSkippedTCPForEndpoint(r, branch.BranchID, p.key) {
			t.Fatalf("unattempted endpoint %v lacks skipped TCP execution", p.key)
		}
	}
}

func TestResolutionOrderingIsIPv4ThenIPv6Numeric(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("192.0.2.10")}
	got, truncated := retainAddresses(addrs)
	if truncated || len(got.v4) != 2 || len(got.v6) != 2 {
		t.Fatalf("retention = %#v truncated=%v", got, truncated)
	}
	if got.v4[0].String() != "192.0.2.10" || got.v4[1].String() != "192.0.2.20" || got.v6[0].String() != "2001:db8::1" || got.v6[1].String() != "2001:db8::2" {
		t.Fatalf("ordering = %#v", got)
	}
}

func TestUnattemptedEndpointHasSkippedTCPAndDependencies(t *testing.T) {
	r := assembleEvidence(topologyFacts([]netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}))
	for _, e := range r.CheckExecutions {
		if e.BranchID == nil || e.ReasonCode == nil || *e.ReasonCode != reasonAddressAttemptCap {
			continue
		}
		if e.Lifecycle != model.CheckNotRun || e.Verdict != model.CheckSkipped {
			t.Fatalf("cap execution = %#v", e)
		}
	}
}

func TestResolutionTruncationAddsPartialVisibility(t *testing.T) {
	addrs := make([]netip.Addr, 0, maxRetainedPerFamily+1)
	for i := 1; i <= maxRetainedPerFamily+1; i++ {
		addrs = append(addrs, netip.MustParseAddr("192.0.2."+itoaTest(i)))
	}
	r := assembleEvidence(topologyFacts(addrs))
	if len(r.Limitations) != 1 || r.Limitations[0].Code != model.LimitationPartialVisibility {
		t.Fatalf("limitations = %#v", r.Limitations)
	}
}

func TestNoProbeModeBranchExists(t *testing.T) {
	r := assembleEvidence(topologyFacts([]netip.Addr{netip.MustParseAddr("192.0.2.1")}))
	for _, b := range r.ServicePath.Branches {
		if strings.Contains(strings.ToLower(string(b.BranchID)), "normal") || strings.Contains(strings.ToLower(string(b.BranchID)), "pinned") {
			t.Fatalf("probe mode became a branch: %#v", b)
		}
	}
}

func TestNormalOutsideRetainedUsesDirectConnectEdgeOnly(t *testing.T) {
	facts := topologyFacts([]netip.Addr{netip.MustParseAddr("192.0.2.1")})
	facts.normal = &normalFact{endpoint: endpointKey{address: netip.MustParseAddr("192.0.2.99"), port: 443}, tcpResult: model.TCPAccepted, exact: true}
	r := assembleEvidence(facts)
	branch := branchForEndpoint(r, facts.normal.endpoint)
	if branch == nil {
		t.Fatal("outside endpoint branch missing")
	}
	for _, eid := range branch.OrderedEdgeIDs {
		for _, e := range r.ServicePath.Edges {
			if e.EdgeID != eid || e.Relation != model.RelationConnectsTo {
				continue
			}
			if e.From != "entity-000001" {
				t.Fatalf("outside edge from = %s, want URL target", e.From)
			}
		}
	}
	for _, o := range r.Observations {
		if o.Kind == model.ObservationSystemResolution && o.Payload.Resolution != nil && o.Payload.Resolution.AddressEntityID != nil && *o.Payload.Resolution.AddressEntityID == endpointAddressEntity(r, facts.normal.endpoint) {
			t.Fatal("outside endpoint received fabricated resolution")
		}
	}
}

func TestProxyEnvironmentUsesSafeExistingCapability(t *testing.T) {
	got := detectProxyEnvironment(func(name string) (string, bool) {
		if name == "HTTPS_PROXY" {
			return "https://user:secret@proxy.invalid:1234", true
		}
		return "", false
	})
	if len(got) != 1 || got[0].CapabilityID != "capability-000001" || got[0].Kind != model.CapabilityHTTPProbe || got[0].State != model.CapabilityAvailable || got[0].ReasonCode != reasonProxyEnvironmentIgnored {
		t.Fatalf("capability = %#v", got)
	}
}

func TestTopologyAssemblyPassesEvidenceValidation(t *testing.T) {
	r := assembleEvidence(topologyFacts([]netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}))
	if _, issues := model.ValidateEvidenceRun(r); len(issues) != 0 {
		t.Fatalf("assembled topology is invalid: %v", issues)
	}
}

func topologyFacts(addrs []netip.Addr) runFacts {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	return runFacts{
		target:  requestTarget{persisted: model.Target{Scheme: "https", Hostname: "example.test", EffectivePort: 443, Path: model.PathSummary{Present: true, IsRoot: true}}},
		started: now, finished: now.Add(time.Second),
		resolution: resolutionFacts{completed: true, addresses: addrs},
		endpoints:  planEndpoints(addrs, 443),
	}
}

func endpointEntities(r model.EvidenceRun) []model.Entity {
	out := []model.Entity{}
	for _, e := range r.Entities {
		if e.Kind == model.EntitySocketEndpoint {
			out = append(out, e)
		}
	}
	return out
}

func branchForEndpoint(r model.EvidenceRun, key endpointKey) *model.Branch {
	endpoint := endpointEntityID(r, key)
	for _, execution := range r.CheckExecutions {
		if execution.BranchID == nil {
			continue
		}
		for _, definition := range r.CheckDefinitions {
			if definition.CheckID == execution.CheckID && definition.Kind == model.CheckTCPConnection && definition.Inputs.SubjectEntityID == endpoint {
				for i := range r.ServicePath.Branches {
					if r.ServicePath.Branches[i].BranchID == *execution.BranchID {
						return &r.ServicePath.Branches[i]
					}
				}
			}
		}
	}
	for i := range r.ServicePath.Branches {
		for _, eid := range r.ServicePath.Branches[i].OrderedEdgeIDs {
			for _, e := range r.ServicePath.Edges {
				if e.EdgeID != eid {
					continue
				}
				for _, entity := range r.Entities {
					if entity.EntityID == e.To && entity.Kind == model.EntitySocketEndpoint && entity.Identity.Endpoint != nil && entity.Identity.Endpoint.Address == key.address && entity.Identity.Endpoint.Port == key.port {
						return &r.ServicePath.Branches[i]
					}
				}
			}
		}
	}
	return nil
}

func hasSkippedTCPForEndpoint(r model.EvidenceRun, branch model.BranchID, key endpointKey) bool {
	endpoint := endpointEntityID(r, key)
	for _, e := range r.CheckExecutions {
		if e.BranchID != nil && *e.BranchID == branch && e.ReasonCode != nil && *e.ReasonCode == reasonAddressAttemptCap {
			for _, d := range r.CheckDefinitions {
				if d.CheckID == e.CheckID && d.Kind == model.CheckTCPConnection && d.Inputs.SubjectEntityID == endpoint {
					return true
				}
			}
		}
	}
	return false
}

func endpointEntityID(r model.EvidenceRun, key endpointKey) model.EntityID {
	for _, e := range r.Entities {
		if e.Kind == model.EntitySocketEndpoint && e.Identity.Endpoint != nil && e.Identity.Endpoint.Address == key.address && e.Identity.Endpoint.Port == key.port {
			return e.EntityID
		}
	}
	return ""
}

func endpointAddressEntity(r model.EvidenceRun, key endpointKey) model.EntityID {
	for _, e := range r.Entities {
		if e.Kind == model.EntityIPAddress && e.Identity.IPAddress != nil && e.Identity.IPAddress.Address == key.address {
			return e.EntityID
		}
	}
	return ""
}

func itoaTest(i int) string {
	if i < 10 {
		return "0"[0:0] + string(rune('0'+i))
	}
	return "10"
}
