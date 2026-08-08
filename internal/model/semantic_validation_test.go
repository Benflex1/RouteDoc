package model

import "testing"

func TestSemanticStringsRejectSourceMaterialByFieldGrammar(t *testing.T) {
	for _, value := range []string{
		"https://user:password@example.test/path?q=secret",
		"Authorization: Bearer secret",
		"Cookie: session=secret",
		"-----BEGIN CERTIFICATE-----",
		"/raw/private/path",
	} {
		t.Run(value, func(t *testing.T) {
			r := minimalEvidence()
			r.Target.Hostname = value
			if _, issues := ValidateEvidenceRun(r); !hasCode(issues, CodeSensitiveDisallowedField) {
				t.Fatalf("source-shaped target hostname accepted: %v", issues)
			}
		})
	}
}

func TestSemanticStringFieldsUseTheirOwnNarrowContracts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*EvidenceRun)
	}{
		{name: "entity hostname", mutate: func(r *EvidenceRun) {
			r.Entities = []Entity{{EntityID: "entity-hostname", Kind: EntityHostname, DisplayLabel: "hostname", Identity: EntityIdentity{Kind: EntityHostname, Hostname: &HostnameIdentity{Hostname: "https://example.test/path"}}}}
		}},
		{name: "reason code", mutate: func(r *EvidenceRun) {
			r.Capabilities = []Capability{{CapabilityID: "capability-000001", Kind: CapabilityHTTPProbe, State: CapabilityAvailable, ReasonCode: "Authorization: Bearer secret"}}
		}},
		{name: "fingerprint", mutate: func(r *EvidenceRun) {
			r.Entities = []Entity{{EntityID: "entity-peer", Kind: EntityTLSPeer, DisplayLabel: "TLS peer", Identity: EntityIdentity{Kind: EntityTLSPeer, TLSPeer: &TLSPeerIdentity{Fingerprint: "sha256:synthetic"}}}}
		}},
		{name: "synthetic identifier", mutate: func(r *EvidenceRun) {
			r.Entities = []Entity{{EntityID: "entity-proxy", Kind: EntityProxyInstance, DisplayLabel: "proxy", Identity: EntityIdentity{Kind: EntityProxyInstance, Opaque: &OpaqueEntityIdentity{SyntheticID: "/raw/private/path"}}}}
		}},
		{name: "display label", mutate: func(r *EvidenceRun) {
			r.Entities = []Entity{{EntityID: "entity-proxy", Kind: EntityProxyInstance, DisplayLabel: "Authorization: Bearer secret", Identity: EntityIdentity{Kind: EntityProxyInstance, Opaque: &OpaqueEntityIdentity{SyntheticID: "proxy-1"}}}}
		}},
		{name: "container runtime identifier", mutate: func(r *EvidenceRun) {
			r.Entities = []Entity{{EntityID: "entity-container", Kind: EntityContainer, DisplayLabel: "container", Identity: EntityIdentity{Kind: EntityContainer, Container: &ContainerIdentity{RuntimeID: "https://user:password@example.test/path", ContainerID: "container-1"}}}}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := minimalEvidence()
			tc.mutate(&r)
			if _, issues := ValidateEvidenceRun(r); !hasCode(issues, CodeSensitiveDisallowedField) {
				t.Fatalf("narrow semantic field accepted source-shaped value: %v", issues)
			}
		})
	}
}

func TestSemanticStringFieldsKeepLegitimateNormalizedValues(t *testing.T) {
	r := minimalEvidence()
	r.Target.Hostname = "example.test"
	r.Entities = []Entity{
		{EntityID: "entity-peer", Kind: EntityTLSPeer, DisplayLabel: "TLS peer", Identity: EntityIdentity{Kind: EntityTLSPeer, TLSPeer: &TLSPeerIdentity{Fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000001"}}},
		{EntityID: "entity-container", Kind: EntityContainer, DisplayLabel: "container", Identity: EntityIdentity{Kind: EntityContainer, Container: &ContainerIdentity{RuntimeID: "docker-runtime-1", ContainerID: "container-1"}}},
	}
	r.Capabilities = []Capability{{CapabilityID: "capability-000001", Kind: CapabilityHTTPProbe, State: CapabilityAvailable, ReasonCode: "ok"}}
	if _, issues := ValidateEvidenceRun(r); len(issues) != 0 {
		t.Fatalf("legitimate sanitized values rejected: %v", issues)
	}
}
