package model

import "net/netip"

type Entity struct {
	EntityID     EntityID
	Kind         EntityKind
	DisplayLabel string
	Identity     EntityIdentity
}
type EntityIdentity struct {
	Kind         EntityKind
	URLTarget    *URLTargetIdentity
	Hostname     *HostnameIdentity
	IPAddress    *IPAddressIdentity
	Endpoint     *EndpointIdentity
	TLSPeer      *TLSPeerIdentity
	HTTPExchange *HTTPExchangeIdentity
	Opaque       *OpaqueEntityIdentity
	Listener     *ListenerIdentity
	Process      *ProcessIdentity
	Container    *ContainerIdentity
	Namespace    *NamespaceIdentity
}
type URLTargetIdentity struct{ Marker bool }
type HostnameIdentity struct{ Hostname string }
type IPAddressIdentity struct{ Address netip.Addr }
type EndpointIdentity struct {
	Address   netip.Addr
	Port      uint16
	Transport Transport
}
type TLSPeerIdentity struct{ Fingerprint string }
type HTTPExchangeIdentity struct{ Ordinal uint64 }
type OpaqueEntityIdentity struct{ SyntheticID string }
type ListenerIdentity struct{ Endpoint EndpointIdentity }
type ProcessIdentity struct{ PID uint64 }
type ContainerIdentity struct{ RuntimeID, ContainerID string }
type NamespaceIdentity struct{ NamespaceInode uint64 }
