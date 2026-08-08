package model

import "time"

type Observation struct {
	ObservationID     ObservationID
	Kind              ObservationKind
	SubjectEntityIDs  []EntityID
	VantageID         *VantageID
	ObservedAt        time.Time
	Payload           ObservationPayload
	AcquisitionMethod AcquisitionMethod
	SourceComponent   SourceComponent
	Sensitivity       Sensitivity
	Limitations       []Limitation
}
type Sensitivity string

const (
	SensitivityPublic           Sensitivity = "PUBLIC"
	SensitivitySanitizedDerived Sensitivity = "SANITIZED_DERIVED"
)

func (v Sensitivity) Valid() bool { return v == SensitivityPublic || v == SensitivitySanitizedDerived }

type ObservationPayload struct {
	Kind                    ObservationKind
	Resolution              *SystemResolutionResult
	TCP                     *TCPConnectionResult
	TLSTransport            *TLSTransportResultPayload
	TLSPeer                 *TLSPeerSummary
	CertificateVerification *CertificateVerificationResultPayload
	HTTP                    *HTTPResult
	ActiveProxyRoute        *ProxyRouteSummary
	ConfiguredProxyRoute    *ProxyRouteSummary
	UpstreamSelection       *UpstreamSelectionSummary
	Listener                *ListenerInventoryEntry
	ListenerInventoryResult *ListenerInventoryResult
	ProcessOwnership        *ProcessOwnershipEntry
	Docker                  *DockerRuntimeSummary
	Capability              *CapabilityPermissionResult
}
type SystemResolutionResult struct {
	HostnameEntityID EntityID
	AddressEntityID  *EntityID
	AddressFamily    AddressFamily
	Result           ResolutionResult
}
type TCPConnectionResult struct {
	EndpointEntityID                EntityID
	Result                          TCPResult
	DurationNS                      int64
	DeadlinePartOfExpectedCondition bool
}
type TLSTransportResultPayload struct {
	PeerEntityID                                          EntityID
	Result                                                TLSTransportResult
	ProtocolVersion, CipherSuite, NegotiatedALPN, SNISent string
	AlertCode                                             *uint16
	DurationNS                                            int64
}
type TLSPeerSummary struct {
	PeerEntityID        EntityID
	CertificateCount    uint64
	LeafSHA256          string
	NotBefore, NotAfter time.Time
	SANType             SANType
	SANCount            uint64
}
type CertificateVerificationResultPayload struct {
	PeerEntityID     EntityID
	VerifiedHostname string
	VerificationTime time.Time
	TrustSource      TrustSource
	Result           CertificateVerificationResult
	FailureReason    *CertificateVerificationResult
}
type HTTPResult struct {
	ExchangeEntityID       EntityID
	ResultKind             HTTPResultKind
	StatusCode             uint16
	RedirectTargetEntityID *EntityID
	RedirectTarget         *Target
}
type ProxyRouteSummary struct {
	ProxyRouteEntityID EntityID
	UpstreamEntityID   *EntityID
	MatcherKind        string
	MatchResult        MatcherResult
}
type UpstreamSelectionSummary struct {
	ProxyRouteEntityID EntityID
	UpstreamEntityID   *EntityID
	Result             UpstreamResult
}
type ListenerInventoryEntry struct {
	ListenerEntityID  EntityID
	NamespaceEntityID EntityID
	Protocol          Transport
	AddressFamily     AddressFamily
	BindSemantics     BindSemantics
	Port              uint16
}
type ListenerInventoryResult struct {
	NamespaceEntityID     EntityID
	Protocol              Transport
	AddressFamily         AddressFamily
	BindSemantics         BindSemantics
	PortStart             uint16
	PortEnd               uint16
	MatchingListenerCount uint64
}
type ProcessOwnershipEntry struct {
	ListenerEntityID EntityID
	ProcessEntityID  *EntityID
	Result           OwnershipResult
}
type DockerRuntimeSummary struct {
	FactKind          DockerFactKind
	ContainerEntityID EntityID
	NamespaceEntityID *EntityID
	EndpointEntityID  *EntityID
	RuntimeState      RuntimeState
}
type CapabilityPermissionResult struct {
	CapabilityID CapabilityID
	Result       CapabilityState
	ReasonCode   string
}
