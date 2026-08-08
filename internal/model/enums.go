package model

type VantageKind string

const (
	VantageKindClientNetwork      VantageKind = "CLIENT_NETWORK"
	VantageKindHostNamespace      VantageKind = "HOST_NAMESPACE"
	VantageKindContainerNamespace VantageKind = "CONTAINER_NAMESPACE"
	VantageKindUnknownNamespace   VantageKind = "UNKNOWN_NAMESPACE"
)

func (v VantageKind) Valid() bool {
	switch v {
	case VantageKindClientNetwork, VantageKindHostNamespace, VantageKindContainerNamespace, VantageKindUnknownNamespace:
		return true
	}
	return false
}

type VantageRole string

const (
	VantageRoleClient      VantageRole = "CLIENT"
	VantageRoleOriginHost  VantageRole = "ORIGIN_HOST"
	VantageRoleProxy       VantageRole = "PROXY"
	VantageRoleUpstream    VantageRole = "UPSTREAM"
	VantageRoleUnspecified VantageRole = "UNSPECIFIED"
)

func (v VantageRole) Valid() bool {
	switch v {
	case VantageRoleClient, VantageRoleOriginHost, VantageRoleProxy, VantageRoleUpstream, VantageRoleUnspecified:
		return true
	}
	return false
}

type VantageEstablishment string

const (
	VantageDirectlyObserved  VantageEstablishment = "DIRECTLY_OBSERVED"
	VantageOperatorSupplied  VantageEstablishment = "OPERATOR_SUPPLIED"
	VantageRuntimeCorrelated VantageEstablishment = "RUNTIME_CORRELATED"
	VantageIdentityUnknown   VantageEstablishment = "UNKNOWN"
)

func (v VantageEstablishment) Valid() bool {
	switch v {
	case VantageDirectlyObserved, VantageOperatorSupplied, VantageRuntimeCorrelated, VantageIdentityUnknown:
		return true
	}
	return false
}

type AssertionKind string

const (
	AssertionLocalOriginParticipation         AssertionKind = "LOCAL_ORIGIN_PARTICIPATION"
	AssertionExpectedPathEdge                 AssertionKind = "EXPECTED_PATH_EDGE"
	AssertionHTTPExpectation                  AssertionKind = "HTTP_EXPECTATION"
	AssertionConfigSourceSelection            AssertionKind = "CONFIG_SOURCE_SELECTION"
	AssertionPrivateRedirectTransitionAllowed AssertionKind = "PRIVATE_REDIRECT_TRANSITION_ALLOWED"
)

func (v AssertionKind) Valid() bool {
	switch v {
	case AssertionLocalOriginParticipation, AssertionExpectedPathEdge, AssertionHTTPExpectation, AssertionConfigSourceSelection, AssertionPrivateRedirectTransitionAllowed:
		return true
	}
	return false
}

type AssertionSource string

const (
	AssertionSourceCommandLine      AssertionSource = "COMMAND_LINE"
	AssertionSourceExplicitConfig   AssertionSource = "EXPLICIT_CONFIG"
	AssertionSourceSyntheticFixture AssertionSource = "SYNTHETIC_FIXTURE"
)

func (v AssertionSource) Valid() bool {
	switch v {
	case AssertionSourceCommandLine, AssertionSourceExplicitConfig, AssertionSourceSyntheticFixture:
		return true
	}
	return false
}

type ExpectationKind string

const (
	ExpectationStatusRange   ExpectationKind = "STATUS_RANGE"
	ExpectationHeaderPresent ExpectationKind = "HEADER_PRESENT"
)

func (v ExpectationKind) Valid() bool {
	return v == ExpectationStatusRange || v == ExpectationHeaderPresent
}

type ComponentKind string

const (
	ComponentCaddy  ComponentKind = "CADDY"
	ComponentDocker ComponentKind = "DOCKER"
)

func (v ComponentKind) Valid() bool { return v == ComponentCaddy || v == ComponentDocker }

type ConfigSourceKind string

const (
	SourceActiveAPI      ConfigSourceKind = "ACTIVE_API"
	SourceExplicitFile   ConfigSourceKind = "EXPLICIT_FILE"
	SourceEngineEndpoint ConfigSourceKind = "ENGINE_ENDPOINT"
)

func (v ConfigSourceKind) Valid() bool {
	return v == SourceActiveAPI || v == SourceExplicitFile || v == SourceEngineEndpoint
}

type EntityKind string

const (
	EntityURLTarget        EntityKind = "URL_TARGET"
	EntityHostname         EntityKind = "HOSTNAME"
	EntityIPAddress        EntityKind = "IP_ADDRESS"
	EntitySocketEndpoint   EntityKind = "SOCKET_ENDPOINT"
	EntityTLSPeer          EntityKind = "TLS_PEER"
	EntityHTTPExchange     EntityKind = "HTTP_EXCHANGE"
	EntityProxyInstance    EntityKind = "PROXY_INSTANCE"
	EntityProxyRoute       EntityKind = "PROXY_ROUTE"
	EntityUpstreamEndpoint EntityKind = "UPSTREAM_ENDPOINT"
	EntityListener         EntityKind = "LISTENER"
	EntityProcess          EntityKind = "PROCESS"
	EntityContainer        EntityKind = "CONTAINER"
	EntityNetworkNamespace EntityKind = "NETWORK_NAMESPACE"
)

func (v EntityKind) Valid() bool {
	switch v {
	case EntityURLTarget, EntityHostname, EntityIPAddress, EntitySocketEndpoint, EntityTLSPeer, EntityHTTPExchange, EntityProxyInstance, EntityProxyRoute, EntityUpstreamEndpoint, EntityListener, EntityProcess, EntityContainer, EntityNetworkNamespace:
		return true
	}
	return false
}

type ScopeKind string

const (
	ScopeClientOnly  ScopeKind = "CLIENT_ONLY"
	ScopeLocalOrigin ScopeKind = "LOCAL_ORIGIN"
)

func (v ScopeKind) Valid() bool { return v == ScopeClientOnly || v == ScopeLocalOrigin }

type GoalKind string

const (
	GoalHTTPResponse        GoalKind = "HTTP_RESPONSE"
	GoalHTTPExpectation     GoalKind = "HTTP_EXPECTATION"
	GoalOriginPathDiagnosis GoalKind = "ORIGIN_PATH_DIAGNOSIS"
)

func (v GoalKind) Valid() bool {
	return v == GoalHTTPResponse || v == GoalHTTPExpectation || v == GoalOriginPathDiagnosis
}

type PathProvenance string

const (
	ProvenanceOperatorAsserted    PathProvenance = "OPERATOR_ASSERTED"
	ProvenanceDirectlyObserved    PathProvenance = "DIRECTLY_OBSERVED"
	ProvenanceActiveRuntimeConfig PathProvenance = "ACTIVE_RUNTIME_CONFIG"
	ProvenanceConfiguredIntent    PathProvenance = "CONFIGURED_INTENT"
)

func (v PathProvenance) Valid() bool {
	switch v {
	case ProvenanceOperatorAsserted, ProvenanceDirectlyObserved, ProvenanceActiveRuntimeConfig, ProvenanceConfiguredIntent:
		return true
	}
	return false
}

type PathRelation string

const (
	RelationResolvesTo        PathRelation = "RESOLVES_TO"
	RelationConnectsTo        PathRelation = "CONNECTS_TO"
	RelationNegotiatesTLSWith PathRelation = "NEGOTIATES_TLS_WITH"
	RelationVerifies          PathRelation = "VERIFIES"
	RelationRequestsHTTPFrom  PathRelation = "REQUESTS_HTTP_FROM"
	RelationRedirectsTo       PathRelation = "REDIRECTS_TO"
	RelationRoutesTo          PathRelation = "ROUTES_TO"
	RelationSelectsUpstream   PathRelation = "SELECTS_UPSTREAM"
	RelationListensOn         PathRelation = "LISTENS_ON"
	RelationOwnedBy           PathRelation = "OWNED_BY"
	RelationAssociatedWith    PathRelation = "ASSOCIATED_WITH"
)

func (v PathRelation) Valid() bool {
	switch v {
	case RelationResolvesTo, RelationConnectsTo, RelationNegotiatesTLSWith, RelationVerifies, RelationRequestsHTTPFrom, RelationRedirectsTo, RelationRoutesTo, RelationSelectsUpstream, RelationListensOn, RelationOwnedBy, RelationAssociatedWith:
		return true
	}
	return false
}

type CheckLifecycle string

const (
	CheckNotRun      CheckLifecycle = "NOT_RUN"
	CheckCompleted   CheckLifecycle = "COMPLETED"
	CheckUnavailable CheckLifecycle = "UNAVAILABLE"
	CheckDenied      CheckLifecycle = "DENIED"
	CheckTimedOut    CheckLifecycle = "TIMED_OUT"
	CheckError       CheckLifecycle = "ERROR"
)

func (v CheckLifecycle) Valid() bool {
	switch v {
	case CheckNotRun, CheckCompleted, CheckUnavailable, CheckDenied, CheckTimedOut, CheckError:
		return true
	}
	return false
}

type CheckVerdict string

const (
	CheckPass    CheckVerdict = "PASS"
	CheckFail    CheckVerdict = "FAIL"
	CheckUnknown CheckVerdict = "UNKNOWN"
	CheckSkipped CheckVerdict = "SKIPPED"
)

func (v CheckVerdict) Valid() bool {
	return v == CheckPass || v == CheckFail || v == CheckUnknown || v == CheckSkipped
}

type EvidenceKind string

const (
	EvidenceKindObservation EvidenceKind = "OBSERVATION"
	EvidenceKindClaim       EvidenceKind = "CLAIM"
	EvidenceKindVisibility  EvidenceKind = "VISIBILITY"
	EvidenceKindAssertion   EvidenceKind = "ASSERTION"
)

func (v EvidenceKind) Valid() bool {
	return v == EvidenceKindObservation || v == EvidenceKindClaim || v == EvidenceKindVisibility || v == EvidenceKindAssertion
}

type ClaimLevel string

const (
	ClaimLevelObserved  ClaimLevel = "OBSERVED"
	ClaimLevelInferred  ClaimLevel = "INFERRED"
	ClaimLevelSuspected ClaimLevel = "SUSPECTED"
)

func (v ClaimLevel) Valid() bool {
	return v == ClaimLevelObserved || v == ClaimLevelInferred || v == ClaimLevelSuspected
}

type FindingKind string

const (
	FindingBlocker             FindingKind = "BLOCKER"
	FindingExpectationFailure  FindingKind = "EXPECTATION_FAILURE"
	FindingPartialReachability FindingKind = "PARTIAL_REACHABILITY"
	FindingAdvisory            FindingKind = "ADVISORY"
	FindingLimitation          FindingKind = "LIMITATION"
)

func (v FindingKind) Valid() bool {
	return v == FindingBlocker || v == FindingExpectationFailure || v == FindingPartialReachability || v == FindingAdvisory || v == FindingLimitation
}

type Selection string

const (
	SelectionGlobalPrimary Selection = "GLOBAL_PRIMARY"
	SelectionBranchPrimary Selection = "BRANCH_PRIMARY"
	SelectionAdditional    Selection = "ADDITIONAL"
	SelectionNone          Selection = "NONE"
)

func (v Selection) Valid() bool {
	return v == SelectionGlobalPrimary || v == SelectionBranchPrimary || v == SelectionAdditional || v == SelectionNone
}

type ObservationKind string

const (
	ObservationSystemResolution        ObservationKind = "SYSTEM_RESOLUTION_RESULT"
	ObservationTCPConnection           ObservationKind = "TCP_CONNECTION_RESULT"
	ObservationTLSTransport            ObservationKind = "TLS_TRANSPORT_RESULT"
	ObservationTLSPeer                 ObservationKind = "TLS_PEER_SUMMARY"
	ObservationCertificateVerification ObservationKind = "CERTIFICATE_VERIFICATION_RESULT"
	ObservationHTTP                    ObservationKind = "HTTP_RESULT"
	ObservationActiveProxyRoute        ObservationKind = "ACTIVE_PROXY_ROUTE_SUMMARY"
	ObservationConfiguredProxyRoute    ObservationKind = "CONFIGURED_PROXY_ROUTE_SUMMARY"
	ObservationUpstreamSelection       ObservationKind = "UPSTREAM_SELECTION_SUMMARY"
	ObservationListenerInventory       ObservationKind = "LISTENER_INVENTORY_ENTRY"
	ObservationProcessOwnership        ObservationKind = "PROCESS_OWNERSHIP_ENTRY"
	ObservationDockerRuntime           ObservationKind = "DOCKER_RUNTIME_SUMMARY"
	ObservationCapabilityPermission    ObservationKind = "CAPABILITY_PERMISSION_RESULT"
)

func (v ObservationKind) Valid() bool {
	switch v {
	case ObservationSystemResolution, ObservationTCPConnection, ObservationTLSTransport, ObservationTLSPeer, ObservationCertificateVerification, ObservationHTTP, ObservationActiveProxyRoute, ObservationConfiguredProxyRoute, ObservationUpstreamSelection, ObservationListenerInventory, ObservationProcessOwnership, ObservationDockerRuntime, ObservationCapabilityPermission:
		return true
	}
	return false
}

type AddressFamily string

const (
	AddressFamilyIPv4 AddressFamily = "IPV4"
	AddressFamilyIPv6 AddressFamily = "IPV6"
)

func (v AddressFamily) Valid() bool { return v == AddressFamilyIPv4 || v == AddressFamilyIPv6 }

type ResolutionResult string

const (
	ResolutionResolved ResolutionResult = "RESOLVED"
	ResolutionNoResult ResolutionResult = "NO_RESULT"
	ResolutionFailed   ResolutionResult = "FAILED"
)

func (v ResolutionResult) Valid() bool {
	return v == ResolutionResolved || v == ResolutionNoResult || v == ResolutionFailed
}

type TCPResult string

const (
	TCPAccepted TCPResult = "ACCEPTED"
	TCPRefused  TCPResult = "REFUSED"
	TCPTimedOut TCPResult = "TIMED_OUT"
	TCPFailed   TCPResult = "FAILED"
)

func (v TCPResult) Valid() bool {
	return v == TCPAccepted || v == TCPRefused || v == TCPTimedOut || v == TCPFailed
}

type TLSTransportResult string

const (
	TLSTransportCompleted TLSTransportResult = "COMPLETED"
	TLSTransportFailed    TLSTransportResult = "FAILED"
	TLSTransportTimedOut  TLSTransportResult = "TIMED_OUT"
)

func (v TLSTransportResult) Valid() bool {
	return v == TLSTransportCompleted || v == TLSTransportFailed || v == TLSTransportTimedOut
}

type CertificateVerificationResult string

const (
	CertVerified            CertificateVerificationResult = "VERIFIED"
	CertHostnameMismatch    CertificateVerificationResult = "HOSTNAME_MISMATCH"
	CertExpired             CertificateVerificationResult = "EXPIRED"
	CertNotYetValid         CertificateVerificationResult = "NOT_YET_VALID"
	CertUntrustedIssuer     CertificateVerificationResult = "UNTRUSTED_ISSUER"
	CertInvalidUsage        CertificateVerificationResult = "INVALID_USAGE"
	CertVerifierUnavailable CertificateVerificationResult = "VERIFIER_UNAVAILABLE"
)

func (v CertificateVerificationResult) Valid() bool {
	switch v {
	case CertVerified, CertHostnameMismatch, CertExpired, CertNotYetValid, CertUntrustedIssuer, CertInvalidUsage, CertVerifierUnavailable:
		return true
	}
	return false
}

type HTTPResultKind string

const (
	HTTPResponse HTTPResultKind = "RESPONSE"
	HTTPRedirect HTTPResultKind = "REDIRECT"
)

func (v HTTPResultKind) Valid() bool { return v == HTTPResponse || v == HTTPRedirect }

type MatcherResult string

const (
	MatcherMatched    MatcherResult = "MATCHED"
	MatcherNotMatched MatcherResult = "NOT_MATCHED"
	MatcherUnknown    MatcherResult = "UNKNOWN"
)

func (v MatcherResult) Valid() bool {
	return v == MatcherMatched || v == MatcherNotMatched || v == MatcherUnknown
}

type UpstreamResult string

const (
	UpstreamSelected    UpstreamResult = "SELECTED"
	UpstreamAmbiguous   UpstreamResult = "AMBIGUOUS"
	UpstreamUnavailable UpstreamResult = "UNAVAILABLE"
)

func (v UpstreamResult) Valid() bool {
	return v == UpstreamSelected || v == UpstreamAmbiguous || v == UpstreamUnavailable
}

type OwnershipResult string

const (
	OwnershipOwned      OwnershipResult = "OWNED"
	OwnershipUnresolved OwnershipResult = "UNRESOLVED"
)

func (v OwnershipResult) Valid() bool { return v == OwnershipOwned || v == OwnershipUnresolved }

type DockerFactKind string

const (
	DockerContainerState    DockerFactKind = "CONTAINER_STATE"
	DockerNetworkMembership DockerFactKind = "NETWORK_MEMBERSHIP"
	DockerPublishedPort     DockerFactKind = "PUBLISHED_PORT"
)

func (v DockerFactKind) Valid() bool {
	return v == DockerContainerState || v == DockerNetworkMembership || v == DockerPublishedPort
}

type RuntimeState string

const (
	RuntimeRunning RuntimeState = "RUNNING"
	RuntimeStopped RuntimeState = "STOPPED"
	RuntimeUnknown RuntimeState = "UNKNOWN"
)

func (v RuntimeState) Valid() bool {
	return v == RuntimeRunning || v == RuntimeStopped || v == RuntimeUnknown
}

type CapabilityState string

const (
	CapabilityAvailable   CapabilityState = "AVAILABLE"
	CapabilityUnavailable CapabilityState = "UNAVAILABLE"
	CapabilityDenied      CapabilityState = "DENIED"
	CapabilityUnknown     CapabilityState = "UNKNOWN"
)

func (v CapabilityState) Valid() bool {
	return v == CapabilityAvailable || v == CapabilityUnavailable || v == CapabilityDenied || v == CapabilityUnknown
}

type Transport string

const (
	TransportTCP Transport = "TCP"
	TransportUDP Transport = "UDP"
)

func (v Transport) Valid() bool { return v == TransportTCP || v == TransportUDP }

type BindSemantics string

const (
	BindExact    BindSemantics = "EXACT"
	BindWildcard BindSemantics = "WILDCARD"
	BindLoopback BindSemantics = "LOOPBACK"
)

func (v BindSemantics) Valid() bool { return v == BindExact || v == BindWildcard || v == BindLoopback }

type SANType string

const (
	SANDNS   SANType = "DNS"
	SANIP    SANType = "IP"
	SANOther SANType = "OTHER"
)

func (v SANType) Valid() bool { return v == SANDNS || v == SANIP || v == SANOther }

type TrustSource string

const (
	TrustSystem   TrustSource = "SYSTEM"
	TrustExplicit TrustSource = "EXPLICIT"
	TrustUnknown  TrustSource = "UNKNOWN"
)

func (v TrustSource) Valid() bool { return v == TrustSystem || v == TrustExplicit || v == TrustUnknown }

type AcquisitionMethod string

const (
	AcquisitionDirectProbe            AcquisitionMethod = "DIRECT_PROBE"
	AcquisitionActiveRuntimeAPI       AcquisitionMethod = "ACTIVE_RUNTIME_API"
	AcquisitionConfiguredIntentSource AcquisitionMethod = "CONFIGURED_INTENT_SOURCE"
	AcquisitionSystemInspection       AcquisitionMethod = "SYSTEM_INSPECTION"
	AcquisitionSyntheticFixture       AcquisitionMethod = "SYNTHETIC_FIXTURE"
)

func (v AcquisitionMethod) Valid() bool {
	switch v {
	case AcquisitionDirectProbe, AcquisitionActiveRuntimeAPI, AcquisitionConfiguredIntentSource, AcquisitionSystemInspection, AcquisitionSyntheticFixture:
		return true
	}
	return false
}

type SourceComponent string

const (
	SourceSystemResolver      SourceComponent = "SYSTEM_RESOLVER"
	SourceTCPProbe            SourceComponent = "TCP_PROBE"
	SourceTLSProbe            SourceComponent = "TLS_PROBE"
	SourceCertificateVerifier SourceComponent = "CERTIFICATE_VERIFIER"
	SourceHTTPProbe           SourceComponent = "HTTP_PROBE"
	SourceCaddyAdapter        SourceComponent = "CADDY_ADAPTER"
	SourceSocketInspector     SourceComponent = "SOCKET_INSPECTOR"
	SourceProcessInspector    SourceComponent = "PROCESS_INSPECTOR"
	SourceDockerAdapter       SourceComponent = "DOCKER_ADAPTER"
	SourceSyntheticFixture    SourceComponent = "SYNTHETIC_FIXTURE"
)

func (v SourceComponent) Valid() bool {
	switch v {
	case SourceSystemResolver, SourceTCPProbe, SourceTLSProbe, SourceCertificateVerifier, SourceHTTPProbe, SourceCaddyAdapter, SourceSocketInspector, SourceProcessInspector, SourceDockerAdapter, SourceSyntheticFixture:
		return true
	}
	return false
}

type CapabilityKind string

const (
	CapabilitySystemResolution  CapabilityKind = "SYSTEM_RESOLUTION"
	CapabilityTCPProbe          CapabilityKind = "TCP_PROBE"
	CapabilityTLSProbe          CapabilityKind = "TLS_PROBE"
	CapabilityHTTPProbe         CapabilityKind = "HTTP_PROBE"
	CapabilityListenerInventory CapabilityKind = "LISTENER_INVENTORY"
	CapabilityProcessOwnership  CapabilityKind = "PROCESS_OWNERSHIP"
	CapabilityActiveCaddy       CapabilityKind = "ACTIVE_CADDY"
	CapabilityConfiguredCaddy   CapabilityKind = "CONFIGURED_CADDY"
	CapabilityDocker            CapabilityKind = "DOCKER"
)

func (v CapabilityKind) Valid() bool {
	switch v {
	case CapabilitySystemResolution, CapabilityTCPProbe, CapabilityTLSProbe, CapabilityHTTPProbe, CapabilityListenerInventory, CapabilityProcessOwnership, CapabilityActiveCaddy, CapabilityConfiguredCaddy, CapabilityDocker:
		return true
	}
	return false
}

type LimitationCode string

const (
	LimitationInsufficientPrivilege LimitationCode = "insufficient_privilege"
	LimitationTLSUnverified         LimitationCode = "tls_peer_unverified"
	LimitationUnsupportedCapability LimitationCode = "unsupported_capability"
	LimitationUnknownVantage        LimitationCode = "unknown_vantage"
	LimitationPartialVisibility     LimitationCode = "partial_visibility"
	LimitationSkippedDependency     LimitationCode = "skipped_dependency"
	LimitationGeneric               LimitationCode = "generic"
)

func (v LimitationCode) Valid() bool {
	switch v {
	case LimitationInsufficientPrivilege, LimitationTLSUnverified, LimitationUnsupportedCapability, LimitationUnknownVantage, LimitationPartialVisibility, LimitationSkippedDependency, LimitationGeneric:
		return true
	}
	return false
}

type LimitationScopeKind string

const (
	LimitationRun         LimitationScopeKind = "RUN"
	LimitationVantage     LimitationScopeKind = "VANTAGE"
	LimitationObservation LimitationScopeKind = "OBSERVATION"
	LimitationVisibility  LimitationScopeKind = "VISIBILITY"
	LimitationFinding     LimitationScopeKind = "FINDING"
)

func (v LimitationScopeKind) Valid() bool {
	return v == LimitationRun || v == LimitationVantage || v == LimitationObservation || v == LimitationVisibility || v == LimitationFinding
}

type VisibilitySubjectKind string

const VisibilitySubjectListener VisibilitySubjectKind = "LISTENER"

func (v VisibilitySubjectKind) Valid() bool { return v == VisibilitySubjectListener }

type VisibilityLevel string

const (
	VisibilityCompleteForScope VisibilityLevel = "COMPLETE_FOR_SCOPE"
	VisibilityPartial          VisibilityLevel = "PARTIAL"
	VisibilityUnknown          VisibilityLevel = "UNKNOWN"
	VisibilityNotApplicable    VisibilityLevel = "NOT_APPLICABLE"
)

func (v VisibilityLevel) Valid() bool {
	return v == VisibilityCompleteForScope || v == VisibilityPartial || v == VisibilityUnknown || v == VisibilityNotApplicable
}

type CheckKind string

const (
	CheckSystemResolution        CheckKind = "SYSTEM_RESOLUTION"
	CheckTCPConnection           CheckKind = "TCP_CONNECTION"
	CheckTLSTransport            CheckKind = "TLS_TRANSPORT"
	CheckTLSPeer                 CheckKind = "TLS_PEER"
	CheckCertificateVerification CheckKind = "CERTIFICATE_VERIFICATION"
	CheckHTTP                    CheckKind = "HTTP"
	CheckActiveProxyRoute        CheckKind = "ACTIVE_PROXY_ROUTE"
	CheckConfiguredProxyRoute    CheckKind = "CONFIGURED_PROXY_ROUTE"
	CheckUpstreamSelection       CheckKind = "UPSTREAM_SELECTION"
	CheckListenerInventory       CheckKind = "LISTENER_INVENTORY"
	CheckProcessOwnership        CheckKind = "PROCESS_OWNERSHIP"
	CheckDockerRuntime           CheckKind = "DOCKER_RUNTIME"
	CheckCapabilityPermission    CheckKind = "CAPABILITY_PERMISSION"
)

func (v CheckKind) Valid() bool {
	switch v {
	case CheckSystemResolution, CheckTCPConnection, CheckTLSTransport, CheckTLSPeer, CheckCertificateVerification, CheckHTTP, CheckActiveProxyRoute, CheckConfiguredProxyRoute, CheckUpstreamSelection, CheckListenerInventory, CheckProcessOwnership, CheckDockerRuntime, CheckCapabilityPermission:
		return true
	}
	return false
}

type ClaimStatementCode string

const (
	StatementTLSCertificateHostnameMismatch ClaimStatementCode = "TLS_CERTIFICATE_HOSTNAME_MISMATCH"
	StatementTCPConnectionRefused           ClaimStatementCode = "TCP_CONNECTION_REFUSED"
	StatementNoMatchingListenerVisible      ClaimStatementCode = "NO_MATCHING_LISTENER_VISIBLE"
)

func (v ClaimStatementCode) Valid() bool {
	return v == StatementTLSCertificateHostnameMismatch || v == StatementTCPConnectionRefused || v == StatementNoMatchingListenerVisible
}

type FindingTitleCode string

const (
	TitleTLSCertificateHostnameMismatch FindingTitleCode = "TLS_CERTIFICATE_HOSTNAME_MISMATCH"
	TitleTCPConnectionRefused           FindingTitleCode = "TCP_CONNECTION_REFUSED"
	TitleNoMatchingListenerVisible      FindingTitleCode = "NO_MATCHING_LISTENER_VISIBLE"
)

func (v FindingTitleCode) Valid() bool {
	return v == TitleTLSCertificateHostnameMismatch || v == TitleTCPConnectionRefused || v == TitleNoMatchingListenerVisible
}

type MissingEvidenceKind string

const (
	MissingObservationRequired MissingEvidenceKind = "OBSERVATION_REQUIRED"
	MissingVisibilityRequired  MissingEvidenceKind = "VISIBILITY_REQUIRED"
	MissingVantageRequired     MissingEvidenceKind = "VANTAGE_REQUIRED"
)

func (v MissingEvidenceKind) Valid() bool {
	return v == MissingObservationRequired || v == MissingVisibilityRequired || v == MissingVantageRequired
}

type CheckInputKind string

const (
	CheckInputSubject       CheckInputKind = "SUBJECT"
	CheckInputNetwork       CheckInputKind = "NETWORK"
	CheckInputWithAssertion CheckInputKind = "WITH_ASSERTION"
)

func (v CheckInputKind) Valid() bool {
	return v == CheckInputSubject || v == CheckInputNetwork || v == CheckInputWithAssertion
}

type ExpectedConditionKind string

const (
	ExpectedResult          ExpectedConditionKind = "RESULT"
	ExpectedFamily          ExpectedConditionKind = "FAMILY"
	ExpectedPort            ExpectedConditionKind = "PORT"
	ExpectedHostname        ExpectedConditionKind = "HOSTNAME"
	ExpectedStatusRange     ExpectedConditionKind = "STATUS_RANGE"
	ExpectedMatcherResult   ExpectedConditionKind = "MATCHER_RESULT"
	ExpectedCapabilityState ExpectedConditionKind = "CAPABILITY_STATE"
)

func (v ExpectedConditionKind) Valid() bool {
	switch v {
	case ExpectedResult, ExpectedFamily, ExpectedPort, ExpectedHostname, ExpectedStatusRange, ExpectedMatcherResult, ExpectedCapabilityState:
		return true
	}
	return false
}
