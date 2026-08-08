package v1

type wReport struct {
	ReportSchemaVersion   string             `json:"report_schema_version"`
	Producer              wProducer          `json:"producer"`
	RunID                 string             `json:"run_id"`
	Target                wTarget            `json:"target"`
	Goal                  wGoal              `json:"goal"`
	RequestedScope        wRequestedScope    `json:"requested_scope"`
	Policy                wPolicy            `json:"policy"`
	StartedAt             string             `json:"started_at"`
	FinishedAt            string             `json:"finished_at"`
	VantagePoints         []wVantage         `json:"vantage_points"`
	Capabilities          []wCapability      `json:"capabilities"`
	OperatorAssertions    []wAssertion       `json:"operator_assertions"`
	Entities              []wEntity          `json:"entities"`
	ServicePath           wServicePath       `json:"service_path"`
	CheckDefinitions      []wCheckDefinition `json:"check_definitions"`
	CheckExecutions       []wCheckExecution  `json:"check_executions"`
	Observations          []wObservation     `json:"observations"`
	VisibilityAssessments []wVisibility      `json:"visibility_assessments"`
	Evaluation            wEvaluation        `json:"evaluation"`
	Claims                []wClaim           `json:"claims"`
	Findings              []wFinding         `json:"findings"`
	Limitations           []wLimitation      `json:"limitations"`
}
type wProducer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Build   string `json:"build"`
}
type wTarget struct {
	Scheme        string       `json:"scheme"`
	Hostname      string       `json:"hostname"`
	EffectivePort uint16       `json:"effective_port"`
	Path          wPathSummary `json:"path"`
}
type wPathSummary struct {
	Present       bool   `json:"present"`
	IsRoot        bool   `json:"is_root"`
	SegmentCount  uint64 `json:"segment_count"`
	TrailingSlash bool   `json:"trailing_slash"`
	QueryPresent  bool   `json:"query_present"`
}
type wGoal struct {
	Kind                   string  `json:"kind"`
	ExpectationAssertionID *string `json:"expectation_assertion_id,omitempty"`
}
type wRequestedScope struct {
	Kind string `json:"kind"`
}
type wPolicy struct {
	CoherenceWindowNS int64 `json:"coherence_window_ns"`
}
type wLimitation struct {
	LimitationID string           `json:"limitation_id"`
	Code         string           `json:"code"`
	Scope        wLimitationScope `json:"scope"`
}
type wLimitationScope struct {
	Kind          string  `json:"kind"`
	VantageID     *string `json:"vantage_id,omitempty"`
	ObservationID *string `json:"observation_id,omitempty"`
	VisibilityID  *string `json:"visibility_id,omitempty"`
	FindingID     *string `json:"finding_id,omitempty"`
}
type wVantage struct {
	VantageID       string        `json:"vantage_id"`
	Kind            string        `json:"kind"`
	Role            string        `json:"role"`
	DisplayLabel    string        `json:"display_label"`
	Identity        wIdentity     `json:"identity"`
	ParentVantageID *string       `json:"parent_vantage_id,omitempty"`
	Establishment   string        `json:"establishment"`
	Limitations     []wLimitation `json:"limitations"`
}
type wIdentity struct {
	Kind           string `json:"kind"`
	Label          string `json:"label,omitempty"`
	NamespaceInode uint64 `json:"namespace_inode,omitempty"`
	DaemonID       string `json:"daemon_id,omitempty"`
	ContainerID    string `json:"container_id,omitempty"`
	ReasonCode     string `json:"reason_code,omitempty"`
}
type wCapability struct {
	CapabilityID string `json:"capability_id"`
	Kind         string `json:"kind"`
	State        string `json:"state"`
	ReasonCode   string `json:"reason_code"`
}
type wAssertion struct {
	AssertionID   string           `json:"assertion_id"`
	Kind          string           `json:"kind"`
	Parameters    wAssertionParams `json:"parameters"`
	EstablishedAt string           `json:"established_at"`
	Source        string           `json:"source"`
}
type wAssertionParams struct {
	Kind              string  `json:"kind"`
	URLTargetEntityID string  `json:"url_target_entity_id,omitempty"`
	HostVantageID     string  `json:"host_vantage_id,omitempty"`
	FromEntityID      string  `json:"from_entity_id,omitempty"`
	ToEntityID        string  `json:"to_entity_id,omitempty"`
	Relation          string  `json:"relation,omitempty"`
	ExpectationKind   string  `json:"expectation_kind,omitempty"`
	StatusMin         *uint16 `json:"status_min,omitempty"`
	StatusMax         *uint16 `json:"status_max,omitempty"`
	HeaderName        *string `json:"header_name,omitempty"`
	ComponentKind     string  `json:"component_kind,omitempty"`
	SourceKind        string  `json:"source_kind,omitempty"`
	FromAddressScope  string  `json:"from_address_scope,omitempty"`
	ToAddressScope    string  `json:"to_address_scope,omitempty"`
}
type wEntity struct {
	EntityID     string          `json:"entity_id"`
	Kind         string          `json:"kind"`
	DisplayLabel string          `json:"display_label"`
	Identity     wEntityIdentity `json:"identity"`
}
type wEndpoint struct {
	Address   string `json:"address"`
	Port      uint16 `json:"port"`
	Transport string `json:"transport"`
}
type wEntityIdentity struct {
	Kind           string     `json:"kind"`
	Marker         *bool      `json:"marker,omitempty"`
	Hostname       string     `json:"hostname,omitempty"`
	Address        string     `json:"address,omitempty"`
	Port           uint16     `json:"port,omitempty"`
	Transport      string     `json:"transport,omitempty"`
	Fingerprint    string     `json:"fingerprint,omitempty"`
	Ordinal        uint64     `json:"ordinal,omitempty"`
	SyntheticID    string     `json:"synthetic_id,omitempty"`
	Endpoint       *wEndpoint `json:"endpoint,omitempty"`
	PID            uint64     `json:"pid,omitempty"`
	RuntimeID      string     `json:"runtime_id,omitempty"`
	ContainerID    string     `json:"container_id,omitempty"`
	NamespaceInode uint64     `json:"namespace_inode,omitempty"`
}
type wServicePath struct {
	Nodes    []wNode   `json:"nodes"`
	Edges    []wEdge   `json:"edges"`
	Branches []wBranch `json:"branches"`
}
type wNode struct {
	EntityID string `json:"entity_id"`
}
type wEdge struct {
	EdgeID       string         `json:"edge_id"`
	From         string         `json:"from"`
	To           string         `json:"to"`
	Relation     string         `json:"relation"`
	Provenance   string         `json:"provenance"`
	EvidenceRefs []wEvidenceRef `json:"evidence_refs"`
}
type wBranch struct {
	BranchID       string   `json:"branch_id"`
	ParentBranchID *string  `json:"parent_branch_id,omitempty"`
	OrderedEdgeIDs []string `json:"ordered_edge_ids"`
	Goal           string   `json:"goal"`
}
type wEvidenceRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type wCheckDefinition struct {
	CheckID               string             `json:"check_id"`
	Kind                  string             `json:"kind"`
	Version               string             `json:"version"`
	Inputs                wCheckInputs       `json:"inputs"`
	DependencyCheckIDs    []string           `json:"dependency_check_ids"`
	RequiredCapabilityIDs []string           `json:"required_capability_ids"`
	ExecutionPolicy       wExecutionPolicy   `json:"execution_policy"`
	ExpectedCondition     wExpectedCondition `json:"expected_condition"`
}
type wCheckInputs struct {
	Kind            string  `json:"kind"`
	SubjectEntityID string  `json:"subject_entity_id"`
	VantageID       *string `json:"vantage_id,omitempty"`
	AssertionID     *string `json:"assertion_id,omitempty"`
}
type wExecutionPolicy struct {
	DeadlineNS                  int64  `json:"deadline_ns"`
	DependencyFailureReasonCode string `json:"dependency_failure_reason_code"`
	DeadlineIsExpectedCondition bool   `json:"deadline_is_expected_condition"`
}
type wExpectedCondition struct {
	Kind            string  `json:"kind"`
	Result          string  `json:"result,omitempty"`
	AddressFamily   *string `json:"address_family,omitempty"`
	Port            *uint16 `json:"port,omitempty"`
	Hostname        *string `json:"hostname,omitempty"`
	StatusMin       *uint16 `json:"status_min,omitempty"`
	StatusMax       *uint16 `json:"status_max,omitempty"`
	MatcherResult   *string `json:"matcher_result,omitempty"`
	CapabilityState *string `json:"capability_state,omitempty"`
}
type wCheckExecution struct {
	ExecutionID             string   `json:"execution_id"`
	CheckID                 string   `json:"check_id"`
	BranchID                *string  `json:"branch_id,omitempty"`
	VantageID               *string  `json:"vantage_id,omitempty"`
	StartedAt               *string  `json:"started_at,omitempty"`
	FinishedAt              *string  `json:"finished_at,omitempty"`
	Lifecycle               string   `json:"lifecycle"`
	Verdict                 string   `json:"verdict"`
	ReasonCode              *string  `json:"reason_code,omitempty"`
	ObservationIDs          []string `json:"observation_ids"`
	VisibilityAssessmentIDs []string `json:"visibility_assessment_ids"`
}
type wObservation struct {
	ObservationID     string        `json:"observation_id"`
	Kind              string        `json:"kind"`
	SubjectEntityIDs  []string      `json:"subject_entity_ids"`
	VantageID         *string       `json:"vantage_id,omitempty"`
	ObservedAt        string        `json:"observed_at"`
	Payload           wPayload      `json:"payload"`
	AcquisitionMethod string        `json:"acquisition_method"`
	SourceComponent   string        `json:"source_component"`
	Sensitivity       string        `json:"sensitivity"`
	Limitations       []wLimitation `json:"limitations"`
}
type wPayload struct {
	Kind                            string   `json:"kind"`
	HostnameEntityID                string   `json:"hostname_entity_id,omitempty"`
	AddressEntityID                 *string  `json:"address_entity_id,omitempty"`
	AddressFamily                   string   `json:"address_family,omitempty"`
	Result                          string   `json:"result,omitempty"`
	EndpointEntityID                string   `json:"endpoint_entity_id,omitempty"`
	DurationNS                      int64    `json:"duration_ns,omitempty"`
	DeadlinePartOfExpectedCondition bool     `json:"deadline_part_of_expected_condition,omitempty"`
	PeerEntityID                    string   `json:"peer_entity_id,omitempty"`
	ProtocolVersion                 string   `json:"protocol_version,omitempty"`
	CipherSuite                     string   `json:"cipher_suite,omitempty"`
	NegotiatedALPN                  string   `json:"negotiated_alpn,omitempty"`
	SNISent                         string   `json:"sni_sent,omitempty"`
	AlertCode                       *uint16  `json:"alert_code,omitempty"`
	CertificateCount                uint64   `json:"certificate_count,omitempty"`
	LeafSHA256                      string   `json:"leaf_sha256,omitempty"`
	NotBefore                       string   `json:"not_before,omitempty"`
	NotAfter                        string   `json:"not_after,omitempty"`
	SANType                         string   `json:"san_type,omitempty"`
	SANCount                        uint64   `json:"san_count,omitempty"`
	VerifiedHostname                string   `json:"verified_hostname,omitempty"`
	VerificationTime                string   `json:"verification_time,omitempty"`
	TrustSource                     string   `json:"trust_source,omitempty"`
	FailureReason                   *string  `json:"failure_reason,omitempty"`
	ExchangeEntityID                string   `json:"exchange_entity_id,omitempty"`
	ResultKind                      string   `json:"result_kind,omitempty"`
	StatusCode                      uint16   `json:"status_code,omitempty"`
	RedirectTargetEntityID          *string  `json:"redirect_target_entity_id,omitempty"`
	RedirectTarget                  *wTarget `json:"redirect_target,omitempty"`
	ProxyRouteEntityID              string   `json:"proxy_route_entity_id,omitempty"`
	UpstreamEntityID                *string  `json:"upstream_entity_id,omitempty"`
	MatcherKind                     string   `json:"matcher_kind,omitempty"`
	MatchResult                     string   `json:"match_result,omitempty"`
	ListenerEntityID                string   `json:"listener_entity_id,omitempty"`
	NamespaceEntityID               string   `json:"namespace_entity_id,omitempty"`
	Protocol                        string   `json:"protocol,omitempty"`
	BindSemantics                   string   `json:"bind_semantics,omitempty"`
	Port                            uint16   `json:"port,omitempty"`
	PortStart                       uint16   `json:"port_start,omitempty"`
	PortEnd                         uint16   `json:"port_end,omitempty"`
	MatchingListenerCount           uint64   `json:"matching_listener_count,omitempty"`
	ProcessEntityID                 *string  `json:"process_entity_id,omitempty"`
	FactKind                        string   `json:"fact_kind,omitempty"`
	ContainerEntityID               string   `json:"container_entity_id,omitempty"`
	RuntimeState                    string   `json:"runtime_state,omitempty"`
	CapabilityID                    string   `json:"capability_id,omitempty"`
	ReasonCode                      string   `json:"reason_code,omitempty"`
}
type wVisibility struct {
	VisibilityID        string           `json:"visibility_id"`
	SubjectKind         string           `json:"subject_kind"`
	VantageID           string           `json:"vantage_id"`
	Scope               wVisibilityScope `json:"scope"`
	Level               string           `json:"level"`
	BasisObservationIDs []string         `json:"basis_observation_ids"`
	Limitations         []wLimitation    `json:"limitations"`
	AssessedAt          string           `json:"assessed_at"`
}
type wVisibilityScope struct {
	Kind                     string `json:"kind"`
	NamespaceEntityID        string `json:"namespace_entity_id"`
	Protocol                 string `json:"protocol"`
	AddressFamily            string `json:"address_family"`
	BindSemantics            string `json:"bind_semantics"`
	PortStart                uint16 `json:"port_start"`
	PortEnd                  uint16 `json:"port_end"`
	ProcessOwnershipRequired bool   `json:"process_ownership_required"`
}
type wEvaluation struct {
	EvaluatedAt    string   `json:"evaluated_at"`
	OrderedRuleIDs []string `json:"ordered_rule_ids"`
}
type wClaim struct {
	ClaimID                 string         `json:"claim_id"`
	StatementCode           string         `json:"statement_code"`
	Level                   string         `json:"level"`
	SubjectEntityIDs        []string       `json:"subject_entity_ids"`
	BranchIDs               []string       `json:"branch_ids"`
	Parameters              wClaimParams   `json:"parameters"`
	SupportingEvidence      []wEvidenceRef `json:"supporting_evidence"`
	ContradictingEvidence   []wEvidenceRef `json:"contradicting_evidence"`
	RequiredMissingEvidence []wMissing     `json:"required_missing_evidence"`
	RuleID                  string         `json:"rule_id"`
}
type wClaimParams struct {
	Kind              string `json:"kind"`
	PeerEntityID      string `json:"peer_entity_id,omitempty"`
	Hostname          string `json:"hostname,omitempty"`
	VerificationTime  string `json:"verification_time,omitempty"`
	TrustSource       string `json:"trust_source,omitempty"`
	EndpointEntityID  string `json:"endpoint_entity_id,omitempty"`
	VantageID         string `json:"vantage_id,omitempty"`
	ObservedAt        string `json:"observed_at,omitempty"`
	NamespaceEntityID string `json:"namespace_entity_id,omitempty"`
	Protocol          string `json:"protocol,omitempty"`
	AddressFamily     string `json:"address_family,omitempty"`
	BindSemantics     string `json:"bind_semantics,omitempty"`
	Port              uint16 `json:"port,omitempty"`
}
type wMissing struct {
	Kind                  string            `json:"kind"`
	ObservationKind       *string           `json:"observation_kind,omitempty"`
	VisibilitySubjectKind *string           `json:"visibility_subject_kind,omitempty"`
	VisibilityScope       *wVisibilityScope `json:"visibility_scope,omitempty"`
	VantageID             *string           `json:"vantage_id,omitempty"`
}
type wPathPosition struct {
	BranchID string `json:"branch_id"`
	Position uint64 `json:"position"`
}
type wFinding struct {
	FindingID            string          `json:"finding_id"`
	Kind                 string          `json:"kind"`
	TitleCode            string          `json:"title_code"`
	Level                string          `json:"level"`
	BranchIDs            []string        `json:"branch_ids"`
	PathPositions        []wPathPosition `json:"path_positions"`
	ClaimIDs             []string        `json:"claim_ids"`
	RuleID               string          `json:"rule_id"`
	Limitations          []wLimitation   `json:"limitations"`
	SuggestedExperiments []string        `json:"suggested_experiments"`
	Selection            string          `json:"selection"`
}
