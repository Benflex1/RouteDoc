package model

import (
	"time"
)

func validateCheckDefinition(is *ValidationIssues, c CheckDefinition, p string, entities map[EntityID]bool, vantages map[VantageID]bool, assertions map[AssertionID]bool, caps map[CapabilityID]bool) {
	if !c.Kind.Valid() {
		addIssue(is, CodeUnknownUnionKind, p+"/kind", "unknown check kind")
	}
	if c.Version.Major == 0 && c.Version.Minor == 0 && c.Version.Patch == 0 {
		addIssue(is, CodeInvalidValue, p+"/version", "check version required")
	}
	if !c.Inputs.Kind.Valid() || !entities[c.Inputs.SubjectEntityID] {
		addIssue(is, CodeReferenceMissing, p+"/inputs/subject_entity_id", "check subject missing")
	}
	if c.Inputs.VantageID != nil && !vantages[*c.Inputs.VantageID] {
		addIssue(is, CodeReferenceMissing, p+"/inputs/vantage_id", "vantage missing")
	}
	if c.Inputs.AssertionID != nil && !assertions[*c.Inputs.AssertionID] {
		addIssue(is, CodeReferenceMissing, p+"/inputs/assertion_id", "assertion missing")
	}
	if c.DependencyCheckIDs == nil {
		addIssue(is, CodeMissingRequiredField, p+"/dependency_check_ids", "required collection")
	}
	if c.RequiredCapabilityIDs == nil {
		addIssue(is, CodeMissingRequiredField, p+"/required_capability_ids", "required collection")
	}
	for _, id := range c.RequiredCapabilityIDs {
		if !caps[id] {
			addIssue(is, CodeReferenceMissing, p+"/required_capability_ids", "capability missing")
		}
	}
	if c.ExecutionPolicy.DeadlineNS < 0 {
		addIssue(is, CodeInvalidValue, p+"/execution_policy/deadline_ns", "duration must be non-negative")
	}
	if err := validateReasonCode(c.ExecutionPolicy.DependencyFailureReasonCode); err != nil {
		addIssue(is, CodeSensitiveDisallowedField, p+"/execution_policy/dependency_failure_reason_code", err.Error())
	}
	if !c.ExpectedCondition.Kind.Valid() {
		addIssue(is, CodeUnknownUnionKind, p+"/expected_condition/kind", "unknown expected condition")
	}
	if c.ExpectedCondition.Hostname != nil {
		if err := validateHostname(*c.ExpectedCondition.Hostname); err != nil {
			addIssue(is, CodeSensitiveDisallowedField, p+"/expected_condition/hostname", err.Error())
		}
	}
	if c.ExpectedCondition.Result != "" {
		if err := validateSafeToken(c.ExpectedCondition.Result, 64); err != nil {
			addIssue(is, CodeSensitiveDisallowedField, p+"/expected_condition/result", err.Error())
		}
	}
}
func validateCheckDAG(is *ValidationIssues, defs []CheckDefinition) {
	known := map[CheckID]bool{}
	deps := map[CheckID][]CheckID{}
	for _, d := range defs {
		known[d.CheckID] = true
		deps[d.CheckID] = d.DependencyCheckIDs
		for _, id := range d.DependencyCheckIDs {
			if !known[id] { /* order-independent check below */
			}
		}
	}
	for _, d := range defs {
		for _, id := range d.DependencyCheckIDs {
			if !known[id] {
				addIssue(is, CodeReferenceMissing, "/check_definitions", "dependency check missing")
			}
		}
	}
	state := map[CheckID]uint8{}
	var visit func(CheckID) bool
	visit = func(id CheckID) bool {
		if state[id] == 1 {
			return false
		}
		if state[id] == 2 {
			return true
		}
		state[id] = 1
		for _, d := range deps[id] {
			if !visit(d) {
				return false
			}
		}
		state[id] = 2
		return true
	}
	for _, d := range defs {
		if !visit(d.CheckID) {
			addIssue(is, CodeInvalidValue, "/check_definitions", "dependency cycle")
		}
	}
}
func validateExecution(is *ValidationIssues, e CheckExecution, p string, entities map[EntityID]bool, vantages map[VantageID]bool, checks map[CheckID]bool, obs []Observation, vis []VisibilityAssessment) {
	if e.BranchID != nil && !e.BranchID.Valid() {
		addIssue(is, CodeInvalidValue, p+"/branch_id", "invalid branch ID")
	}
	if e.VantageID != nil && !vantages[*e.VantageID] {
		addIssue(is, CodeReferenceMissing, p+"/vantage_id", "vantage missing")
	}
	if e.ReasonCode != nil {
		if err := validateReasonCode(*e.ReasonCode); err != nil {
			addIssue(is, CodeSensitiveDisallowedField, p+"/reason_code", err.Error())
		}
	}
	valid := false
	switch e.Lifecycle {
	case CheckNotRun:
		valid = e.Verdict == CheckSkipped
	case CheckCompleted:
		valid = e.Verdict == CheckPass || e.Verdict == CheckFail || e.Verdict == CheckUnknown
	case CheckUnavailable, CheckDenied:
		valid = e.Verdict == CheckSkipped
	case CheckTimedOut:
		valid = e.Verdict == CheckFail || e.Verdict == CheckUnknown
	case CheckError:
		valid = e.Verdict == CheckUnknown
	default:
		addIssue(is, CodeUnknownEnumValue, p+"/lifecycle", "unknown lifecycle")
	}
	if !e.Verdict.Valid() || !valid {
		addIssue(is, CodeInvalidExecutionState, p, "lifecycle/verdict combination invalid")
	}
	if e.ObservationIDs == nil {
		addIssue(is, CodeMissingRequiredField, p+"/observation_ids", "required collection")
	}
	if e.VisibilityAssessmentIDs == nil {
		addIssue(is, CodeMissingRequiredField, p+"/visibility_assessment_ids", "required collection")
	}
	oi := map[ObservationID]bool{}
	for _, o := range obs {
		oi[o.ObservationID] = true
	}
	vi := map[VisibilityID]bool{}
	for _, v := range vis {
		vi[v.VisibilityID] = true
	}
	for _, id := range e.ObservationIDs {
		if !oi[id] {
			addIssue(is, CodeReferenceMissing, p+"/observation_ids", "observation missing")
		}
	}
	for _, id := range e.VisibilityAssessmentIDs {
		if !vi[id] {
			addIssue(is, CodeReferenceMissing, p+"/visibility_assessment_ids", "visibility missing")
		}
	}
	if e.StartedAt != nil && e.FinishedAt != nil {
		if e.StartedAt.Location() != time.UTC || e.FinishedAt.Location() != time.UTC {
			addIssue(is, CodeInvalidValue, p, "execution times must be UTC")
		}
		if e.FinishedAt.Before(*e.StartedAt) {
			addIssue(is, CodeInvalidValue, p, "execution finished before started")
		}
	}
}
func validateObservation(is *ValidationIssues, o Observation, p string, entities map[EntityID]bool, vantages map[VantageID]bool) {
	if !o.Kind.Valid() {
		addIssue(is, CodeUnknownUnionKind, p+"/kind", "unknown observation kind")
	}
	if o.SubjectEntityIDs == nil {
		addIssue(is, CodeMissingRequiredField, p+"/subject_entity_ids", "required collection")
	}
	for _, id := range o.SubjectEntityIDs {
		if !entities[id] {
			addIssue(is, CodeReferenceMissing, p+"/subject_entity_ids", "entity missing")
		}
	}
	if observationNeedsVantage(o.Kind) && (o.VantageID == nil || !vantages[*o.VantageID]) {
		if o.VantageID == nil {
			addIssue(is, CodeVantageRequired, p+"/vantage_id", "network observation requires one vantage")
		} else {
			addIssue(is, CodeReferenceMissing, p+"/vantage_id", "vantage missing")
		}
	}
	if o.ObservedAt.IsZero() || o.ObservedAt.Location() != time.UTC {
		addIssue(is, CodeInvalidValue, p+"/observed_at", "observation time must be UTC")
	}
	if !o.AcquisitionMethod.Valid() {
		addIssue(is, CodeUnknownEnumValue, p+"/acquisition_method", "unknown acquisition method")
	}
	if !o.SourceComponent.Valid() {
		addIssue(is, CodeUnknownEnumValue, p+"/source_component", "unknown source component")
	}
	if !o.Sensitivity.Valid() {
		addIssue(is, CodeUnknownEnumValue, p+"/sensitivity", "unknown sensitivity")
	}
	if o.Limitations == nil {
		addIssue(is, CodeMissingRequiredField, p+"/limitations", "required collection")
	}
	if o.Payload.Kind != o.Kind {
		addIssue(is, CodeUnknownUnionKind, p+"/payload/kind", "payload kind mismatch")
	}
	if payloadCount(o.Payload) != 1 {
		addIssue(is, CodeInvalidValue, p+"/payload", "exactly one payload case required")
	}
	validatePayload(is, o, p, entities)
}
func observationNeedsVantage(k ObservationKind) bool { return k != ObservationCapabilityPermission }
func payloadCount(p ObservationPayload) int {
	n := 0
	if p.Resolution != nil {
		n++
	}
	if p.TCP != nil {
		n++
	}
	if p.TLSTransport != nil {
		n++
	}
	if p.TLSPeer != nil {
		n++
	}
	if p.CertificateVerification != nil {
		n++
	}
	if p.HTTP != nil {
		n++
	}
	if p.ActiveProxyRoute != nil {
		n++
	}
	if p.ConfiguredProxyRoute != nil {
		n++
	}
	if p.UpstreamSelection != nil {
		n++
	}
	if p.Listener != nil {
		n++
	}
	if p.ListenerInventoryResult != nil {
		n++
	}
	if p.ProcessOwnership != nil {
		n++
	}
	if p.Docker != nil {
		n++
	}
	if p.Capability != nil {
		n++
	}
	return n
}
func validatePayload(is *ValidationIssues, o Observation, p string, entities map[EntityID]bool) {
	switch o.Kind {
	case ObservationSystemResolution:
		if o.Payload.Resolution != nil {
			v := o.Payload.Resolution
			if !v.AddressFamily.Valid() || !v.Result.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/payload", "invalid resolution enum")
			}
			if !entities[v.HostnameEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/hostname_entity_id", "entity missing")
			}
			if v.AddressEntityID != nil && !entities[*v.AddressEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/address_entity_id", "entity missing")
			}
		}
	case ObservationTCPConnection:
		if o.Payload.TCP != nil {
			v := o.Payload.TCP
			if !v.Result.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/payload/result", "unknown TCP result")
			}
			if v.DurationNS < 0 {
				addIssue(is, CodeInvalidValue, p+"/payload/duration_ns", "duration must be non-negative")
			}
			if !entities[v.EndpointEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/endpoint_entity_id", "entity missing")
			}
		}
	case ObservationTLSTransport:
		if o.Payload.TLSTransport != nil {
			v := o.Payload.TLSTransport
			if !v.Result.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/payload/result", "unknown TLS result")
			}
			if v.DurationNS < 0 {
				addIssue(is, CodeInvalidValue, p+"/payload/duration_ns", "duration must be non-negative")
			}
			for field, value := range map[string]string{"protocol_version": v.ProtocolVersion, "cipher_suite": v.CipherSuite, "negotiated_alpn": v.NegotiatedALPN} {
				if value != "" {
					if err := validateSafeToken(value, 128); err != nil {
						addIssue(is, CodeSensitiveDisallowedField, p+"/payload/"+field, err.Error())
					}
				}
			}
			if v.SNISent != "" {
				if err := validateHostname(v.SNISent); err != nil {
					addIssue(is, CodeSensitiveDisallowedField, p+"/payload/sni_sent", err.Error())
				}
			}
			if !entities[v.PeerEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/peer_entity_id", "entity missing")
			}
		}
	case ObservationTLSPeer:
		if o.Payload.TLSPeer != nil {
			v := o.Payload.TLSPeer
			if !entities[v.PeerEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/peer_entity_id", "entity missing")
			}
			if v.NotBefore.Location() != time.UTC || v.NotAfter.Location() != time.UTC {
				addIssue(is, CodeInvalidValue, p+"/payload", "certificate times must be UTC")
			}
			if v.CertificateCount == 0 {
				addIssue(is, CodeInvalidValue, p+"/payload/certificate_count", "certificate required")
			}
			if err := validateFingerprint(v.LeafSHA256); err != nil {
				addIssue(is, CodeSensitiveDisallowedField, p+"/payload/leaf_sha256", err.Error())
			}
		}
	case ObservationCertificateVerification:
		if o.Payload.CertificateVerification != nil {
			v := o.Payload.CertificateVerification
			if !v.Result.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/payload/result", "unknown certificate result")
			}
			if !v.TrustSource.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/payload/trust_source", "unknown trust source")
			}
			if v.VerificationTime.Location() != time.UTC {
				addIssue(is, CodeInvalidValue, p+"/payload/verification_time", "time must be UTC")
			}
			if !entities[v.PeerEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/peer_entity_id", "entity missing")
			}
			if err := validateHostname(v.VerifiedHostname); err != nil {
				addIssue(is, CodeSensitiveDisallowedField, p+"/payload/verified_hostname", err.Error())
			}
		}
	case ObservationHTTP:
		if o.Payload.HTTP != nil {
			v := o.Payload.HTTP
			if !v.ResultKind.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/payload/result_kind", "unknown HTTP result")
			}
			if !entities[v.ExchangeEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/exchange_entity_id", "entity missing")
			}
			if v.RedirectTarget != nil && !v.RedirectTarget.Path.Present && v.RedirectTarget.Path.IsRoot {
				addIssue(is, CodeSensitiveDisallowedField, p+"/payload/redirect_target", "invalid path summary")
			}
		}
	case ObservationActiveProxyRoute, ObservationConfiguredProxyRoute:
		var v *ProxyRouteSummary
		if o.Kind == ObservationActiveProxyRoute {
			v = o.Payload.ActiveProxyRoute
		} else {
			v = o.Payload.ConfiguredProxyRoute
		}
		if v != nil {
			if !v.MatchResult.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/payload/match_result", "unknown matcher result")
			}
			if !entities[v.ProxyRouteEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/proxy_route_entity_id", "entity missing")
			}
			if v.UpstreamEntityID != nil && !entities[*v.UpstreamEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/upstream_entity_id", "entity missing")
			}
			if err := validateSafeToken(v.MatcherKind, 64); err != nil {
				addIssue(is, CodeSensitiveDisallowedField, p+"/payload/matcher_kind", err.Error())
			}
		}
	case ObservationUpstreamSelection:
		if o.Payload.UpstreamSelection != nil {
			v := o.Payload.UpstreamSelection
			if !v.Result.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/payload/result", "unknown upstream result")
			}
			if !entities[v.ProxyRouteEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/proxy_route_entity_id", "entity missing")
			}
			if v.UpstreamEntityID != nil && !entities[*v.UpstreamEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/upstream_entity_id", "entity missing")
			}
		}
	case ObservationListenerInventory:
		if o.Payload.Listener != nil {
			v := o.Payload.Listener
			if !v.Protocol.Valid() || !v.AddressFamily.Valid() || !v.BindSemantics.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/payload", "invalid listener enum")
			}
			if !entities[v.ListenerEntityID] || !entities[v.NamespaceEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload", "listener or namespace missing")
			}
		}
	case ObservationListenerInventoryResult:
		if o.Payload.ListenerInventoryResult != nil {
			v := o.Payload.ListenerInventoryResult
			if len(o.Limitations) != 0 {
				addIssue(is, CodeInvalidValue, p+"/limitations", "completed listener inventory result cannot carry limitations")
			}
			if !v.NamespaceEntityID.Valid() {
				addIssue(is, CodeInvalidValue, p+"/payload/namespace_entity_id", "invalid namespace entity ID")
			}
			if !v.Protocol.Valid() || !v.AddressFamily.Valid() || !v.BindSemantics.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/payload", "invalid listener inventory result enum")
			}
			if v.PortStart > v.PortEnd {
				addIssue(is, CodeInvalidValue, p+"/payload/port_start", "listener inventory result port range is invalid")
			}
			if !entities[v.NamespaceEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/namespace_entity_id", "namespace missing")
			}
		}
	case ObservationProcessOwnership:
		if o.Payload.ProcessOwnership != nil {
			v := o.Payload.ProcessOwnership
			if !v.Result.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/payload/result", "unknown ownership result")
			}
			if !entities[v.ListenerEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/listener_entity_id", "listener missing")
			}
			if v.ProcessEntityID != nil && !entities[*v.ProcessEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/process_entity_id", "process missing")
			}
		}
	case ObservationDockerRuntime:
		if o.Payload.Docker != nil {
			v := o.Payload.Docker
			if !v.FactKind.Valid() || !v.RuntimeState.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/payload", "invalid Docker summary enum")
			}
			if !entities[v.ContainerEntityID] {
				addIssue(is, CodeReferenceMissing, p+"/payload/container_entity_id", "container missing")
			}
		}
	case ObservationCapabilityPermission:
		if o.Payload.Capability != nil {
			if !o.Payload.Capability.Result.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/payload/result", "unknown capability result")
			}
			if err := validateReasonCode(o.Payload.Capability.ReasonCode); err != nil {
				addIssue(is, CodeSensitiveDisallowedField, p+"/payload/reason_code", err.Error())
			}
		}
	}
}
func validateVisibility(is *ValidationIssues, v VisibilityAssessment, p string, entities map[EntityID]bool, vantages map[VantageID]bool, obs map[ObservationID]bool, all []Observation, run EvidenceRun) {
	if !v.SubjectKind.Valid() {
		addIssue(is, CodeUnknownUnionKind, p+"/subject_kind", "unknown visibility subject")
	}
	if !v.VantageID.Valid() || !vantages[v.VantageID] {
		addIssue(is, CodeReferenceMissing, p+"/vantage_id", "vantage missing")
	}
	if !v.Level.Valid() {
		addIssue(is, CodeUnknownEnumValue, p+"/level", "unknown visibility level")
	}
	if v.BasisObservationIDs == nil {
		addIssue(is, CodeMissingRequiredField, p+"/basis_observation_ids", "required collection")
	}
	if v.Limitations == nil {
		addIssue(is, CodeMissingRequiredField, p+"/limitations", "required collection")
	}
	if v.Scope.Kind != "LISTENER" || v.Scope.Listener == nil {
		addIssue(is, CodeVisibilityScopeMismatch, p+"/scope", "listener scope required")
		return
	}
	s := v.Scope.Listener
	if s.PortStart > s.PortEnd {
		addIssue(is, CodeVisibilityScopeMismatch, p+"/scope/port_start", "invalid port range")
	}
	if !entities[s.NamespaceEntityID] {
		addIssue(is, CodeReferenceMissing, p+"/scope/namespace_entity_id", "namespace missing")
	}
	for _, id := range v.BasisObservationIDs {
		if !obs[id] {
			addIssue(is, CodeReferenceMissing, p+"/basis_observation_ids", "basis observation missing")
		}
		for _, o := range all {
			if o.ObservationID == id && o.VantageID != nil && *o.VantageID != v.VantageID {
				addIssue(is, CodeVantageMismatch, p+"/basis_observation_ids", "basis vantage mismatch")
			}
		}
	}
	if v.Level == VisibilityCompleteForScope && len(v.BasisObservationIDs) == 0 {
		addIssue(is, CodeVisibilityInsufficientForAbsence, p+"/level", "complete visibility needs basis observations")
	}
	if v.Level == VisibilityCompleteForScope && len(v.BasisObservationIDs) > 0 {
		if code := listenerVisibilityBasisIssueCode(run, v); code != "" && code != CodeVisibilityInsufficientForAbsence {
			addIssue(is, code, p+"/basis_observation_ids", "complete visibility basis does not match listener scope")
		} else if !ListenerVisibilityComplete(run, v) {
			addIssue(is, CodeVisibilityInsufficientForAbsence, p+"/level", "complete visibility requires a qualifying completed inventory result")
		}
	}
}
func validateLimitation(is *ValidationIssues, l Limitation, p string) {
	if !l.Code.Valid() {
		addIssue(is, CodeUnknownEnumValue, p+"/code", "unknown limitation")
	}
	if !l.Scope.Kind.Valid() {
		addIssue(is, CodeInvalidValue, p+"/scope/kind", "unknown limitation scope")
	}
}
