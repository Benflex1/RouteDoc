package v1

import (
	"bytes"
	"encoding/json"
	"time"

	"routedoc/internal/model"
)

func EncodeCanonical(v model.ValidatedEvaluatedRun) ([]byte, model.ValidationIssues) {
	r := v.Value()
	if r.Evidence.ReportSchemaVersion != (model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}) {
		return nil, model.ValidationIssues{{Code: model.CodeExactVersionRequired, Pointer: "/report_schema_version", Message: "canonical output requires exact version"}}
	}
	if _, issues := model.ValidatePersistedEvaluatedRun(r); len(issues) > 0 {
		return nil, issues
	}
	w := reportWire(r)
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(w); err != nil {
		return nil, model.ValidationIssues{{Code: model.CodeInvalidValue, Pointer: "/", Message: err.Error()}}
	}
	return b.Bytes(), nil
}
func timeWire(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func reportWire(r model.EvaluatedRun) wReport {
	e := r.Evidence
	w := wReport{ReportSchemaVersion: e.ReportSchemaVersion.String(), Producer: wProducer{Name: e.Producer.Name, Version: e.Producer.Version, Build: e.Producer.Build}, RunID: string(e.RunID), Target: targetWire(e.Target), Goal: wGoal{Kind: string(e.Goal.Kind)}, RequestedScope: wRequestedScope{Kind: string(e.RequestedScope.Kind)}, Policy: wPolicy{CoherenceWindowNS: e.Policy.CoherenceWindowNS}, StartedAt: timeWire(e.StartedAt), FinishedAt: timeWire(e.FinishedAt), VantagePoints: make([]wVantage, len(e.VantagePoints)), Capabilities: make([]wCapability, len(e.Capabilities)), OperatorAssertions: make([]wAssertion, len(e.OperatorAssertions)), Entities: make([]wEntity, len(e.Entities)), ServicePath: servicePathWire(e.ServicePath), CheckDefinitions: make([]wCheckDefinition, len(e.CheckDefinitions)), CheckExecutions: make([]wCheckExecution, len(e.CheckExecutions)), Observations: make([]wObservation, len(e.Observations)), VisibilityAssessments: make([]wVisibility, len(e.VisibilityAssessments)), Evaluation: wEvaluation{EvaluatedAt: timeWire(r.Evaluation.EvaluatedAt), OrderedRuleIDs: make([]string, len(r.Evaluation.OrderedRuleIDs))}, Claims: make([]wClaim, len(r.Claims)), Findings: make([]wFinding, len(r.Findings)), Limitations: make([]wLimitation, len(e.Limitations))}
	if e.Goal.ExpectationAssertionID != nil {
		x := string(*e.Goal.ExpectationAssertionID)
		w.Goal.ExpectationAssertionID = &x
	}
	for i, x := range e.VantagePoints {
		w.VantagePoints[i] = vantageWire(x)
	}
	for i, x := range e.Capabilities {
		w.Capabilities[i] = wCapability{CapabilityID: string(x.CapabilityID), Kind: string(x.Kind), State: string(x.State), ReasonCode: x.ReasonCode}
	}
	for i, x := range e.OperatorAssertions {
		w.OperatorAssertions[i] = assertionWire(x)
	}
	for i, x := range e.Entities {
		w.Entities[i] = entityWire(x)
	}
	for i, x := range e.CheckDefinitions {
		w.CheckDefinitions[i] = checkDefinitionWire(x)
	}
	for i, x := range e.CheckExecutions {
		w.CheckExecutions[i] = checkExecutionWire(x)
	}
	for i, x := range e.Observations {
		w.Observations[i] = observationWire(x)
	}
	for i, x := range e.VisibilityAssessments {
		w.VisibilityAssessments[i] = visibilityWire(x)
	}
	for i, x := range e.Limitations {
		w.Limitations[i] = limitationWire(x)
	}
	for i, x := range r.Evaluation.OrderedRuleIDs {
		w.Evaluation.OrderedRuleIDs[i] = string(x)
	}
	for i, x := range r.Claims {
		w.Claims[i] = claimWire(x)
	}
	for i, x := range r.Findings {
		w.Findings[i] = findingWire(x)
	}
	return w
}
func targetWire(x model.Target) wTarget {
	return wTarget{Scheme: x.Scheme, Hostname: x.Hostname, EffectivePort: x.EffectivePort, Path: wPathSummary{Present: x.Path.Present, IsRoot: x.Path.IsRoot, SegmentCount: x.Path.SegmentCount, TrailingSlash: x.Path.TrailingSlash, QueryPresent: x.Path.QueryPresent}}
}
func limitationWire(x model.Limitation) wLimitation {
	w := wLimitation{LimitationID: string(x.LimitationID), Code: string(x.Code), Scope: wLimitationScope{Kind: string(x.Scope.Kind)}}
	if x.Scope.VantageID != nil {
		s := string(*x.Scope.VantageID)
		w.Scope.VantageID = &s
	}
	if x.Scope.ObservationID != nil {
		s := string(*x.Scope.ObservationID)
		w.Scope.ObservationID = &s
	}
	if x.Scope.VisibilityID != nil {
		s := string(*x.Scope.VisibilityID)
		w.Scope.VisibilityID = &s
	}
	if x.Scope.FindingID != nil {
		s := string(*x.Scope.FindingID)
		w.Scope.FindingID = &s
	}
	return w
}
func vantageWire(x model.VantagePoint) wVantage {
	w := wVantage{VantageID: string(x.VantageID), Kind: string(x.Kind), Role: string(x.Role), DisplayLabel: x.DisplayLabel, Identity: wIdentity{Kind: string(x.Identity.Kind)}, Establishment: string(x.Establishment), Limitations: make([]wLimitation, len(x.Limitations))}
	switch x.Identity.Kind {
	case model.VantageKindClientNetwork:
		if x.Identity.ClientNetwork != nil {
			w.Identity.Label = x.Identity.ClientNetwork.Label
		}
	case model.VantageKindHostNamespace:
		if x.Identity.HostNamespace != nil {
			w.Identity.NamespaceInode = x.Identity.HostNamespace.NamespaceInode
		}
	case model.VantageKindContainerNamespace:
		if x.Identity.ContainerNamespace != nil {
			w.Identity.DaemonID = x.Identity.ContainerNamespace.DaemonID
			w.Identity.ContainerID = x.Identity.ContainerNamespace.ContainerID
		}
	case model.VantageKindUnknownNamespace:
		if x.Identity.UnknownNamespace != nil {
			w.Identity.ReasonCode = x.Identity.UnknownNamespace.ReasonCode
		}
	}
	if x.ParentVantageID != nil {
		s := string(*x.ParentVantageID)
		w.ParentVantageID = &s
	}
	for i, l := range x.Limitations {
		w.Limitations[i] = limitationWire(l)
	}
	return w
}
func assertionWire(x model.OperatorAssertion) wAssertion {
	w := wAssertion{AssertionID: string(x.AssertionID), Kind: string(x.Kind), Parameters: assertionParamsWire(x.Parameters), EstablishedAt: timeWire(x.EstablishedAt), Source: string(x.Source)}
	return w
}
func assertionParamsWire(x model.AssertionParameters) wAssertionParams {
	w := wAssertionParams{Kind: string(x.Kind)}
	if x.LocalOrigin != nil {
		w.URLTargetEntityID = string(x.LocalOrigin.URLTargetEntityID)
		w.HostVantageID = string(x.LocalOrigin.HostVantageID)
	}
	if x.ExpectedPath != nil {
		w.FromEntityID = string(x.ExpectedPath.FromEntityID)
		w.ToEntityID = string(x.ExpectedPath.ToEntityID)
		w.Relation = string(x.ExpectedPath.Relation)
	}
	if x.HTTP != nil {
		w.ExpectationKind = string(x.HTTP.ExpectationKind)
		w.StatusMin = x.HTTP.StatusMin
		w.StatusMax = x.HTTP.StatusMax
		w.HeaderName = x.HTTP.HeaderName
	}
	if x.ConfigSource != nil {
		w.ComponentKind = string(x.ConfigSource.ComponentKind)
		w.SourceKind = string(x.ConfigSource.SourceKind)
	}
	if x.PrivateRedirect != nil {
		w.FromAddressScope = x.PrivateRedirect.FromAddressScope
		w.ToAddressScope = x.PrivateRedirect.ToAddressScope
	}
	return w
}
func endpointWire(x model.EndpointIdentity) *wEndpoint {
	a := x.Address.String()
	return &wEndpoint{Address: a, Port: x.Port, Transport: string(x.Transport)}
}
func entityWire(x model.Entity) wEntity {
	w := wEntity{EntityID: string(x.EntityID), Kind: string(x.Kind), DisplayLabel: x.DisplayLabel, Identity: wEntityIdentity{Kind: string(x.Identity.Kind)}}
	switch x.Kind {
	case model.EntityURLTarget:
		if x.Identity.URLTarget != nil {
			b := x.Identity.URLTarget.Marker
			w.Identity.Marker = &b
		}
	case model.EntityHostname:
		if x.Identity.Hostname != nil {
			w.Identity.Hostname = x.Identity.Hostname.Hostname
		}
	case model.EntityIPAddress:
		if x.Identity.IPAddress != nil {
			w.Identity.Address = x.Identity.IPAddress.Address.String()
		}
	case model.EntitySocketEndpoint, model.EntityUpstreamEndpoint:
		if x.Identity.Endpoint != nil {
			w.Identity.Endpoint = endpointWire(*x.Identity.Endpoint)
		}
	case model.EntityTLSPeer:
		if x.Identity.TLSPeer != nil {
			w.Identity.Fingerprint = x.Identity.TLSPeer.Fingerprint
		}
	case model.EntityHTTPExchange:
		if x.Identity.HTTPExchange != nil {
			w.Identity.Ordinal = x.Identity.HTTPExchange.Ordinal
		}
	case model.EntityProxyInstance, model.EntityProxyRoute:
		if x.Identity.Opaque != nil {
			w.Identity.SyntheticID = x.Identity.Opaque.SyntheticID
		}
	case model.EntityListener:
		if x.Identity.Listener != nil {
			w.Identity.Endpoint = endpointWire(x.Identity.Listener.Endpoint)
		}
	case model.EntityProcess:
		if x.Identity.Process != nil {
			w.Identity.PID = x.Identity.Process.PID
		}
	case model.EntityContainer:
		if x.Identity.Container != nil {
			w.Identity.RuntimeID = x.Identity.Container.RuntimeID
			w.Identity.ContainerID = x.Identity.Container.ContainerID
		}
	case model.EntityNetworkNamespace:
		if x.Identity.Namespace != nil {
			w.Identity.NamespaceInode = x.Identity.Namespace.NamespaceInode
		}
	}
	return w
}
func servicePathWire(x model.ServicePath) wServicePath {
	w := wServicePath{Nodes: make([]wNode, len(x.Nodes)), Edges: make([]wEdge, len(x.Edges)), Branches: make([]wBranch, len(x.Branches))}
	for i, n := range x.Nodes {
		w.Nodes[i] = wNode{EntityID: string(n.EntityID)}
	}
	for i, e := range x.Edges {
		w.Edges[i] = wEdge{EdgeID: string(e.EdgeID), From: string(e.From), To: string(e.To), Relation: string(e.Relation), Provenance: string(e.Provenance), EvidenceRefs: refsWire(e.EvidenceRefs)}
	}
	for i, b := range x.Branches {
		w.Branches[i] = wBranch{BranchID: string(b.BranchID), OrderedEdgeIDs: make([]string, len(b.OrderedEdgeIDs)), Goal: string(b.Goal)}
		for j, id := range b.OrderedEdgeIDs {
			w.Branches[i].OrderedEdgeIDs[j] = string(id)
		}
		if b.ParentBranchID != nil {
			s := string(*b.ParentBranchID)
			w.Branches[i].ParentBranchID = &s
		}
	}
	return w
}
func refsWire(v []model.EvidenceRef) []wEvidenceRef {
	w := make([]wEvidenceRef, len(v))
	for i, x := range v {
		w[i].Kind = string(x.Kind)
		if x.ObservationID != nil {
			w[i].ID = string(*x.ObservationID)
		}
		if x.ClaimID != nil {
			w[i].ID = string(*x.ClaimID)
		}
		if x.VisibilityID != nil {
			w[i].ID = string(*x.VisibilityID)
		}
		if x.AssertionID != nil {
			w[i].ID = string(*x.AssertionID)
		}
	}
	return w
}
func checkDefinitionWire(x model.CheckDefinition) wCheckDefinition {
	w := wCheckDefinition{CheckID: string(x.CheckID), Kind: string(x.Kind), Version: x.Version.String(), Inputs: wCheckInputs{Kind: string(x.Inputs.Kind), SubjectEntityID: string(x.Inputs.SubjectEntityID)}, DependencyCheckIDs: make([]string, len(x.DependencyCheckIDs)), RequiredCapabilityIDs: make([]string, len(x.RequiredCapabilityIDs)), ExecutionPolicy: wExecutionPolicy{DeadlineNS: x.ExecutionPolicy.DeadlineNS, DependencyFailureReasonCode: x.ExecutionPolicy.DependencyFailureReasonCode, DeadlineIsExpectedCondition: x.ExecutionPolicy.DeadlineIsExpectedCondition}, ExpectedCondition: wExpectedCondition{Kind: string(x.ExpectedCondition.Kind), Result: x.ExpectedCondition.Result, Port: x.ExpectedCondition.Port, Hostname: x.ExpectedCondition.Hostname, StatusMin: x.ExpectedCondition.StatusMin, StatusMax: x.ExpectedCondition.StatusMax}}
	for i, id := range x.DependencyCheckIDs {
		w.DependencyCheckIDs[i] = string(id)
	}
	for i, id := range x.RequiredCapabilityIDs {
		w.RequiredCapabilityIDs[i] = string(id)
	}
	if x.Inputs.VantageID != nil {
		s := string(*x.Inputs.VantageID)
		w.Inputs.VantageID = &s
	}
	if x.Inputs.AssertionID != nil {
		s := string(*x.Inputs.AssertionID)
		w.Inputs.AssertionID = &s
	}
	if x.ExpectedCondition.AddressFamily != nil {
		s := string(*x.ExpectedCondition.AddressFamily)
		w.ExpectedCondition.AddressFamily = &s
	}
	if x.ExpectedCondition.MatcherResult != nil {
		s := string(*x.ExpectedCondition.MatcherResult)
		w.ExpectedCondition.MatcherResult = &s
	}
	if x.ExpectedCondition.CapabilityState != nil {
		s := string(*x.ExpectedCondition.CapabilityState)
		w.ExpectedCondition.CapabilityState = &s
	}
	return w
}
func checkExecutionWire(x model.CheckExecution) wCheckExecution {
	w := wCheckExecution{ExecutionID: string(x.ExecutionID), CheckID: string(x.CheckID), Lifecycle: string(x.Lifecycle), Verdict: string(x.Verdict), ObservationIDs: make([]string, len(x.ObservationIDs)), VisibilityAssessmentIDs: make([]string, len(x.VisibilityAssessmentIDs))}
	for i, id := range x.ObservationIDs {
		w.ObservationIDs[i] = string(id)
	}
	for i, id := range x.VisibilityAssessmentIDs {
		w.VisibilityAssessmentIDs[i] = string(id)
	}
	if x.BranchID != nil {
		s := string(*x.BranchID)
		w.BranchID = &s
	}
	if x.VantageID != nil {
		s := string(*x.VantageID)
		w.VantageID = &s
	}
	if x.StartedAt != nil {
		s := timeWire(*x.StartedAt)
		w.StartedAt = &s
	}
	if x.FinishedAt != nil {
		s := timeWire(*x.FinishedAt)
		w.FinishedAt = &s
	}
	w.ReasonCode = x.ReasonCode
	return w
}
func observationWire(x model.Observation) wObservation {
	w := wObservation{ObservationID: string(x.ObservationID), Kind: string(x.Kind), SubjectEntityIDs: make([]string, len(x.SubjectEntityIDs)), ObservedAt: timeWire(x.ObservedAt), Payload: payloadWire(x.Payload), AcquisitionMethod: string(x.AcquisitionMethod), SourceComponent: string(x.SourceComponent), Sensitivity: string(x.Sensitivity), Limitations: make([]wLimitation, len(x.Limitations))}
	for i, id := range x.SubjectEntityIDs {
		w.SubjectEntityIDs[i] = string(id)
	}
	if x.VantageID != nil {
		s := string(*x.VantageID)
		w.VantageID = &s
	}
	for i, l := range x.Limitations {
		w.Limitations[i] = limitationWire(l)
	}
	return w
}
func payloadWire(x model.ObservationPayload) wPayload {
	w := wPayload{Kind: string(x.Kind)}
	switch x.Kind {
	case model.ObservationSystemResolution:
		if x.Resolution != nil {
			v := x.Resolution
			w.HostnameEntityID = string(v.HostnameEntityID)
			w.AddressFamily = string(v.AddressFamily)
			w.Result = string(v.Result)
			if v.AddressEntityID != nil {
				s := string(*v.AddressEntityID)
				w.AddressEntityID = &s
			}
		}
	case model.ObservationTCPConnection:
		if x.TCP != nil {
			v := x.TCP
			w.EndpointEntityID = string(v.EndpointEntityID)
			w.Result = string(v.Result)
			w.DurationNS = v.DurationNS
			w.DeadlinePartOfExpectedCondition = v.DeadlinePartOfExpectedCondition
		}
	case model.ObservationTLSTransport:
		if x.TLSTransport != nil {
			v := x.TLSTransport
			w.EndpointEntityID = string(v.EndpointEntityID)
			if v.PeerEntityID != nil {
				x := string(*v.PeerEntityID)
				w.PeerEntityID = &x
			}
			w.Result = string(v.Result)
			w.ProtocolVersion = v.ProtocolVersion
			w.CipherSuite = v.CipherSuite
			w.NegotiatedALPN = v.NegotiatedALPN
			w.SNISent = v.SNISent
			w.AlertCode = v.AlertCode
			w.DurationNS = v.DurationNS
		}
	case model.ObservationTLSPeer:
		if x.TLSPeer != nil {
			v := x.TLSPeer
			x := string(v.PeerEntityID)
			w.PeerEntityID = &x
			w.CertificateCount = v.CertificateCount
			w.LeafSHA256 = v.LeafSHA256
			w.NotBefore = timeWire(v.NotBefore)
			w.NotAfter = timeWire(v.NotAfter)
			w.SANType = string(v.SANType)
			w.SANCount = v.SANCount
		}
	case model.ObservationCertificateVerification:
		if x.CertificateVerification != nil {
			v := x.CertificateVerification
			x := string(v.PeerEntityID)
			w.PeerEntityID = &x
			w.VerifiedHostname = v.VerifiedHostname
			w.VerificationTime = timeWire(v.VerificationTime)
			w.TrustSource = string(v.TrustSource)
			w.Result = string(v.Result)
			if v.FailureReason != nil {
				s := string(*v.FailureReason)
				w.FailureReason = &s
			}
		}
	case model.ObservationHTTP:
		if x.HTTP != nil {
			v := x.HTTP
			w.ExchangeEntityID = string(v.ExchangeEntityID)
			w.ResultKind = string(v.ResultKind)
			w.StatusCode = v.StatusCode
			if v.RedirectTargetEntityID != nil {
				s := string(*v.RedirectTargetEntityID)
				w.RedirectTargetEntityID = &s
			}
			if v.RedirectTarget != nil {
				z := targetWire(*v.RedirectTarget)
				w.RedirectTarget = &z
			}
		}
	case model.ObservationActiveProxyRoute:
		if x.ActiveProxyRoute != nil {
			proxyPayloadWire(&w, *x.ActiveProxyRoute)
		}
	case model.ObservationConfiguredProxyRoute:
		if x.ConfiguredProxyRoute != nil {
			proxyPayloadWire(&w, *x.ConfiguredProxyRoute)
		}
	case model.ObservationUpstreamSelection:
		if x.UpstreamSelection != nil {
			v := x.UpstreamSelection
			w.ProxyRouteEntityID = string(v.ProxyRouteEntityID)
			w.Result = string(v.Result)
			if v.UpstreamEntityID != nil {
				s := string(*v.UpstreamEntityID)
				w.UpstreamEntityID = &s
			}
		}
	case model.ObservationListenerInventory:
		if x.Listener != nil {
			v := x.Listener
			w.ListenerEntityID = string(v.ListenerEntityID)
			w.NamespaceEntityID = string(v.NamespaceEntityID)
			w.Protocol = string(v.Protocol)
			w.AddressFamily = string(v.AddressFamily)
			w.BindSemantics = string(v.BindSemantics)
			w.Port = v.Port
		}
	case model.ObservationListenerInventoryResult:
		if x.ListenerInventoryResult != nil {
			v := x.ListenerInventoryResult
			w.NamespaceEntityID = string(v.NamespaceEntityID)
			w.Protocol = string(v.Protocol)
			w.AddressFamily = string(v.AddressFamily)
			w.BindSemantics = string(v.BindSemantics)
			w.PortStart = v.PortStart
			w.PortEnd = v.PortEnd
			w.MatchingListenerCount = v.MatchingListenerCount
		}
	case model.ObservationProcessOwnership:
		if x.ProcessOwnership != nil {
			v := x.ProcessOwnership
			w.ListenerEntityID = string(v.ListenerEntityID)
			w.Result = string(v.Result)
			if v.ProcessEntityID != nil {
				s := string(*v.ProcessEntityID)
				w.ProcessEntityID = &s
			}
		}
	case model.ObservationDockerRuntime:
		if x.Docker != nil {
			v := x.Docker
			w.FactKind = string(v.FactKind)
			w.ContainerEntityID = string(v.ContainerEntityID)
			w.RuntimeState = string(v.RuntimeState)
			if v.NamespaceEntityID != nil {
				s := string(*v.NamespaceEntityID)
				w.NamespaceEntityID = s
			}
			if v.EndpointEntityID != nil {
				s := string(*v.EndpointEntityID)
				w.EndpointEntityID = s
			}
		}
	case model.ObservationCapabilityPermission:
		if x.Capability != nil {
			w.CapabilityID = string(x.Capability.CapabilityID)
			w.Result = string(x.Capability.Result)
			w.ReasonCode = x.Capability.ReasonCode
		}
	}
	return w
}
func proxyPayloadWire(w *wPayload, x model.ProxyRouteSummary) {
	w.ProxyRouteEntityID = string(x.ProxyRouteEntityID)
	w.MatcherKind = x.MatcherKind
	w.MatchResult = string(x.MatchResult)
	if x.UpstreamEntityID != nil {
		s := string(*x.UpstreamEntityID)
		w.UpstreamEntityID = &s
	}
}
func visibilityWire(x model.VisibilityAssessment) wVisibility {
	w := wVisibility{VisibilityID: string(x.VisibilityID), SubjectKind: string(x.SubjectKind), VantageID: string(x.VantageID), Level: string(x.Level), BasisObservationIDs: make([]string, len(x.BasisObservationIDs)), Limitations: make([]wLimitation, len(x.Limitations)), AssessedAt: timeWire(x.AssessedAt)}
	if x.Scope.Listener != nil {
		s := x.Scope.Listener
		w.Scope = wVisibilityScope{Kind: x.Scope.Kind, NamespaceEntityID: string(s.NamespaceEntityID), Protocol: string(s.Protocol), AddressFamily: string(s.AddressFamily), BindSemantics: string(s.BindSemantics), PortStart: s.PortStart, PortEnd: s.PortEnd, ProcessOwnershipRequired: s.ProcessOwnershipRequired}
	}
	for i, id := range x.BasisObservationIDs {
		w.BasisObservationIDs[i] = string(id)
	}
	for i, l := range x.Limitations {
		w.Limitations[i] = limitationWire(l)
	}
	return w
}
func claimWire(x model.Claim) wClaim {
	w := wClaim{ClaimID: string(x.ClaimID), StatementCode: string(x.StatementCode), Level: string(x.Level), SubjectEntityIDs: make([]string, len(x.SubjectEntityIDs)), BranchIDs: make([]string, len(x.BranchIDs)), Parameters: claimParamsWire(x.Parameters), SupportingEvidence: refsWire(x.SupportingEvidence), ContradictingEvidence: refsWire(x.ContradictingEvidence), RequiredMissingEvidence: make([]wMissing, len(x.RequiredMissingEvidence)), RuleID: string(x.RuleID)}
	for i, id := range x.SubjectEntityIDs {
		w.SubjectEntityIDs[i] = string(id)
	}
	for i, id := range x.BranchIDs {
		w.BranchIDs[i] = string(id)
	}
	for i, m := range x.RequiredMissingEvidence {
		w.RequiredMissingEvidence[i] = missingWire(m)
	}
	return w
}
func claimParamsWire(x model.ClaimParameters) wClaimParams {
	w := wClaimParams{Kind: string(x.Kind)}
	if x.HostnameMismatch != nil {
		v := x.HostnameMismatch
		w.PeerEntityID = string(v.PeerEntityID)
		w.Hostname = v.Hostname
		w.VerificationTime = timeWire(v.VerificationTime)
		w.TrustSource = string(v.TrustSource)
	}
	if x.TCPRefused != nil {
		v := x.TCPRefused
		w.EndpointEntityID = string(v.EndpointEntityID)
		w.VantageID = string(v.VantageID)
		w.ObservedAt = timeWire(v.ObservedAt)
	}
	if x.ListenerAbsent != nil {
		v := x.ListenerAbsent
		w.NamespaceEntityID = string(v.NamespaceEntityID)
		w.VantageID = string(v.VantageID)
		w.Protocol = string(v.Protocol)
		w.AddressFamily = string(v.AddressFamily)
		w.BindSemantics = string(v.BindSemantics)
		w.Port = v.Port
	}
	return w
}
func missingWire(x model.MissingEvidenceRequirement) wMissing {
	w := wMissing{Kind: string(x.Kind)}
	if x.ObservationKind != nil {
		s := string(*x.ObservationKind)
		w.ObservationKind = &s
	}
	if x.VisibilitySubjectKind != nil {
		s := string(*x.VisibilitySubjectKind)
		w.VisibilitySubjectKind = &s
	}
	if x.VisibilityScope != nil {
		z := visibilityScopeWire(*x.VisibilityScope)
		w.VisibilityScope = &z
	}
	if x.VantageID != nil {
		s := string(*x.VantageID)
		w.VantageID = &s
	}
	return w
}
func visibilityScopeWire(x model.VisibilityScope) wVisibilityScope {
	w := wVisibilityScope{Kind: x.Kind}
	if x.Listener != nil {
		s := x.Listener
		w.NamespaceEntityID = string(s.NamespaceEntityID)
		w.Protocol = string(s.Protocol)
		w.AddressFamily = string(s.AddressFamily)
		w.BindSemantics = string(s.BindSemantics)
		w.PortStart = s.PortStart
		w.PortEnd = s.PortEnd
		w.ProcessOwnershipRequired = s.ProcessOwnershipRequired
	}
	return w
}
func findingWire(x model.Finding) wFinding {
	w := wFinding{FindingID: string(x.FindingID), Kind: string(x.Kind), TitleCode: string(x.TitleCode), Level: string(x.Level), BranchIDs: make([]string, len(x.BranchIDs)), PathPositions: make([]wPathPosition, len(x.PathPositions)), ClaimIDs: make([]string, len(x.ClaimIDs)), RuleID: string(x.RuleID), Limitations: make([]wLimitation, len(x.Limitations)), SuggestedExperiments: append([]string{}, x.SuggestedExperiments...), Selection: string(x.Selection)}
	for i, id := range x.BranchIDs {
		w.BranchIDs[i] = string(id)
	}
	for i, p := range x.PathPositions {
		w.PathPositions[i] = wPathPosition{BranchID: string(p.BranchID), Position: p.Position}
	}
	for i, id := range x.ClaimIDs {
		w.ClaimIDs[i] = string(id)
	}
	for i, l := range x.Limitations {
		w.Limitations[i] = limitationWire(l)
	}
	return w
}
