package v1

import (
	"net/netip"
	"time"

	"routedoc/internal/model"
)

func toModel(w wReport, is *model.ValidationIssues) (model.EvaluatedRun, model.ValidationIssues) {
	r := model.EvaluatedRun{}
	r.Evidence.ReportSchemaVersion = model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}
	r.Evidence.Producer = model.Producer{Name: w.Producer.Name, Version: w.Producer.Version, Build: w.Producer.Build}
	r.Evidence.RunID = model.RunID(w.RunID)
	r.Evidence.Target = targetModel(w.Target, is)
	r.Evidence.Goal = model.Goal{Kind: model.GoalKind(w.Goal.Kind)}
	if w.Goal.ExpectationAssertionID != nil {
		x := model.AssertionID(*w.Goal.ExpectationAssertionID)
		r.Evidence.Goal.ExpectationAssertionID = &x
	}
	r.Evidence.RequestedScope = model.RequestedScope{Kind: model.ScopeKind(w.RequestedScope.Kind)}
	r.Evidence.Policy = model.Policy{CoherenceWindowNS: w.Policy.CoherenceWindowNS}
	r.Evidence.StartedAt = parseTime(w.StartedAt, "/started_at", is)
	r.Evidence.FinishedAt = parseTime(w.FinishedAt, "/finished_at", is)
	r.Evidence.VantagePoints = make([]model.VantagePoint, len(w.VantagePoints))
	for i, x := range w.VantagePoints {
		r.Evidence.VantagePoints[i] = vantageModel(x, is)
	}
	r.Evidence.Capabilities = make([]model.Capability, len(w.Capabilities))
	for i, x := range w.Capabilities {
		r.Evidence.Capabilities[i] = model.Capability{CapabilityID: model.CapabilityID(x.CapabilityID), Kind: model.CapabilityKind(x.Kind), State: model.CapabilityState(x.State), ReasonCode: x.ReasonCode}
	}
	r.Evidence.OperatorAssertions = make([]model.OperatorAssertion, len(w.OperatorAssertions))
	for i, x := range w.OperatorAssertions {
		r.Evidence.OperatorAssertions[i] = assertionModel(x, is)
	}
	r.Evidence.Entities = make([]model.Entity, len(w.Entities))
	for i, x := range w.Entities {
		r.Evidence.Entities[i] = entityModel(x, is)
	}
	r.Evidence.ServicePath = servicePathModel(w.ServicePath, is)
	r.Evidence.CheckDefinitions = make([]model.CheckDefinition, len(w.CheckDefinitions))
	for i, x := range w.CheckDefinitions {
		r.Evidence.CheckDefinitions[i] = checkDefinitionModel(x, is)
	}
	r.Evidence.CheckExecutions = make([]model.CheckExecution, len(w.CheckExecutions))
	for i, x := range w.CheckExecutions {
		r.Evidence.CheckExecutions[i] = checkExecutionModel(x, is)
	}
	r.Evidence.Observations = make([]model.Observation, len(w.Observations))
	for i, x := range w.Observations {
		r.Evidence.Observations[i] = observationModel(x, is)
	}
	r.Evidence.VisibilityAssessments = make([]model.VisibilityAssessment, len(w.VisibilityAssessments))
	for i, x := range w.VisibilityAssessments {
		r.Evidence.VisibilityAssessments[i] = visibilityModel(x, is)
	}
	r.Evidence.Limitations = make([]model.Limitation, len(w.Limitations))
	for i, x := range w.Limitations {
		r.Evidence.Limitations[i] = limitationModel(x, is)
	}
	r.Evaluation = model.Evaluation{EvaluatedAt: parseTime(w.Evaluation.EvaluatedAt, "/evaluation/evaluated_at", is), OrderedRuleIDs: make([]model.RuleID, len(w.Evaluation.OrderedRuleIDs))}
	for i, x := range w.Evaluation.OrderedRuleIDs {
		r.Evaluation.OrderedRuleIDs[i] = model.RuleID(x)
	}
	r.Claims = make([]model.Claim, len(w.Claims))
	for i, x := range w.Claims {
		r.Claims[i] = claimModel(x, is)
	}
	r.Findings = make([]model.Finding, len(w.Findings))
	for i, x := range w.Findings {
		r.Findings[i] = findingModel(x, is)
	}
	return r, *is
}
func parseTime(s, p string, is *model.ValidationIssues) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		addDecodeIssue(is, model.CodeInvalidValue, p, err.Error())
		return time.Time{}
	}
	return t
}
func addDecodeIssue(is *model.ValidationIssues, c model.ValidationCode, p, m string) {
	*is = append(*is, model.ValidationIssue{Code: c, Pointer: p, Message: m})
}
func targetModel(w wTarget, is *model.ValidationIssues) model.Target {
	return model.Target{Scheme: w.Scheme, Hostname: w.Hostname, EffectivePort: w.EffectivePort, Path: model.PathSummary{Present: w.Path.Present, IsRoot: w.Path.IsRoot, SegmentCount: w.Path.SegmentCount, TrailingSlash: w.Path.TrailingSlash, QueryPresent: w.Path.QueryPresent}}
}
func limitationModel(w wLimitation, is *model.ValidationIssues) model.Limitation {
	l := model.Limitation{LimitationID: model.LimitationID(w.LimitationID), Code: model.LimitationCode(w.Code), Scope: model.LimitationScope{Kind: model.LimitationScopeKind(w.Scope.Kind)}}
	if w.Scope.VantageID != nil {
		x := model.VantageID(*w.Scope.VantageID)
		l.Scope.VantageID = &x
	}
	if w.Scope.ObservationID != nil {
		x := model.ObservationID(*w.Scope.ObservationID)
		l.Scope.ObservationID = &x
	}
	if w.Scope.VisibilityID != nil {
		x := model.VisibilityID(*w.Scope.VisibilityID)
		l.Scope.VisibilityID = &x
	}
	if w.Scope.FindingID != nil {
		x := model.FindingID(*w.Scope.FindingID)
		l.Scope.FindingID = &x
	}
	return l
}
func vantageModel(w wVantage, is *model.ValidationIssues) model.VantagePoint {
	v := model.VantagePoint{VantageID: model.VantageID(w.VantageID), Kind: model.VantageKind(w.Kind), Role: model.VantageRole(w.Role), DisplayLabel: w.DisplayLabel, Establishment: model.VantageEstablishment(w.Establishment), Limitations: make([]model.Limitation, len(w.Limitations))}
	for i, x := range w.Limitations {
		v.Limitations[i] = limitationModel(x, is)
	}
	v.Identity = model.VantageIdentity{Kind: model.VantageKind(w.Identity.Kind)}
	switch w.Identity.Kind {
	case string(model.VantageKindClientNetwork):
		v.Identity.ClientNetwork = &model.ClientNetworkIdentity{Label: w.Identity.Label}
	case string(model.VantageKindHostNamespace):
		v.Identity.HostNamespace = &model.HostNamespaceIdentity{NamespaceInode: w.Identity.NamespaceInode}
	case string(model.VantageKindContainerNamespace):
		v.Identity.ContainerNamespace = &model.ContainerNamespaceIdentity{DaemonID: w.Identity.DaemonID, ContainerID: w.Identity.ContainerID}
	case string(model.VantageKindUnknownNamespace):
		v.Identity.UnknownNamespace = &model.UnknownNamespaceIdentity{ReasonCode: w.Identity.ReasonCode}
	default:
		addDecodeIssue(is, model.CodeUnknownUnionKind, "/vantage_points/identity/kind", "unknown vantage identity")
	}
	if w.ParentVantageID != nil {
		x := model.VantageID(*w.ParentVantageID)
		v.ParentVantageID = &x
	}
	return v
}
func endpointModel(w *wEndpoint) model.EndpointIdentity {
	if w == nil {
		return model.EndpointIdentity{}
	}
	a, _ := netip.ParseAddr(w.Address)
	return model.EndpointIdentity{Address: a, Port: w.Port, Transport: model.Transport(w.Transport)}
}
func entityModel(w wEntity, is *model.ValidationIssues) model.Entity {
	e := model.Entity{EntityID: model.EntityID(w.EntityID), Kind: model.EntityKind(w.Kind), DisplayLabel: w.DisplayLabel, Identity: model.EntityIdentity{Kind: model.EntityKind(w.Identity.Kind)}}
	x := w.Identity
	switch x.Kind {
	case string(model.EntityURLTarget):
		m := true
		if x.Marker != nil {
			m = *x.Marker
		}
		e.Identity.URLTarget = &model.URLTargetIdentity{Marker: m}
	case string(model.EntityHostname):
		e.Identity.Hostname = &model.HostnameIdentity{Hostname: x.Hostname}
	case string(model.EntityIPAddress):
		a, _ := netip.ParseAddr(x.Address)
		e.Identity.IPAddress = &model.IPAddressIdentity{Address: a}
	case string(model.EntitySocketEndpoint), string(model.EntityUpstreamEndpoint):
		ep := endpointModel(x.Endpoint)
		e.Identity.Endpoint = &ep
	case string(model.EntityTLSPeer):
		e.Identity.TLSPeer = &model.TLSPeerIdentity{Fingerprint: x.Fingerprint}
	case string(model.EntityHTTPExchange):
		e.Identity.HTTPExchange = &model.HTTPExchangeIdentity{Ordinal: x.Ordinal}
	case string(model.EntityProxyInstance), string(model.EntityProxyRoute):
		e.Identity.Opaque = &model.OpaqueEntityIdentity{SyntheticID: x.SyntheticID}
	case string(model.EntityListener):
		epe := endpointModel(x.Endpoint)
		e.Identity.Listener = &model.ListenerIdentity{Endpoint: epe}
	case string(model.EntityProcess):
		e.Identity.Process = &model.ProcessIdentity{PID: x.PID}
	case string(model.EntityContainer):
		e.Identity.Container = &model.ContainerIdentity{RuntimeID: x.RuntimeID, ContainerID: x.ContainerID}
	case string(model.EntityNetworkNamespace):
		e.Identity.Namespace = &model.NamespaceIdentity{NamespaceInode: x.NamespaceInode}
	default:
		addDecodeIssue(is, model.CodeUnknownUnionKind, "/entities/identity/kind", "unknown entity identity")
	}
	return e
}
func servicePathModel(w wServicePath, is *model.ValidationIssues) model.ServicePath {
	p := model.ServicePath{Nodes: make([]model.PathNode, len(w.Nodes)), Edges: make([]model.PathEdge, len(w.Edges)), Branches: make([]model.Branch, len(w.Branches))}
	for i, x := range w.Nodes {
		p.Nodes[i] = model.PathNode{EntityID: model.EntityID(x.EntityID)}
	}
	for i, x := range w.Edges {
		p.Edges[i] = model.PathEdge{EdgeID: model.EdgeID(x.EdgeID), From: model.EntityID(x.From), To: model.EntityID(x.To), Relation: model.PathRelation(x.Relation), Provenance: model.PathProvenance(x.Provenance), EvidenceRefs: refsModel(x.EvidenceRefs, is)}
	}
	for i, x := range w.Branches {
		p.Branches[i] = model.Branch{BranchID: model.BranchID(x.BranchID), OrderedEdgeIDs: make([]model.EdgeID, len(x.OrderedEdgeIDs)), Goal: model.GoalKind(x.Goal)}
		for j, id := range x.OrderedEdgeIDs {
			p.Branches[i].OrderedEdgeIDs[j] = model.EdgeID(id)
		}
		if x.ParentBranchID != nil {
			b := model.BranchID(*x.ParentBranchID)
			p.Branches[i].ParentBranchID = &b
		}
	}
	return p
}
func refsModel(v []wEvidenceRef, is *model.ValidationIssues) []model.EvidenceRef {
	r := make([]model.EvidenceRef, len(v))
	for i, x := range v {
		switch x.Kind {
		case string(model.EvidenceKindObservation):
			r[i] = model.ObservationRef(model.ObservationID(x.ID))
		case string(model.EvidenceKindClaim):
			r[i] = model.ClaimRef(model.ClaimID(x.ID))
		case string(model.EvidenceKindVisibility):
			r[i] = model.VisibilityRef(model.VisibilityID(x.ID))
		case string(model.EvidenceKindAssertion):
			r[i] = model.AssertionRef(model.AssertionID(x.ID))
		default:
			addDecodeIssue(is, model.CodeUnknownEnumValue, "/evidence_refs/kind", "unknown evidence kind")
		}
	}
	return r
}
func assertionModel(w wAssertion, is *model.ValidationIssues) model.OperatorAssertion {
	a := model.OperatorAssertion{AssertionID: model.AssertionID(w.AssertionID), Kind: model.AssertionKind(w.Kind), EstablishedAt: parseTime(w.EstablishedAt, "/operator_assertions/established_at", is), Source: model.AssertionSource(w.Source)}
	a.Parameters = model.AssertionParameters{Kind: model.AssertionKind(w.Parameters.Kind)}
	p := w.Parameters
	switch p.Kind {
	case string(model.AssertionLocalOriginParticipation):
		a.Parameters.LocalOrigin = &model.LocalOriginParticipation{URLTargetEntityID: model.EntityID(p.URLTargetEntityID), HostVantageID: model.VantageID(p.HostVantageID)}
	case string(model.AssertionExpectedPathEdge):
		a.Parameters.ExpectedPath = &model.ExpectedPathEdge{FromEntityID: model.EntityID(p.FromEntityID), ToEntityID: model.EntityID(p.ToEntityID), Relation: model.PathRelation(p.Relation)}
	case string(model.AssertionHTTPExpectation):
		a.Parameters.HTTP = &model.HTTPExpectation{ExpectationKind: model.ExpectationKind(p.ExpectationKind), StatusMin: p.StatusMin, StatusMax: p.StatusMax, HeaderName: p.HeaderName}
	case string(model.AssertionConfigSourceSelection):
		a.Parameters.ConfigSource = &model.ConfigSourceSelection{ComponentKind: model.ComponentKind(p.ComponentKind), SourceKind: model.ConfigSourceKind(p.SourceKind)}
	case string(model.AssertionPrivateRedirectTransitionAllowed):
		a.Parameters.PrivateRedirect = &model.PrivateRedirectTransitionAllowed{FromAddressScope: p.FromAddressScope, ToAddressScope: p.ToAddressScope}
	default:
		addDecodeIssue(is, model.CodeUnknownUnionKind, "/operator_assertions/parameters/kind", "unknown assertion payload")
	}
	return a
}
func checkDefinitionModel(w wCheckDefinition, is *model.ValidationIssues) model.CheckDefinition {
	v, _ := model.ParseSchemaVersion(w.Version)
	c := model.CheckDefinition{CheckID: model.CheckID(w.CheckID), Kind: model.CheckKind(w.Kind), Version: v, Inputs: model.CheckInputs{Kind: model.CheckInputKind(w.Inputs.Kind), SubjectEntityID: model.EntityID(w.Inputs.SubjectEntityID)}, DependencyCheckIDs: make([]model.CheckID, len(w.DependencyCheckIDs)), RequiredCapabilityIDs: make([]model.CapabilityID, len(w.RequiredCapabilityIDs)), ExecutionPolicy: model.ExecutionPolicy{DeadlineNS: w.ExecutionPolicy.DeadlineNS, DependencyFailureReasonCode: w.ExecutionPolicy.DependencyFailureReasonCode, DeadlineIsExpectedCondition: w.ExecutionPolicy.DeadlineIsExpectedCondition}, ExpectedCondition: model.ExpectedCondition{Kind: model.ExpectedConditionKind(w.ExpectedCondition.Kind), Result: w.ExpectedCondition.Result, Port: w.ExpectedCondition.Port, Hostname: w.ExpectedCondition.Hostname, StatusMin: w.ExpectedCondition.StatusMin, StatusMax: w.ExpectedCondition.StatusMax}}
	for i, x := range w.DependencyCheckIDs {
		c.DependencyCheckIDs[i] = model.CheckID(x)
	}
	for i, x := range w.RequiredCapabilityIDs {
		c.RequiredCapabilityIDs[i] = model.CapabilityID(x)
	}
	if w.Inputs.VantageID != nil {
		x := model.VantageID(*w.Inputs.VantageID)
		c.Inputs.VantageID = &x
	}
	if w.Inputs.AssertionID != nil {
		x := model.AssertionID(*w.Inputs.AssertionID)
		c.Inputs.AssertionID = &x
	}
	if w.ExpectedCondition.AddressFamily != nil {
		x := model.AddressFamily(*w.ExpectedCondition.AddressFamily)
		c.ExpectedCondition.AddressFamily = &x
	}
	if w.ExpectedCondition.MatcherResult != nil {
		x := model.MatcherResult(*w.ExpectedCondition.MatcherResult)
		c.ExpectedCondition.MatcherResult = &x
	}
	if w.ExpectedCondition.CapabilityState != nil {
		x := model.CapabilityState(*w.ExpectedCondition.CapabilityState)
		c.ExpectedCondition.CapabilityState = &x
	}
	return c
}
func checkExecutionModel(w wCheckExecution, is *model.ValidationIssues) model.CheckExecution {
	c := model.CheckExecution{ExecutionID: model.ExecutionID(w.ExecutionID), CheckID: model.CheckID(w.CheckID), Lifecycle: model.CheckLifecycle(w.Lifecycle), Verdict: model.CheckVerdict(w.Verdict), ObservationIDs: make([]model.ObservationID, len(w.ObservationIDs)), VisibilityAssessmentIDs: make([]model.VisibilityID, len(w.VisibilityAssessmentIDs))}
	for i, x := range w.ObservationIDs {
		c.ObservationIDs[i] = model.ObservationID(x)
	}
	for i, x := range w.VisibilityAssessmentIDs {
		c.VisibilityAssessmentIDs[i] = model.VisibilityID(x)
	}
	if w.BranchID != nil {
		x := model.BranchID(*w.BranchID)
		c.BranchID = &x
	}
	if w.VantageID != nil {
		x := model.VantageID(*w.VantageID)
		c.VantageID = &x
	}
	if w.ReasonCode != nil {
		c.ReasonCode = w.ReasonCode
	}
	if w.StartedAt != nil {
		x := parseTime(*w.StartedAt, "/check_executions/started_at", is)
		c.StartedAt = &x
	}
	if w.FinishedAt != nil {
		x := parseTime(*w.FinishedAt, "/check_executions/finished_at", is)
		c.FinishedAt = &x
	}
	return c
}
func observationModel(w wObservation, is *model.ValidationIssues) model.Observation {
	o := model.Observation{ObservationID: model.ObservationID(w.ObservationID), Kind: model.ObservationKind(w.Kind), SubjectEntityIDs: make([]model.EntityID, len(w.SubjectEntityIDs)), ObservedAt: parseTime(w.ObservedAt, "/observations/observed_at", is), AcquisitionMethod: model.AcquisitionMethod(w.AcquisitionMethod), SourceComponent: model.SourceComponent(w.SourceComponent), Sensitivity: model.Sensitivity(w.Sensitivity), Limitations: make([]model.Limitation, len(w.Limitations))}
	for i, x := range w.SubjectEntityIDs {
		o.SubjectEntityIDs[i] = model.EntityID(x)
	}
	for i, x := range w.Limitations {
		o.Limitations[i] = limitationModel(x, is)
	}
	if w.VantageID != nil {
		x := model.VantageID(*w.VantageID)
		o.VantageID = &x
	}
	o.Payload = payloadModel(w.Payload, is)
	return o
}
func payloadModel(w wPayload, is *model.ValidationIssues) model.ObservationPayload {
	p := model.ObservationPayload{Kind: model.ObservationKind(w.Kind)}
	switch w.Kind {
	case string(model.ObservationSystemResolution):
		p.Resolution = &model.SystemResolutionResult{HostnameEntityID: model.EntityID(w.HostnameEntityID), AddressFamily: model.AddressFamily(w.AddressFamily), Result: model.ResolutionResult(w.Result)}
		if w.AddressEntityID != nil {
			x := model.EntityID(*w.AddressEntityID)
			p.Resolution.AddressEntityID = &x
		}
	case string(model.ObservationTCPConnection):
		p.TCP = &model.TCPConnectionResult{EndpointEntityID: model.EntityID(w.EndpointEntityID), Result: model.TCPResult(w.Result), DurationNS: w.DurationNS, DeadlinePartOfExpectedCondition: w.DeadlinePartOfExpectedCondition}
	case string(model.ObservationTLSTransport):
		p.TLSTransport = &model.TLSTransportResultPayload{PeerEntityID: model.EntityID(w.PeerEntityID), Result: model.TLSTransportResult(w.Result), ProtocolVersion: w.ProtocolVersion, CipherSuite: w.CipherSuite, NegotiatedALPN: w.NegotiatedALPN, SNISent: w.SNISent, AlertCode: w.AlertCode, DurationNS: w.DurationNS}
	case string(model.ObservationTLSPeer):
		p.TLSPeer = &model.TLSPeerSummary{PeerEntityID: model.EntityID(w.PeerEntityID), CertificateCount: w.CertificateCount, LeafSHA256: w.LeafSHA256, NotBefore: parseTime(w.NotBefore, "/observations/payload/not_before", is), NotAfter: parseTime(w.NotAfter, "/observations/payload/not_after", is), SANType: model.SANType(w.SANType), SANCount: w.SANCount}
	case string(model.ObservationCertificateVerification):
		p.CertificateVerification = &model.CertificateVerificationResultPayload{PeerEntityID: model.EntityID(w.PeerEntityID), VerifiedHostname: w.VerifiedHostname, VerificationTime: parseTime(w.VerificationTime, "/observations/payload/verification_time", is), TrustSource: model.TrustSource(w.TrustSource), Result: model.CertificateVerificationResult(w.Result)}
		if w.FailureReason != nil {
			x := model.CertificateVerificationResult(*w.FailureReason)
			p.CertificateVerification.FailureReason = &x
		}
	case string(model.ObservationHTTP):
		p.HTTP = &model.HTTPResult{ExchangeEntityID: model.EntityID(w.ExchangeEntityID), ResultKind: model.HTTPResultKind(w.ResultKind), StatusCode: w.StatusCode}
		if w.RedirectTargetEntityID != nil {
			x := model.EntityID(*w.RedirectTargetEntityID)
			p.HTTP.RedirectTargetEntityID = &x
		}
		if w.RedirectTarget != nil {
			x := targetModel(*w.RedirectTarget, is)
			p.HTTP.RedirectTarget = &x
		}
	case string(model.ObservationActiveProxyRoute), string(model.ObservationConfiguredProxyRoute):
		v := &model.ProxyRouteSummary{ProxyRouteEntityID: model.EntityID(w.ProxyRouteEntityID), MatcherKind: w.MatcherKind, MatchResult: model.MatcherResult(w.MatchResult)}
		if w.UpstreamEntityID != nil {
			x := model.EntityID(*w.UpstreamEntityID)
			v.UpstreamEntityID = &x
		}
		if w.Kind == string(model.ObservationActiveProxyRoute) {
			p.ActiveProxyRoute = v
		} else {
			p.ConfiguredProxyRoute = v
		}
	case string(model.ObservationUpstreamSelection):
		v := &model.UpstreamSelectionSummary{ProxyRouteEntityID: model.EntityID(w.ProxyRouteEntityID), Result: model.UpstreamResult(w.Result)}
		if w.UpstreamEntityID != nil {
			x := model.EntityID(*w.UpstreamEntityID)
			v.UpstreamEntityID = &x
		}
		p.UpstreamSelection = v
	case string(model.ObservationListenerInventory):
		p.Listener = &model.ListenerInventoryEntry{ListenerEntityID: model.EntityID(w.ListenerEntityID), NamespaceEntityID: model.EntityID(w.NamespaceEntityID), Protocol: model.Transport(w.Protocol), AddressFamily: model.AddressFamily(w.AddressFamily), BindSemantics: model.BindSemantics(w.BindSemantics), Port: w.Port}
	case string(model.ObservationProcessOwnership):
		p.ProcessOwnership = &model.ProcessOwnershipEntry{ListenerEntityID: model.EntityID(w.ListenerEntityID), Result: model.OwnershipResult(w.Result)}
		if w.ProcessEntityID != nil {
			x := model.EntityID(*w.ProcessEntityID)
			p.ProcessOwnership.ProcessEntityID = &x
		}
	case string(model.ObservationDockerRuntime):
		p.Docker = &model.DockerRuntimeSummary{FactKind: model.DockerFactKind(w.FactKind), ContainerEntityID: model.EntityID(w.ContainerEntityID), RuntimeState: model.RuntimeState(w.RuntimeState)}
		if w.NamespaceEntityID != "" {
			x := model.EntityID(w.NamespaceEntityID)
			p.Docker.NamespaceEntityID = &x
		}
		if w.EndpointEntityID != "" {
			x := model.EntityID(w.EndpointEntityID)
			p.Docker.EndpointEntityID = &x
		}
	case string(model.ObservationCapabilityPermission):
		p.Capability = &model.CapabilityPermissionResult{CapabilityID: model.CapabilityID(w.CapabilityID), Result: model.CapabilityState(w.Result), ReasonCode: w.ReasonCode}
	default:
		addDecodeIssue(is, model.CodeUnknownUnionKind, "/observations/payload/kind", "unknown observation payload")
	}
	return p
}
func visibilityModel(w wVisibility, is *model.ValidationIssues) model.VisibilityAssessment {
	v := model.VisibilityAssessment{VisibilityID: model.VisibilityID(w.VisibilityID), SubjectKind: model.VisibilitySubjectKind(w.SubjectKind), VantageID: model.VantageID(w.VantageID), Scope: model.VisibilityScope{Kind: w.Scope.Kind, Listener: &model.ListenerVisibilityScope{NamespaceEntityID: model.EntityID(w.Scope.NamespaceEntityID), Protocol: model.Transport(w.Scope.Protocol), AddressFamily: model.AddressFamily(w.Scope.AddressFamily), BindSemantics: model.BindSemantics(w.Scope.BindSemantics), PortStart: w.Scope.PortStart, PortEnd: w.Scope.PortEnd, ProcessOwnershipRequired: w.Scope.ProcessOwnershipRequired}}, Level: model.VisibilityLevel(w.Level), BasisObservationIDs: make([]model.ObservationID, len(w.BasisObservationIDs)), Limitations: make([]model.Limitation, len(w.Limitations)), AssessedAt: parseTime(w.AssessedAt, "/visibility_assessments/assessed_at", is)}
	for i, x := range w.BasisObservationIDs {
		v.BasisObservationIDs[i] = model.ObservationID(x)
	}
	for i, x := range w.Limitations {
		v.Limitations[i] = limitationModel(x, is)
	}
	return v
}
func claimModel(w wClaim, is *model.ValidationIssues) model.Claim {
	c := model.Claim{ClaimID: model.ClaimID(w.ClaimID), StatementCode: model.ClaimStatementCode(w.StatementCode), Level: model.ClaimLevel(w.Level), SubjectEntityIDs: make([]model.EntityID, len(w.SubjectEntityIDs)), BranchIDs: make([]model.BranchID, len(w.BranchIDs)), Parameters: claimParamsModel(w.Parameters, is), SupportingEvidence: refsModel(w.SupportingEvidence, is), ContradictingEvidence: refsModel(w.ContradictingEvidence, is), RequiredMissingEvidence: make([]model.MissingEvidenceRequirement, len(w.RequiredMissingEvidence)), RuleID: model.RuleID(w.RuleID)}
	for i, x := range w.SubjectEntityIDs {
		c.SubjectEntityIDs[i] = model.EntityID(x)
	}
	for i, x := range w.BranchIDs {
		c.BranchIDs[i] = model.BranchID(x)
	}
	for i, x := range w.RequiredMissingEvidence {
		c.RequiredMissingEvidence[i] = missingModel(x, is)
	}
	return c
}
func claimParamsModel(w wClaimParams, is *model.ValidationIssues) model.ClaimParameters {
	p := model.ClaimParameters{Kind: model.ClaimStatementCode(w.Kind)}
	switch w.Kind {
	case string(model.StatementTLSCertificateHostnameMismatch):
		p.HostnameMismatch = &model.HostnameMismatchClaimParameters{PeerEntityID: model.EntityID(w.PeerEntityID), Hostname: w.Hostname, VerificationTime: parseTime(w.VerificationTime, "/claims/parameters/verification_time", is), TrustSource: model.TrustSource(w.TrustSource)}
	case string(model.StatementTCPConnectionRefused):
		p.TCPRefused = &model.TCPRefusedClaimParameters{EndpointEntityID: model.EntityID(w.EndpointEntityID), VantageID: model.VantageID(w.VantageID), ObservedAt: parseTime(w.ObservedAt, "/claims/parameters/observed_at", is)}
	case string(model.StatementNoMatchingListenerVisible):
		p.ListenerAbsent = &model.ListenerAbsentClaimParameters{NamespaceEntityID: model.EntityID(w.NamespaceEntityID), VantageID: model.VantageID(w.VantageID), Protocol: model.Transport(w.Protocol), AddressFamily: model.AddressFamily(w.AddressFamily), BindSemantics: model.BindSemantics(w.BindSemantics), Port: w.Port}
	default:
		addDecodeIssue(is, model.CodeUnknownUnionKind, "/claims/parameters/kind", "unknown claim parameters")
	}
	return p
}
func missingModel(w wMissing, is *model.ValidationIssues) model.MissingEvidenceRequirement {
	m := model.MissingEvidenceRequirement{Kind: model.MissingEvidenceKind(w.Kind)}
	if w.ObservationKind != nil {
		x := model.ObservationKind(*w.ObservationKind)
		m.ObservationKind = &x
	}
	if w.VisibilitySubjectKind != nil {
		x := model.VisibilitySubjectKind(*w.VisibilitySubjectKind)
		m.VisibilitySubjectKind = &x
	}
	if w.VisibilityScope != nil {
		x := visibilityScopeModel(*w.VisibilityScope)
		m.VisibilityScope = &x
	}
	if w.VantageID != nil {
		x := model.VantageID(*w.VantageID)
		m.VantageID = &x
	}
	return m
}
func visibilityScopeModel(w wVisibilityScope) model.VisibilityScope {
	return model.VisibilityScope{Kind: w.Kind, Listener: &model.ListenerVisibilityScope{NamespaceEntityID: model.EntityID(w.NamespaceEntityID), Protocol: model.Transport(w.Protocol), AddressFamily: model.AddressFamily(w.AddressFamily), BindSemantics: model.BindSemantics(w.BindSemantics), PortStart: w.PortStart, PortEnd: w.PortEnd, ProcessOwnershipRequired: w.ProcessOwnershipRequired}}
}
func findingModel(w wFinding, is *model.ValidationIssues) model.Finding {
	f := model.Finding{FindingID: model.FindingID(w.FindingID), Kind: model.FindingKind(w.Kind), TitleCode: model.FindingTitleCode(w.TitleCode), Level: model.ClaimLevel(w.Level), BranchIDs: make([]model.BranchID, len(w.BranchIDs)), PathPositions: make([]model.PathPosition, len(w.PathPositions)), ClaimIDs: make([]model.ClaimID, len(w.ClaimIDs)), RuleID: model.RuleID(w.RuleID), Limitations: make([]model.Limitation, len(w.Limitations)), SuggestedExperiments: append([]string{}, w.SuggestedExperiments...), Selection: model.Selection(w.Selection)}
	for i, x := range w.BranchIDs {
		f.BranchIDs[i] = model.BranchID(x)
	}
	for i, x := range w.PathPositions {
		f.PathPositions[i] = model.PathPosition{BranchID: model.BranchID(x.BranchID), Position: x.Position}
	}
	for i, x := range w.ClaimIDs {
		f.ClaimIDs[i] = model.ClaimID(x)
	}
	for i, x := range w.Limitations {
		f.Limitations[i] = limitationModel(x, is)
	}
	return f
}
