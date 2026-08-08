package model

import (
	"fmt"
	"time"
)

type ValidatedEvidenceRun struct{ run EvidenceRun }

func (v ValidatedEvidenceRun) Value() EvidenceRun { return v.run }

func ValidateEvidenceRun(r EvidenceRun) (ValidatedEvidenceRun, ValidationIssues) {
	var is ValidationIssues
	add := func(c ValidationCode, p, m string) { is = append(is, ValidationIssue{Code: c, Pointer: p, Message: m}) }
	if r.ReportSchemaVersion.Major != 1 {
		add(CodeInvalidValue, "/report_schema_version", "unsupported schema major")
	}
	if !r.RunID.Valid() {
		add(CodeInvalidValue, "/run_id", "invalid run ID")
	}
	if err := ValidateScalar(r.Producer.Name); err != nil {
		add(CodeSensitiveDisallowedField, "/producer/name", err.Error())
	}
	if err := ValidateScalar(r.Producer.Version); err != nil {
		add(CodeSensitiveDisallowedField, "/producer/version", err.Error())
	}
	if err := ValidateScalar(r.Producer.Build); err != nil {
		add(CodeSensitiveDisallowedField, "/producer/build", err.Error())
	}
	if err := validateTarget(r.Target); err != nil {
		add(CodeSensitiveDisallowedField, "/target", err.Error())
	}
	if !r.Goal.Kind.Valid() {
		add(CodeInvalidValue, "/goal/kind", "unknown goal")
	}
	if r.Goal.ExpectationAssertionID != nil && !r.Goal.ExpectationAssertionID.Valid() {
		add(CodeInvalidValue, "/goal/expectation_assertion_id", "invalid assertion ID")
	}
	if !r.RequestedScope.Kind.Valid() {
		add(CodeInvalidValue, "/requested_scope/kind", "unknown scope")
	}
	if r.Policy.CoherenceWindowNS < 0 {
		add(CodeInvalidValue, "/policy/coherence_window_ns", "duration must be non-negative")
	}
	validateTimes(&is, r.StartedAt, r.FinishedAt, "/started_at", "/finished_at")
	if r.VantagePoints == nil {
		add(CodeMissingRequiredField, "/vantage_points", "required collection must be present")
	}
	if r.Capabilities == nil {
		add(CodeMissingRequiredField, "/capabilities", "required collection must be present")
	}
	if r.OperatorAssertions == nil {
		add(CodeMissingRequiredField, "/operator_assertions", "required collection must be present")
	}
	if r.Entities == nil {
		add(CodeMissingRequiredField, "/entities", "required collection must be present")
	}
	if r.ServicePath.Nodes == nil {
		add(CodeMissingRequiredField, "/service_path/nodes", "required collection must be present")
	}
	if r.ServicePath.Edges == nil {
		add(CodeMissingRequiredField, "/service_path/edges", "required collection must be present")
	}
	if r.ServicePath.Branches == nil {
		add(CodeMissingRequiredField, "/service_path/branches", "required collection must be present")
	}
	if r.CheckDefinitions == nil {
		add(CodeMissingRequiredField, "/check_definitions", "required collection must be present")
	}
	if r.CheckExecutions == nil {
		add(CodeMissingRequiredField, "/check_executions", "required collection must be present")
	}
	if r.Observations == nil {
		add(CodeMissingRequiredField, "/observations", "required collection must be present")
	}
	if r.VisibilityAssessments == nil {
		add(CodeMissingRequiredField, "/visibility_assessments", "required collection must be present")
	}
	if r.Limitations == nil {
		add(CodeMissingRequiredField, "/limitations", "required collection must be present")
	}
	vantageIDs := map[VantageID]bool{}
	for i, v := range r.VantagePoints {
		p := fmt.Sprintf("/vantage_points/%d", i)
		if !v.VantageID.Valid() {
			add(CodeInvalidValue, p+"/vantage_id", "invalid vantage ID")
		}
		if vantageIDs[v.VantageID] {
			add(CodeDuplicateID, p+"/vantage_id", "duplicate vantage ID")
		}
		vantageIDs[v.VantageID] = true
		validateVantage(&is, v, p)
	}
	capIDs := map[CapabilityID]bool{}
	for i, v := range r.Capabilities {
		p := fmt.Sprintf("/capabilities/%d", i)
		if !v.CapabilityID.Valid() {
			add(CodeInvalidValue, p+"/capability_id", "invalid capability ID")
		}
		if capIDs[v.CapabilityID] {
			add(CodeDuplicateID, p+"/capability_id", "duplicate capability ID")
		}
		capIDs[v.CapabilityID] = true
		if !v.Kind.Valid() {
			add(CodeInvalidValue, p+"/kind", "unknown capability")
		}
		if !v.State.Valid() {
			add(CodeUnknownEnumValue, p+"/state", "unknown capability state")
		}
		if err := validateReasonCode(v.ReasonCode); err != nil {
			add(CodeSensitiveDisallowedField, p+"/reason_code", err.Error())
		}
	}
	assertionIDs := map[AssertionID]bool{}
	for i, a := range r.OperatorAssertions {
		p := fmt.Sprintf("/operator_assertions/%d", i)
		if !a.AssertionID.Valid() {
			add(CodeInvalidValue, p+"/assertion_id", "invalid assertion ID")
		}
		if assertionIDs[a.AssertionID] {
			add(CodeDuplicateID, p+"/assertion_id", "duplicate assertion ID")
		}
		assertionIDs[a.AssertionID] = true
		validateAssertion(&is, a, p)
	}
	entityIDs := map[EntityID]bool{}
	entityValues := map[EntityID]Entity{}
	for i, e := range r.Entities {
		p := fmt.Sprintf("/entities/%d", i)
		if !e.EntityID.Valid() {
			add(CodeInvalidValue, p+"/entity_id", "invalid entity ID")
		}
		if entityIDs[e.EntityID] {
			add(CodeDuplicateID, p+"/entity_id", "duplicate entity ID")
		}
		entityIDs[e.EntityID] = true
		entityValues[e.EntityID] = e
		validateEntity(&is, e, p)
	}
	validatePath(&is, r.ServicePath, entityIDs, assertionIDs, r.Observations, prefix("/service_path"))
	checkIDs := map[CheckID]bool{}
	for i, c := range r.CheckDefinitions {
		p := fmt.Sprintf("/check_definitions/%d", i)
		if !c.CheckID.Valid() {
			add(CodeInvalidValue, p+"/check_id", "invalid check ID")
		}
		if checkIDs[c.CheckID] {
			add(CodeDuplicateID, p+"/check_id", "duplicate check ID")
		}
		checkIDs[c.CheckID] = true
		validateCheckDefinition(&is, c, p, entityIDs, vantageIDs, assertionIDs, capIDs)
	}
	validateCheckDAG(&is, r.CheckDefinitions)
	executionIDs := map[ExecutionID]bool{}
	for i, e := range r.CheckExecutions {
		p := fmt.Sprintf("/check_executions/%d", i)
		if !e.ExecutionID.Valid() {
			add(CodeInvalidValue, p+"/execution_id", "invalid execution ID")
		}
		if executionIDs[e.ExecutionID] {
			add(CodeDuplicateID, p+"/execution_id", "duplicate execution ID")
		}
		executionIDs[e.ExecutionID] = true
		if !checkIDs[e.CheckID] {
			add(CodeReferenceMissing, p+"/check_id", "check does not exist")
		}
		validateExecution(&is, e, p, entityIDs, vantageIDs, checkIDs, r.Observations, r.VisibilityAssessments)
	}
	observationIDs := map[ObservationID]bool{}
	for i, o := range r.Observations {
		p := fmt.Sprintf("/observations/%d", i)
		if !o.ObservationID.Valid() {
			add(CodeInvalidValue, p+"/observation_id", "invalid observation ID")
		}
		if observationIDs[o.ObservationID] {
			add(CodeDuplicateID, p+"/observation_id", "duplicate observation ID")
		}
		observationIDs[o.ObservationID] = true
		validateObservation(&is, o, p, entityIDs, vantageIDs)
		if o.Kind == ObservationListenerInventoryResult && o.Payload.ListenerInventoryResult != nil {
			result := o.Payload.ListenerInventoryResult
			if entity, ok := entityValues[result.NamespaceEntityID]; !ok || entity.Kind != EntityNetworkNamespace || entity.Identity.Namespace == nil {
				add(CodeReferenceMissing, p+"/payload/namespace_entity_id", "listener inventory result namespace must be a network namespace")
			} else if o.VantageID != nil {
				var vantage *VantagePoint
				for i := range r.VantagePoints {
					if r.VantagePoints[i].VantageID == *o.VantageID {
						vantage = &r.VantagePoints[i]
						break
					}
				}
				if vantage == nil || vantage.Kind != VantageKindHostNamespace || vantage.Identity.HostNamespace == nil || vantage.Identity.HostNamespace.NamespaceInode != entity.Identity.Namespace.NamespaceInode {
					add(CodeVantageMismatch, p+"/payload/namespace_entity_id", "listener inventory result namespace does not correspond to vantage")
				}
			}
		}
	}
	visibilityIDs := map[VisibilityID]bool{}
	for i, v := range r.VisibilityAssessments {
		p := fmt.Sprintf("/visibility_assessments/%d", i)
		if !v.VisibilityID.Valid() {
			add(CodeInvalidValue, p+"/visibility_id", "invalid visibility ID")
		}
		if visibilityIDs[v.VisibilityID] {
			add(CodeDuplicateID, p+"/visibility_id", "duplicate visibility ID")
		}
		visibilityIDs[v.VisibilityID] = true
		validateVisibility(&is, v, p, entityIDs, vantageIDs, observationIDs, r.Observations, r)
	}
	limitationIDs := map[LimitationID]bool{}
	for i, l := range r.Limitations {
		p := fmt.Sprintf("/limitations/%d", i)
		if !l.LimitationID.Valid() {
			add(CodeInvalidValue, p+"/limitation_id", "invalid limitation ID")
		}
		if limitationIDs[l.LimitationID] {
			add(CodeDuplicateID, p+"/limitation_id", "duplicate limitation ID")
		}
		limitationIDs[l.LimitationID] = true
		validateLimitation(&is, l, p)
	}
	SortValidationIssues(is)
	if len(is) != 0 {
		return ValidatedEvidenceRun{}, is
	}
	return ValidatedEvidenceRun{run: r}, is
}

func CanonicalizeAndValidateEvidenceRun(r EvidenceRun) (ValidatedEvidenceRun, ValidationIssues) {
	c, issues := CanonicalizeEvidence(r)
	if len(issues) > 0 {
		return ValidatedEvidenceRun{}, issues
	}
	v, more := ValidateEvidenceRun(c)
	return v, more
}
func addIssue(is *ValidationIssues, c ValidationCode, p, m string) {
	*is = append(*is, ValidationIssue{Code: c, Pointer: p, Message: m})
}
func prefix(s string) string { return s }
func validateTimes(is *ValidationIssues, start, finish time.Time, sp, fp string) {
	if start.IsZero() {
		addIssue(is, CodeMissingRequiredField, sp, "time is required")
	}
	if finish.IsZero() {
		addIssue(is, CodeMissingRequiredField, fp, "time is required")
	}
	if !start.IsZero() && start.Location() != time.UTC {
		addIssue(is, CodeInvalidValue, sp, "timestamp must be UTC")
	}
	if !finish.IsZero() && finish.Location() != time.UTC {
		addIssue(is, CodeInvalidValue, fp, "timestamp must be UTC")
	}
	if !start.IsZero() && !finish.IsZero() && finish.Before(start) {
		addIssue(is, CodeInvalidValue, fp, "finished time precedes started time")
	}
}
func validateTarget(t Target) error {
	if t.Scheme != "http" && t.Scheme != "https" {
		return fmt.Errorf("invalid scheme")
	}
	if err := validateHostname(t.Hostname); err != nil {
		return err
	}
	if t.EffectivePort == 0 {
		return fmt.Errorf("effective port required")
	}
	if !t.Path.Present && t.Path.IsRoot {
		return fmt.Errorf("root path must be present")
	}
	if t.Path.IsRoot && t.Path.SegmentCount != 0 {
		return fmt.Errorf("root path has segments")
	}
	if !t.Path.Present && (t.Path.SegmentCount != 0 || t.Path.TrailingSlash || t.Path.QueryPresent) {
		return fmt.Errorf("absent path has details")
	}
	return nil
}
func validateVantage(is *ValidationIssues, v VantagePoint, p string) {
	if !v.Kind.Valid() {
		addIssue(is, CodeUnknownEnumValue, p+"/kind", "unknown vantage kind")
	}
	if !v.Role.Valid() {
		addIssue(is, CodeUnknownEnumValue, p+"/role", "unknown vantage role")
	}
	if !v.Establishment.Valid() {
		addIssue(is, CodeUnknownEnumValue, p+"/establishment", "unknown establishment")
	}
	if err := validateDisplayLabel(v.DisplayLabel); err != nil {
		addIssue(is, CodeSensitiveDisallowedField, p+"/display_label", err.Error())
	}
	if v.Limitations == nil {
		addIssue(is, CodeMissingRequiredField, p+"/limitations", "required collection must be present")
	}
	count := 0
	if v.Identity.ClientNetwork != nil {
		count++
	}
	if v.Identity.HostNamespace != nil {
		count++
	}
	if v.Identity.ContainerNamespace != nil {
		count++
	}
	if v.Identity.UnknownNamespace != nil {
		count++
	}
	if count != 1 || v.Identity.Kind != v.Kind {
		addIssue(is, CodeInvalidValue, p+"/identity", "identity discriminant does not match vantage")
	}
	if v.Kind == VantageKindClientNetwork && v.Identity.ClientNetwork != nil {
		if err := validateDisplayLabel(v.Identity.ClientNetwork.Label); err != nil {
			addIssue(is, CodeSensitiveDisallowedField, p+"/identity/label", err.Error())
		}
	}
	if v.Kind == VantageKindHostNamespace && v.Identity.HostNamespace != nil && v.Identity.HostNamespace.NamespaceInode == 0 {
		addIssue(is, CodeInvalidValue, p+"/identity/namespace_inode", "inode required")
	}
	if v.Kind == VantageKindContainerNamespace && v.Identity.ContainerNamespace != nil {
		if err := validateSafeIdentifier(v.Identity.ContainerNamespace.DaemonID); err != nil {
			addIssue(is, CodeSensitiveDisallowedField, p+"/identity/daemon_id", err.Error())
		}
		if err := validateSafeIdentifier(v.Identity.ContainerNamespace.ContainerID); err != nil {
			addIssue(is, CodeSensitiveDisallowedField, p+"/identity/container_id", err.Error())
		}
	}
	if v.Kind == VantageKindUnknownNamespace && v.Identity.UnknownNamespace != nil {
		if err := validateReasonCode(v.Identity.UnknownNamespace.ReasonCode); err != nil {
			addIssue(is, CodeSensitiveDisallowedField, p+"/identity/reason_code", err.Error())
		}
	}
}
func validateAssertion(is *ValidationIssues, a OperatorAssertion, p string) {
	if !a.Kind.Valid() {
		addIssue(is, CodeUnknownUnionKind, p+"/kind", "unknown assertion kind")
	}
	if !a.Source.Valid() {
		addIssue(is, CodeInvalidAssertionSource, p+"/source", "invalid assertion source")
	}
	if a.EstablishedAt.IsZero() || a.EstablishedAt.Location() != time.UTC {
		addIssue(is, CodeInvalidValue, p+"/established_at", "assertion time must be UTC")
	}
	n := 0
	if a.Parameters.LocalOrigin != nil {
		n++
	}
	if a.Parameters.ExpectedPath != nil {
		n++
	}
	if a.Parameters.HTTP != nil {
		n++
	}
	if a.Parameters.ConfigSource != nil {
		n++
	}
	if a.Parameters.PrivateRedirect != nil {
		n++
	}
	if n != 1 || a.Parameters.Kind != a.Kind {
		addIssue(is, CodeInvalidValue, p+"/parameters", "assertion payload discriminant mismatch")
	}
	switch a.Kind {
	case AssertionLocalOriginParticipation:
		if a.Parameters.LocalOrigin == nil {
			break
		}
		if !a.Parameters.LocalOrigin.URLTargetEntityID.Valid() || !a.Parameters.LocalOrigin.HostVantageID.Valid() {
			addIssue(is, CodeInvalidValue, p+"/parameters", "invalid local origin payload")
		}
	case AssertionExpectedPathEdge:
		if a.Parameters.ExpectedPath == nil || !a.Parameters.ExpectedPath.Relation.Valid() {
			addIssue(is, CodeInvalidValue, p+"/parameters/relation", "invalid edge relation")
		}
	case AssertionHTTPExpectation:
		if a.Parameters.HTTP != nil {
			h := a.Parameters.HTTP
			if !h.ExpectationKind.Valid() {
				addIssue(is, CodeUnknownEnumValue, p+"/parameters/expectation_kind", "unknown expectation")
			}
			if h.ExpectationKind == ExpectationStatusRange && (h.StatusMin == nil || h.StatusMax == nil || *h.StatusMin > *h.StatusMax) {
				addIssue(is, CodeInvalidValue, p+"/parameters", "invalid status range")
			}
			if h.ExpectationKind == ExpectationHeaderPresent && (h.HeaderName == nil || *h.HeaderName == "") {
				addIssue(is, CodeInvalidValue, p+"/parameters/header_name", "header name required")
			}
			if h.HeaderName != nil {
				if err := validateHeaderName(*h.HeaderName); err != nil {
					addIssue(is, CodeSensitiveDisallowedField, p+"/parameters/header_name", err.Error())
				}
			}
		}
	case AssertionConfigSourceSelection:
		if a.Parameters.ConfigSource == nil || !a.Parameters.ConfigSource.ComponentKind.Valid() || !a.Parameters.ConfigSource.SourceKind.Valid() {
			addIssue(is, CodeInvalidValue, p+"/parameters", "invalid config source")
		}
	case AssertionPrivateRedirectTransitionAllowed:
		if a.Parameters.PrivateRedirect != nil {
			if err := validateSafeToken(a.Parameters.PrivateRedirect.FromAddressScope, 32); err != nil {
				addIssue(is, CodeSensitiveDisallowedField, p+"/parameters/from_address_scope", err.Error())
			}
			if err := validateSafeToken(a.Parameters.PrivateRedirect.ToAddressScope, 32); err != nil {
				addIssue(is, CodeSensitiveDisallowedField, p+"/parameters/to_address_scope", err.Error())
			}
		}
	}
}
func unionEntityCount(e EntityIdentity) int {
	n := 0
	if e.URLTarget != nil {
		n++
	}
	if e.Hostname != nil {
		n++
	}
	if e.IPAddress != nil {
		n++
	}
	if e.Endpoint != nil {
		n++
	}
	if e.TLSPeer != nil {
		n++
	}
	if e.HTTPExchange != nil {
		n++
	}
	if e.Opaque != nil {
		n++
	}
	if e.Listener != nil {
		n++
	}
	if e.Process != nil {
		n++
	}
	if e.Container != nil {
		n++
	}
	if e.Namespace != nil {
		n++
	}
	return n
}
func validateEntity(is *ValidationIssues, e Entity, p string) {
	if !e.Kind.Valid() {
		addIssue(is, CodeUnknownUnionKind, p+"/kind", "unknown entity kind")
	}
	if err := validateDisplayLabel(e.DisplayLabel); err != nil {
		addIssue(is, CodeSensitiveDisallowedField, p+"/display_label", err.Error())
	}
	if unionEntityCount(e.Identity) != 1 || e.Identity.Kind != e.Kind {
		addIssue(is, CodeInvalidValue, p+"/identity", "entity identity discriminant mismatch")
	}
	if e.Kind == EntityIPAddress && e.Identity.IPAddress != nil && !e.Identity.IPAddress.Address.IsValid() {
		addIssue(is, CodeInvalidValue, p+"/identity/address", "invalid IP address")
	}
	if (e.Kind == EntitySocketEndpoint || e.Kind == EntityUpstreamEndpoint) && e.Identity.Endpoint != nil {
		validateEndpoint(is, e.Identity.Endpoint, p+"/identity/endpoint")
	}
	if e.Kind == EntityListener && e.Identity.Listener != nil {
		validateEndpoint(is, &e.Identity.Listener.Endpoint, p+"/identity/endpoint")
	}
	if e.Kind == EntityHostname && e.Identity.Hostname != nil {
		if err := validateHostname(e.Identity.Hostname.Hostname); err != nil {
			addIssue(is, CodeSensitiveDisallowedField, p+"/identity/hostname", err.Error())
		}
	}
	if e.Kind == EntityTLSPeer && e.Identity.TLSPeer != nil {
		if err := validateFingerprint(e.Identity.TLSPeer.Fingerprint); err != nil {
			addIssue(is, CodeSensitiveDisallowedField, p+"/identity/fingerprint", err.Error())
		}
	}
	if (e.Kind == EntityProxyInstance || e.Kind == EntityProxyRoute) && e.Identity.Opaque != nil {
		if err := validateSafeIdentifier(e.Identity.Opaque.SyntheticID); err != nil {
			addIssue(is, CodeSensitiveDisallowedField, p+"/identity/synthetic_id", err.Error())
		}
	}
	if e.Kind == EntityContainer && e.Identity.Container != nil {
		if err := validateSafeIdentifier(e.Identity.Container.RuntimeID); err != nil {
			addIssue(is, CodeSensitiveDisallowedField, p+"/identity/runtime_id", err.Error())
		}
		if err := validateSafeIdentifier(e.Identity.Container.ContainerID); err != nil {
			addIssue(is, CodeSensitiveDisallowedField, p+"/identity/container_id", err.Error())
		}
	}
}
func validateEndpoint(is *ValidationIssues, e *EndpointIdentity, p string) {
	if !e.Address.IsValid() {
		addIssue(is, CodeInvalidValue, p+"/address", "invalid address")
	}
	if e.Port == 0 {
		addIssue(is, CodeInvalidValue, p+"/port", "port required")
	}
	if !e.Transport.Valid() {
		addIssue(is, CodeUnknownEnumValue, p+"/transport", "unknown transport")
	}
}
func validatePath(is *ValidationIssues, p ServicePath, entities map[EntityID]bool, assertions map[AssertionID]bool, obs []Observation, base string) {
	observations := map[ObservationID]bool{}
	for _, o := range obs {
		observations[o.ObservationID] = true
	}
	for i, n := range p.Nodes {
		q := fmt.Sprintf("%s/nodes/%d", base, i)
		if !entities[n.EntityID] {
			addIssue(is, CodeReferenceMissing, q+"/entity_id", "entity missing")
		}
	}
	edges := map[EdgeID]bool{}
	for i, e := range p.Edges {
		q := fmt.Sprintf("%s/edges/%d", base, i)
		if !e.EdgeID.Valid() {
			addIssue(is, CodeInvalidValue, q+"/edge_id", "invalid edge ID")
		}
		if edges[e.EdgeID] {
			addIssue(is, CodeDuplicateID, q+"/edge_id", "duplicate edge ID")
		}
		edges[e.EdgeID] = true
		if !entities[e.From] {
			addIssue(is, CodeReferenceMissing, q+"/from", "from entity missing")
		}
		if !entities[e.To] {
			addIssue(is, CodeReferenceMissing, q+"/to", "to entity missing")
		}
		if !e.Relation.Valid() {
			addIssue(is, CodeUnknownEnumValue, q+"/relation", "unknown relation")
		}
		if !e.Provenance.Valid() {
			addIssue(is, CodeUnknownEnumValue, q+"/provenance", "unknown provenance")
		}
		if e.EvidenceRefs == nil {
			addIssue(is, CodeMissingRequiredField, q+"/evidence_refs", "required collection")
		}
		for j, r := range e.EvidenceRefs {
			qq := fmt.Sprintf("%s/evidence_refs/%d", q, j)
			if !r.Kind.Valid() || refTargetCount(r) != 1 {
				addIssue(is, CodeReferenceKindMismatch, qq, "reference must have exactly one target")
				continue
			}
			if e.Provenance == ProvenanceOperatorAsserted {
				if r.Kind != EvidenceKindAssertion {
					addIssue(is, CodeReferenceKindMismatch, qq, "operator edge requires assertion")
					continue
				}
				if r.AssertionID == nil || !assertions[*r.AssertionID] {
					addIssue(is, CodeReferenceMissing, qq, "assertion missing")
				}
				continue
			}
			if r.Kind != EvidenceKindObservation {
				addIssue(is, CodeReferenceKindMismatch, qq, "base path edge requires observation")
				continue
			}
			if r.ObservationID == nil || !observations[*r.ObservationID] {
				addIssue(is, CodeReferenceMissing, qq, "observation missing")
			}
		}
	}
	branches := map[BranchID]bool{}
	for i, b := range p.Branches {
		q := fmt.Sprintf("%s/branches/%d", base, i)
		if !b.BranchID.Valid() {
			addIssue(is, CodeInvalidValue, q+"/branch_id", "invalid branch ID")
		}
		if branches[b.BranchID] {
			addIssue(is, CodeDuplicateID, q+"/branch_id", "duplicate branch ID")
		}
		branches[b.BranchID] = true
		if b.OrderedEdgeIDs == nil {
			addIssue(is, CodeMissingRequiredField, q+"/ordered_edge_ids", "required collection")
		}
		for _, id := range b.OrderedEdgeIDs {
			if !edges[id] {
				addIssue(is, CodeReferenceMissing, q+"/ordered_edge_ids", "edge missing")
			}
		}
	}
	for _, b := range p.Branches {
		if b.ParentBranchID != nil && !branches[*b.ParentBranchID] {
			addIssue(is, CodeReferenceMissing, "/service_path/branches", "parent branch missing")
		}
	}
}
