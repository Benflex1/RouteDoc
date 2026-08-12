package render

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"routedoc/internal/model"
)

func isClientReport(v model.ValidatedEvaluatedRun) bool {
	if strings.Contains(v.Value().Evidence.Producer.Version, "milestone1") {
		return true
	}
	for _, definition := range v.Value().Evidence.CheckDefinitions {
		if definition.Kind == model.CheckHTTP {
			return true
		}
	}
	return false
}

func reportClientConcise(w io.Writer, v model.ValidatedEvaluatedRun) error {
	r := v.Value()
	if err := writeLine(w, "RouteDoctor — "+clientTargetText(r.Evidence.Target)); err != nil {
		return err
	}
	if err := writeLine(w, ""); err != nil {
		return err
	}
	definitions, entities, observations := clientEvidenceMaps(r)
	if line := resolutionSummary(observations); line != "" {
		if err := writeLine(w, line); err != nil {
			return err
		}
	}
	for _, capability := range r.Evidence.Capabilities {
		if capability.CapabilityID == "capability-000001" && capability.Kind == model.CapabilityHTTPProbe && capability.State == model.CapabilityAvailable && capability.ReasonCode == "proxy_environment_detected_ignored" {
			if err := writeLine(w, "Proxy environment detected; direct path probed."); err != nil {
				return err
			}
		}
	}
	pathLines := clientPathSummaryLines(r.Evidence.Target, definitions, entities, r.Evidence.CheckExecutions, observations)
	for _, line := range pathLines {
		if err := writeLine(w, line); err != nil {
			return err
		}
	}
	selected := selectedClientFindings(r.Findings)
	diagnoses := certificateDiagnoses(r.Evidence.Observations)
	statuses := httpResponseStatuses(r.Evidence.Observations)
	if len(statuses) > 0 {
		if err := writeLine(w, ""); err != nil {
			return err
		}
		if err := writeLine(w, "Service is reachable."); err != nil {
			return err
		}
		for _, status := range statuses {
			if err := writeLine(w, fmt.Sprintf("HTTP %d received.", status)); err != nil {
				return err
			}
		}
	}
	for _, finding := range selected {
		if err := writeLine(w, clientFindingConclusion(finding.TitleCode)); err != nil {
			return err
		}
	}
	if len(selected) == 0 && len(statuses) == 0 && len(diagnoses) > 0 {
		if err := writeLine(w, "Blocked at certificate verification."); err != nil {
			return err
		}
	}
	if len(selected) == 0 && len(statuses) == 0 && len(diagnoses) == 0 && len(pathLines) == 0 {
		if err := writeLine(w, "No definitive conclusion from the available checks."); err != nil {
			return err
		}
	}
	if len(r.Evidence.Limitations) > 0 {
		partial := false
		for _, limitation := range r.Evidence.Limitations {
			if limitation.Code == model.LimitationPartialVisibility {
				partial = true
				break
			}
		}
		if partial {
			if err := writeLine(w, "Partial visibility: additional resolved addresses were not retained/probed."); err != nil {
				return err
			}
		}
	}
	return nil
}

func clientEvidenceMaps(r model.EvaluatedRun) (map[model.CheckID]model.CheckDefinition, map[model.EntityID]model.Entity, map[model.ObservationID]model.Observation) {
	definitions := map[model.CheckID]model.CheckDefinition{}
	for _, definition := range r.Evidence.CheckDefinitions {
		definitions[definition.CheckID] = definition
	}
	entities := map[model.EntityID]model.Entity{}
	for _, entity := range r.Evidence.Entities {
		entities[entity.EntityID] = entity
	}
	observations := map[model.ObservationID]model.Observation{}
	for _, observation := range r.Evidence.Observations {
		observations[observation.ObservationID] = observation
	}
	return definitions, entities, observations
}

func resolutionSummary(observations map[model.ObservationID]model.Observation) string {
	resolved := map[model.AddressFamily]map[model.EntityID]bool{
		model.AddressFamilyIPv4: {},
		model.AddressFamilyIPv6: {},
	}
	anyResolution := false
	for _, observation := range observations {
		if observation.Payload.Resolution == nil {
			continue
		}
		anyResolution = true
		resolution := observation.Payload.Resolution
		if resolution.Result != model.ResolutionResolved {
			continue
		}
		key := model.EntityID(string(resolution.AddressFamily)) + model.EntityID(stringValueEntity(resolution.AddressEntityID))
		resolved[resolution.AddressFamily][key] = true
	}
	v4 := len(resolved[model.AddressFamilyIPv4])
	v6 := len(resolved[model.AddressFamilyIPv6])
	if v4 == 0 && v6 == 0 {
		if anyResolution {
			return "DNS    ✗ No addresses resolved"
		}
		return ""
	}
	parts := []string{}
	if v4 > 0 {
		parts = append(parts, addressCountText(v4, "IPv4"))
	}
	if v6 > 0 {
		parts = append(parts, addressCountText(v6, "IPv6"))
	}
	return "DNS    ✓ " + strings.Join(parts, ", ")
}

func stringValueEntity(id *model.EntityID) string {
	if id == nil {
		return ""
	}
	return string(*id)
}

func addressCountText(count int, family string) string {
	unit := "addresses"
	if count == 1 {
		unit = "address"
	}
	return fmt.Sprintf("%d %s %s", count, family, unit)
}

type clientEndpointSummary struct {
	family        model.AddressFamily
	address       string
	tcp           model.TCPResult
	observedTCP   bool
	tls           model.TLSTransportResult
	observedTLS   bool
	certificate   model.CertificateVerificationResult
	observedCert  bool
	httpResponses []string
}

func clientPathSummaryLines(target model.Target, definitions map[model.CheckID]model.CheckDefinition, entities map[model.EntityID]model.Entity, executions []model.CheckExecution, observations map[model.ObservationID]model.Observation) []string {
	byFamily := map[model.AddressFamily]map[string]*clientEndpointSummary{
		model.AddressFamilyIPv4: {},
		model.AddressFamilyIPv6: {},
	}
	for _, execution := range executions {
		if execution.BranchID == nil {
			continue
		}
		definition, ok := definitions[execution.CheckID]
		if !ok {
			continue
		}
		entity, ok := entities[definition.Inputs.SubjectEntityID]
		if !ok || entity.Identity.Endpoint == nil {
			continue
		}
		endpoint := entity.Identity.Endpoint
		family, ok := endpointFamily(endpoint)
		if !ok {
			continue
		}
		key := endpoint.Address.String() + ":" + strconv.Itoa(int(endpoint.Port))
		familyEndpoints := byFamily[family]
		summary := familyEndpoints[key]
		if summary == nil {
			summary = &clientEndpointSummary{family: family, address: endpointDisplay(endpoint)}
			familyEndpoints[key] = summary
		}
		for _, observationID := range execution.ObservationIDs {
			observation, ok := observations[observationID]
			if !ok {
				continue
			}
			if observation.Payload.TCP != nil {
				summary.tcp = observation.Payload.TCP.Result
				summary.observedTCP = true
			}
			if observation.Payload.TLSTransport != nil {
				summary.tls = observation.Payload.TLSTransport.Result
				summary.observedTLS = true
			}
			if observation.Payload.CertificateVerification != nil {
				summary.certificate = observation.Payload.CertificateVerification.Result
				summary.observedCert = true
			}
			if observation.Payload.HTTP != nil && observation.Payload.HTTP.ResultKind.Valid() {
				response := fmt.Sprintf("HTTP %d", observation.Payload.HTTP.StatusCode)
				if observation.Payload.HTTP.ResultKind == model.HTTPRedirect {
					response += " redirect"
					if observation.Payload.HTTP.RedirectTarget != nil {
						response += " → " + redirectTargetText(*observation.Payload.HTTP.RedirectTarget)
					}
				}
				if !containsString(summary.httpResponses, response) {
					summary.httpResponses = append(summary.httpResponses, response)
				}
			}
		}
	}
	lines := []string{}
	for _, family := range []model.AddressFamily{model.AddressFamilyIPv4, model.AddressFamilyIPv6} {
		endpoints := byFamily[family]
		outcomes := []string{}
		states := []string{}
		for _, endpoint := range endpoints {
			state, text, observed := endpointSummary(target.Scheme, endpoint)
			if !observed {
				continue
			}
			key := state + "\x00" + text
			if !containsString(outcomes, key) {
				outcomes = append(outcomes, key)
				states = append(states, state+"\x00"+text)
			}
		}
		if len(states) == 0 {
			continue
		}
		label := "IPv4"
		if family == model.AddressFamilyIPv6 {
			label = "IPv6"
		}
		if len(states) > 1 {
			lines = append(lines, label+"   ! Mixed results; see --verbose")
			continue
		}
		parts := strings.SplitN(states[0], "\x00", 2)
		indicator := "?"
		if parts[0] == "success" {
			indicator = "✓"
		} else if parts[0] == "failure" {
			indicator = "✗"
		}
		lines = append(lines, fmt.Sprintf("%-6s %s %s", label, indicator, parts[1]))
	}
	return lines
}

func endpointFamily(endpoint *model.EndpointIdentity) (model.AddressFamily, bool) {
	if endpoint.Address.Is4() {
		return model.AddressFamilyIPv4, true
	}
	if endpoint.Address.Is6() {
		return model.AddressFamilyIPv6, true
	}
	return "", false
}

func endpointSummary(scheme string, endpoint *clientEndpointSummary) (string, string, bool) {
	if !endpoint.observedTCP {
		return "", "", false
	}
	if endpoint.tcp != model.TCPAccepted {
		switch endpoint.tcp {
		case model.TCPRefused:
			return "failure", "TCP: Connection refused", true
		case model.TCPTimedOut:
			return "failure", "TCP: Connection timed out", true
		default:
			return "failure", "TCP: Connection failed", true
		}
	}
	stages := []string{"TCP"}
	if scheme == "https" {
		if !endpoint.observedTLS {
			return "uncertain", "TCP → TLS unavailable", true
		}
		if endpoint.tls != model.TLSTransportCompleted {
			if endpoint.tls == model.TLSTransportTimedOut {
				return "failure", "TCP → TLS handshake timed out", true
			}
			return "failure", "TCP → TLS handshake failed", true
		}
		stages = append(stages, "TLS")
		if !endpoint.observedCert {
			return "uncertain", strings.Join(stages, " → ") + " → certificate unavailable", true
		}
		if endpoint.certificate != model.CertVerified {
			return "failure", strings.Join(stages, " → ") + " → certificate (" + certificateFailureShort(endpoint.certificate) + ")", true
		}
		stages = append(stages, "certificate")
	}
	if len(endpoint.httpResponses) == 0 {
		return "uncertain", strings.Join(stages, " → ") + " → HTTP unavailable", true
	}
	if len(endpoint.httpResponses) > 1 {
		return "mixed", "Different HTTP responses; see --verbose", true
	}
	return "success", strings.Join(append(stages, endpoint.httpResponses[0]), " → "), true
}

func certificateFailureShort(result model.CertificateVerificationResult) string {
	switch result {
	case model.CertHostnameMismatch:
		return "hostname mismatch"
	case model.CertExpired:
		return "expired"
	case model.CertNotYetValid:
		return "not yet valid"
	case model.CertUntrustedIssuer:
		return "not trusted"
	case model.CertInvalidUsage:
		return "invalid usage"
	case model.CertVerifierUnavailable:
		return "verification unavailable"
	default:
		return "verification failed"
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func selectedClientFindings(findings []model.Finding) []model.Finding {
	selected := []model.Finding{}
	for _, finding := range findings {
		if finding.Selection == model.SelectionGlobalPrimary || finding.Selection == model.SelectionBranchPrimary {
			selected = append(selected, finding)
		}
	}
	return selected
}

func clientFindingConclusion(title model.FindingTitleCode) string {
	switch title {
	case model.TitleTCPConnectionRefused:
		return "Blocked at TCP: the target refused the connection."
	case model.TitleTLSCertificateHostnameMismatch:
		return "Blocked at certificate verification: hostname mismatch."
	case model.TitleNoMatchingListenerVisible:
		return "Blocked at listener visibility: no matching listener was visible."
	default:
		return "Blocked: " + titleText(title) + "."
	}
}

func clientTargetText(t model.Target) string {
	authority := t.Hostname
	if strings.Contains(authority, ":") {
		authority = "[" + authority + "]"
	}
	if !((t.Scheme == "http" && t.EffectivePort == 80) || (t.Scheme == "https" && t.EffectivePort == 443)) {
		authority += ":" + strconv.Itoa(int(t.EffectivePort))
	}
	path := "/"
	if t.Path.Present && !t.Path.IsRoot {
		path = "/..."
	}
	return fmt.Sprintf("%s://%s%s", t.Scheme, authority, path)
}

func reportClientVerbose(w io.Writer, v model.ValidatedEvaluatedRun) error {
	if err := reportClientConcise(w, v); err != nil {
		return err
	}
	r := v.Value()
	if err := writeLine(w, fmt.Sprintf("Target details: PathSummary present=%t root=%t segments=%d trailing_slash=%t query_present=%t", r.Evidence.Target.Path.Present, r.Evidence.Target.Path.IsRoot, r.Evidence.Target.Path.SegmentCount, r.Evidence.Target.Path.TrailingSlash, r.Evidence.Target.Path.QueryPresent)); err != nil {
		return err
	}
	if err := reportClientTechnicalDetails(w, r); err != nil {
		return err
	}
	if err := writeLine(w, "CLIENT CHECK EVIDENCE"); err != nil {
		return err
	}
	for _, execution := range r.Evidence.CheckExecutions {
		if err := writeLine(w, fmt.Sprintf("- %s check=%s lifecycle=%s verdict=%s reason=%s observations=%v", execution.ExecutionID, execution.CheckID, execution.Lifecycle, execution.Verdict, stringValue(execution.ReasonCode), execution.ObservationIDs)); err != nil {
			return err
		}
	}
	return nil
}

func reportClientTechnicalDetails(w io.Writer, r model.EvaluatedRun) error {
	definitions, entities, observations := clientEvidenceMaps(r)
	if len(r.Evidence.ServicePath.Branches) > 0 {
		if err := writeLine(w, "ENDPOINT BRANCHES"); err != nil {
			return err
		}
	}
	for _, branch := range r.Evidence.ServicePath.Branches {
		endpoint := branchEndpoint(branch.BranchID, r.Evidence.CheckExecutions, definitions, entities)
		if err := writeLine(w, fmt.Sprintf("- %s endpoint=%s", branch.BranchID, endpoint)); err != nil {
			return err
		}
		for _, execution := range r.Evidence.CheckExecutions {
			if execution.BranchID == nil || *execution.BranchID != branch.BranchID {
				continue
			}
			definition := definitions[execution.CheckID]
			status := executionSummary(execution, observations)
			if err := writeLine(w, fmt.Sprintf("  CHECK %s: %s %s%s", definition.Kind, execution.Lifecycle, execution.Verdict, status)); err != nil {
				return err
			}
		}
	}
	for _, execution := range r.Evidence.CheckExecutions {
		if execution.BranchID != nil {
			continue
		}
		if err := writeLine(w, fmt.Sprintf("UNATTRIBUTED CHECK %s: %s/%s reason=%s", definitions[execution.CheckID].Kind, execution.Lifecycle, execution.Verdict, stringValue(execution.ReasonCode))); err != nil {
			return err
		}
	}
	selected := selectedClientFindings(r.Findings)
	for _, finding := range selected {
		if err := writeLine(w, fmt.Sprintf("PRIMARY [%s] %s", finding.Selection, titleText(finding.TitleCode))); err != nil {
			return err
		}
	}
	diagnoses := certificateDiagnoses(r.Evidence.Observations)
	for _, diagnosis := range diagnoses {
		if err := writeLine(w, diagnosis); err != nil {
			return err
		}
	}
	if len(selected) == 0 && len(diagnoses) == 0 {
		if err := writeLine(w, "No rule-produced primary finding."); err != nil {
			return err
		}
	}
	return nil
}

func branchEndpoint(branchID model.BranchID, executions []model.CheckExecution, definitions map[model.CheckID]model.CheckDefinition, entities map[model.EntityID]model.Entity) string {
	for _, execution := range executions {
		if execution.BranchID == nil || *execution.BranchID != branchID {
			continue
		}
		definition := definitions[execution.CheckID]
		if definition.Kind != model.CheckTCPConnection {
			continue
		}
		if entity, ok := entities[definition.Inputs.SubjectEntityID]; ok && entity.Identity.Endpoint != nil {
			return endpointDisplay(entity.Identity.Endpoint)
		}
	}
	return "unknown endpoint"
}

func endpointDisplay(endpoint *model.EndpointIdentity) string {
	return net.JoinHostPort(endpoint.Address.String(), strconv.Itoa(int(endpoint.Port)))
}

func httpResponseStatuses(observations []model.Observation) []uint16 {
	seen := map[uint16]bool{}
	var statuses []uint16
	for _, observation := range observations {
		if observation.Payload.HTTP == nil || !observation.Payload.HTTP.ResultKind.Valid() || seen[observation.Payload.HTTP.StatusCode] {
			continue
		}
		seen[observation.Payload.HTTP.StatusCode] = true
		statuses = append(statuses, observation.Payload.HTTP.StatusCode)
	}
	return statuses
}

func executionSummary(execution model.CheckExecution, observations map[model.ObservationID]model.Observation) string {
	reason := stringValue(execution.ReasonCode)
	status := ""
	for _, id := range execution.ObservationIDs {
		if observation, ok := observations[id]; ok && observation.Payload.HTTP != nil {
			status = fmt.Sprintf(" status=%d", observation.Payload.HTTP.StatusCode)
			if observation.Payload.HTTP.ResultKind == model.HTTPRedirect {
				status += " redirect"
				if observation.Payload.HTTP.RedirectTarget != nil {
					status += " → " + redirectTargetText(*observation.Payload.HTTP.RedirectTarget)
				}
			}
		}
	}
	if reason == "" {
		return status
	}
	return " reason=" + reason + status
}

func redirectTargetText(t model.Target) string {
	text := fmt.Sprintf("%s://%s:%d", t.Scheme, t.Hostname, t.EffectivePort)
	if !t.Path.Present {
		return text
	}
	if t.Path.IsRoot {
		return text + "/"
	}
	return text + "/..."
}

func certificateDiagnoses(observations []model.Observation) []string {
	seen := map[string]bool{}
	var diagnoses []string
	for _, observation := range observations {
		if observation.Payload.CertificateVerification == nil {
			continue
		}
		if diagnosis := certificateDiagnosis(observation.Payload.CertificateVerification.Result); diagnosis != "" && !seen[diagnosis] {
			seen[diagnosis] = true
			diagnoses = append(diagnoses, diagnosis)
		}
	}
	return diagnoses
}

func certificateDiagnosis(result model.CertificateVerificationResult) string {
	switch result {
	case model.CertHostnameMismatch:
		return "TLS certificate hostname mismatch."
	case model.CertExpired:
		return "TLS certificate is expired."
	case model.CertNotYetValid:
		return "TLS certificate is not yet valid."
	case model.CertUntrustedIssuer:
		return "TLS certificate is untrusted (issuer not trusted)."
	case model.CertInvalidUsage:
		return "TLS certificate has invalid usage."
	case model.CertVerifierUnavailable:
		return "TLS certificate verification was unavailable."
	default:
		return ""
	}
}
