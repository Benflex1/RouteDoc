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
	if err := writeLine(w, "RouteDoctor client probe report"); err != nil {
		return err
	}
	if err := writeLine(w, "Target: "+clientTargetText(r.Evidence.Target)); err != nil {
		return err
	}
	if err := writeLine(w, fmt.Sprintf("Vantages: %d  Endpoint branches: %d", len(r.Evidence.VantagePoints), len(r.Evidence.ServicePath.Branches))); err != nil {
		return err
	}
	for _, capability := range r.Evidence.Capabilities {
		if capability.CapabilityID == "capability-000001" && capability.Kind == model.CapabilityHTTPProbe && capability.State == model.CapabilityAvailable && capability.ReasonCode == "proxy_environment_detected_ignored" {
			if err := writeLine(w, "Proxy environment detected and ignored; direct path probed."); err != nil {
				return err
			}
		}
	}
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
	selected := 0
	for _, finding := range r.Findings {
		if finding.Selection != model.SelectionGlobalPrimary && finding.Selection != model.SelectionBranchPrimary {
			continue
		}
		selected++
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
	if selected == 0 && len(diagnoses) == 0 {
		statuses := httpResponseStatuses(r.Evidence.Observations)
		if len(statuses) > 0 {
			if err := writeLine(w, "Service is reachable."); err != nil {
				return err
			}
			for _, status := range statuses {
				if err := writeLine(w, fmt.Sprintf("HTTP %d received.", status)); err != nil {
					return err
				}
			}
		} else if err := writeLine(w, "No rule-produced primary finding."); err != nil {
			return err
		}
	}
	if len(r.Evidence.Limitations) > 0 {
		if err := writeLine(w, fmt.Sprintf("Limitations: %d", len(r.Evidence.Limitations))); err != nil {
			return err
		}
		for _, limitation := range r.Evidence.Limitations {
			if limitation.Code == model.LimitationPartialVisibility {
				if err := writeLine(w, "Partial visibility: additional resolved addresses were not retained/probed."); err != nil {
					return err
				}
				break
			}
		}
	}
	return nil
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
