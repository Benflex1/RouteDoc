package render

import (
	"fmt"
	"io"
	"strings"

	"routedoc/internal/model"
)

func isClientReport(v model.ValidatedEvaluatedRun) bool {
	return strings.Contains(v.Value().Evidence.Producer.Version, "milestone1")
}

func reportClientConcise(w io.Writer, v model.ValidatedEvaluatedRun) error {
	r := v.Value()
	if err := writeLine(w, "RouteDoctor client probe report"); err != nil {
		return err
	}
	if err := writeLine(w, "Target: "+targetText(r.Evidence.Target)); err != nil {
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
	if selected == 0 {
		if err := writeLine(w, "No rule-produced primary finding."); err != nil {
			return err
		}
	}
	if len(r.Evidence.Limitations) > 0 {
		if err := writeLine(w, fmt.Sprintf("Limitations: %d", len(r.Evidence.Limitations))); err != nil {
			return err
		}
	}
	return nil
}

func reportClientVerbose(w io.Writer, v model.ValidatedEvaluatedRun) error {
	if err := reportClientConcise(w, v); err != nil {
		return err
	}
	r := v.Value()
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
	return fmt.Sprintf("%s:%d", endpoint.Address, endpoint.Port)
}

func executionSummary(execution model.CheckExecution, observations map[model.ObservationID]model.Observation) string {
	reason := stringValue(execution.ReasonCode)
	status := ""
	for _, id := range execution.ObservationIDs {
		if observation, ok := observations[id]; ok && observation.Payload.HTTP != nil {
			status = fmt.Sprintf(" status=%d", observation.Payload.HTTP.StatusCode)
		}
	}
	if reason == "" {
		return status
	}
	return " reason=" + reason + status
}
