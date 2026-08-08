package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"routedoc/internal/model"
	"routedoc/internal/render"
)

type issueJSON struct {
	Code    string `json:"code"`
	Pointer string `json:"pointer"`
	Message string `json:"message"`
}
type validationJSON struct {
	Valid    bool        `json:"valid"`
	Issues   []issueJSON `json:"issues"`
	Warnings []issueJSON `json:"warnings"`
}
type versionJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Build   string `json:"build"`
}
type explanationJSON struct {
	FindingID string         `json:"finding_id"`
	TitleCode string         `json:"title_code"`
	Level     string         `json:"level"`
	RuleID    string         `json:"rule_id"`
	ClaimIDs  []string       `json:"claim_ids"`
	Evidence  []evidenceJSON `json:"evidence"`
}
type evidenceJSON struct {
	Kind          string `json:"kind"`
	ID            string `json:"id"`
	Contradicting bool   `json:"contradicting"`
}

func issuesJSON(v model.ValidationIssues) []issueJSON {
	out := make([]issueJSON, len(v))
	for i, x := range v {
		out[i] = issueJSON{Code: string(x.Code), Pointer: x.Pointer, Message: x.Message}
	}
	return out
}
func writeJSON(w io.Writer, v interface{}) error {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return err
	}
	_, err := w.Write(b.Bytes())
	return err
}
func writeValidationJSON(w io.Writer, valid bool, issues, warnings model.ValidationIssues) error {
	return writeJSON(w, validationJSON{Valid: valid, Issues: issuesJSON(issues), Warnings: issuesJSON(warnings)})
}
func writeVersionJSON(w io.Writer) error {
	return writeJSON(w, versionJSON{Name: ProducerName, Version: ProducerVersion, Build: ProducerBuild})
}
func writeExplanationJSON(w io.Writer, e render.Explanation) error {
	ids := make([]string, len(e.Claims))
	for i, c := range e.Claims {
		ids[i] = string(c.ClaimID)
	}
	ev := make([]evidenceJSON, len(e.Evidence))
	for i, x := range e.Evidence {
		ev[i] = evidenceJSON{Kind: string(x.Ref.Kind), ID: refID(x.Ref), Contradicting: x.Contradicting}
	}
	return writeJSON(w, explanationJSON{FindingID: string(e.Finding.FindingID), TitleCode: string(e.Finding.TitleCode), Level: string(e.Finding.Level), RuleID: string(e.Finding.RuleID), ClaimIDs: ids, Evidence: ev})
}
func printIssues(w io.Writer, v model.ValidationIssues) {
	for _, x := range v {
		fmt.Fprintf(w, "%s %s: %s\n", x.Code, x.Pointer, x.Message)
	}
}
func printWarnings(w io.Writer, v model.ValidationIssues) {
	for _, x := range v {
		fmt.Fprintf(w, "warning: %s %s: %s\n", x.Code, x.Pointer, x.Message)
	}
}
func refID(x model.EvidenceRef) string {
	if x.ObservationID != nil {
		return string(*x.ObservationID)
	}
	if x.ClaimID != nil {
		return string(*x.ClaimID)
	}
	if x.VisibilityID != nil {
		return string(*x.VisibilityID)
	}
	if x.AssertionID != nil {
		return string(*x.AssertionID)
	}
	return ""
}
