package main

import (
	"bytes"
	"context"
	"routedoc/internal/clientprobe"
	"routedoc/internal/localdiagnosis"
	"routedoc/internal/model"
	"routedoc/internal/schema/v1"
	"strings"
	"testing"
	"time"
)

func TestCLIExactCommandBoundary(t *testing.T) {
	for _, args := range [][]string{{"diagnose", "https://example.test"}, {"https://example.test", "--json", "--json"}, {"https://example.test", "--bad"}, {"render"}, {"version", "--bad"}} {
		var out, err bytes.Buffer
		code := NewApp(args, strings.NewReader("stdin"), &out, &err, nil).Run()
		if code != ExitUsage {
			t.Fatalf("%v returned %d", args, code)
		}
	}
}

func TestCLIURLDispatchAndSafeInputError(t *testing.T) {
	var out, errOut bytes.Buffer
	app := NewApp([]string{"https://example.test/private?token=secret"}, strings.NewReader(""), &out, &errOut, nil)
	app.Diagnose = func(context.Context, string, model.Producer) (model.ValidatedEvaluatedRun, error) {
		return model.ValidatedEvaluatedRun{}, &clientprobe.InputError{Code: "url_credentials_disallowed"}
	}
	if code := app.Run(); code != ExitUsage || errOut.String() != "url_credentials_disallowed\n" {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
}

func TestCLIProbeIndeterminateMapsToTwo(t *testing.T) {
	var out, errOut bytes.Buffer
	app := NewApp([]string{"https://example.test"}, strings.NewReader(""), &out, &errOut, nil)
	app.Diagnose = func(context.Context, string, model.Producer) (model.ValidatedEvaluatedRun, error) {
		return model.ValidatedEvaluatedRun{}, nil
	}
	if code := app.Run(); code != ExitData {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestCLILocalDispatchesOnceAndRendersLocalShape(t *testing.T) {
	var out, errOut bytes.Buffer
	app := NewApp([]string{"local", "http://localhost:8080"}, strings.NewReader(""), &out, &errOut, nil)
	calls := 0
	app.LocalDiagnose = func(_ context.Context, raw string, _ model.Producer) (model.ValidatedEvaluatedRun, error) {
		calls++
		if raw != "http://localhost:8080" {
			t.Fatalf("raw URL = %q", raw)
		}
		v, issues := model.CanonicalizeAndValidateEvaluatedRun(model.EvaluatedRun{
			Evidence: model.EvidenceRun{
				ReportSchemaVersion: model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}, Producer: model.Producer{Name: "routedoc", Version: "test", Build: "test"}, RunID: "run-000001",
				Target: model.Target{Scheme: "http", Hostname: "localhost", EffectivePort: 8080, Path: model.PathSummary{Present: true, IsRoot: true}}, Goal: model.Goal{Kind: model.GoalOriginPathDiagnosis}, RequestedScope: model.RequestedScope{Kind: model.ScopeLocalOrigin}, StartedAt: time.Unix(0, 0).UTC(), FinishedAt: time.Unix(0, 0).UTC(),
				VantagePoints: []model.VantagePoint{}, Capabilities: []model.Capability{}, OperatorAssertions: []model.OperatorAssertion{}, Entities: []model.Entity{}, ServicePath: model.ServicePath{Nodes: []model.PathNode{}, Edges: []model.PathEdge{}, Branches: []model.Branch{}}, CheckDefinitions: []model.CheckDefinition{}, CheckExecutions: []model.CheckExecution{}, Observations: []model.Observation{}, VisibilityAssessments: []model.VisibilityAssessment{}, Limitations: []model.Limitation{},
			},
			Evaluation: model.Evaluation{EvaluatedAt: time.Unix(0, 0).UTC(), OrderedRuleIDs: []model.RuleID{}}, Claims: []model.Claim{}, Findings: []model.Finding{},
		})
		if len(issues) != 0 {
			t.Fatal(issues)
		}
		return v, nil
	}
	if code := app.Run(); code != ExitData || calls != 1 || !strings.Contains(out.String(), "local service") {
		t.Fatalf("code=%d calls=%d out=%q err=%q", code, calls, out.String(), errOut.String())
	}
}

func TestCLILocalRejectsPortOnlyForm(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := NewApp([]string{"local", ":8080"}, strings.NewReader(""), &out, &errOut, nil).Run(); code != ExitUsage || errOut.String() != "invalid_url\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestCLILocalJSONRemainsSchemaValid(t *testing.T) {
	var out, errOut bytes.Buffer
	app := NewApp([]string{"local", "http://localhost:8080", "--json"}, strings.NewReader(""), &out, &errOut, nil)
	app.LocalDiagnose = func(context.Context, string, model.Producer) (model.ValidatedEvaluatedRun, error) {
		v, issues := model.CanonicalizeAndValidateEvaluatedRun(model.EvaluatedRun{
			Evidence: model.EvidenceRun{
				ReportSchemaVersion: model.SchemaVersion{Major: 1, Minor: 0, Patch: 0}, Producer: model.Producer{Name: "routedoc", Version: "test", Build: "test"}, RunID: "run-000001",
				Target: model.Target{Scheme: "http", Hostname: "localhost", EffectivePort: 8080, Path: model.PathSummary{Present: true, IsRoot: true}}, Goal: model.Goal{Kind: model.GoalOriginPathDiagnosis}, RequestedScope: model.RequestedScope{Kind: model.ScopeLocalOrigin}, StartedAt: time.Unix(0, 0).UTC(), FinishedAt: time.Unix(0, 0).UTC(),
				VantagePoints: []model.VantagePoint{}, Capabilities: []model.Capability{}, OperatorAssertions: []model.OperatorAssertion{}, Entities: []model.Entity{}, ServicePath: model.ServicePath{Nodes: []model.PathNode{}, Edges: []model.PathEdge{}, Branches: []model.Branch{}}, CheckDefinitions: []model.CheckDefinition{}, CheckExecutions: []model.CheckExecution{}, Observations: []model.Observation{}, VisibilityAssessments: []model.VisibilityAssessment{}, Limitations: []model.Limitation{},
			},
			Evaluation: model.Evaluation{EvaluatedAt: time.Unix(0, 0).UTC(), OrderedRuleIDs: []model.RuleID{}}, Claims: []model.Claim{}, Findings: []model.Finding{},
		})
		if len(issues) != 0 {
			return model.ValidatedEvaluatedRun{}, issues.Err()
		}
		return v, nil
	}
	if code := app.Run(); code != ExitData {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	d, issues := v1.Decode(out.Bytes(), v1.ReadValidate)
	if len(issues) != 0 {
		t.Fatalf("JSON decode issues: %v; output=%s", issues, out.String())
	}
	if _, issues := model.ValidatePersistedEvaluatedRun(d.Run); len(issues) != 0 {
		t.Fatalf("JSON validation issues: %v", issues)
	}
}

func TestCLILocalUnsupportedPlatformIsHumanFacing(t *testing.T) {
	var out, errOut bytes.Buffer
	app := NewApp([]string{"local", "http://localhost:8080"}, strings.NewReader(""), &out, &errOut, nil)
	app.LocalDiagnose = func(context.Context, string, model.Producer) (model.ValidatedEvaluatedRun, error) {
		return model.ValidatedEvaluatedRun{}, localdiagnosis.ErrUnsupportedPlatform
	}
	if code := app.Run(); code != ExitData || errOut.String() != "local diagnosis is only supported on Linux\n" {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
}

func TestCLIVersionJSON(t *testing.T) {
	var out, err bytes.Buffer
	code := NewApp([]string{"version", "--json"}, strings.NewReader(""), &out, &err, nil).Run()
	if code != ExitOK || !strings.Contains(out.String(), `"name":"routedoc"`) {
		t.Fatalf("%d %q %q", code, out.String(), err.String())
	}
}
