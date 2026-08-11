package main

import (
	"bytes"
	"context"
	"routedoc/internal/clientprobe"
	"routedoc/internal/model"
	"strings"
	"testing"
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

func TestCLIVersionJSON(t *testing.T) {
	var out, err bytes.Buffer
	code := NewApp([]string{"version", "--json"}, strings.NewReader(""), &out, &err, nil).Run()
	if code != ExitOK || !strings.Contains(out.String(), `"name":"routedoc"`) {
		t.Fatalf("%d %q %q", code, out.String(), err.String())
	}
}
