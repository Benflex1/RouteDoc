package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"routedoc/internal/model"
	"routedoc/internal/rules"
)

var fixtureCases = []string{"valid-multibranch-no-global", "ipv4-success-ipv6-refused-partial", "tls-hostname-mismatch-http-skipped", "tls-transport-endpoint-adversarial", "caddy-active-over-configured-intent", "upstream-refused-wrong-vantage", "listener-absent-complete-scope", "listener-absent-exact-zero-scope", "listener-absent-partial-scope", "two-proxy-upstreams-no-global", "operator-asserted-expected-path", "multiclaim-acyclic", "claim-forward-invalid", "claim-cycle-invalid", "provenance-missing-invalid", "provenance-recoverable-stored", "reevaluation-replacement-before", "reevaluation-replacement-after", "path-summary-only", "sensitive-derived-only", "client-probe-http-success", "client-probe-tls-untrusted", "client-probe-unattempted-address", "exact-unknown-field-invalid", "newer-minor-ignored-fields", "newer-patch-known-readonly", "unknown-enum-invalid", "unknown-union-invalid", "missing-required-field-invalid", "unsupported-major-invalid"}

type fixtureIssueJSON struct {
	Code    string `json:"code"`
	Pointer string `json:"pointer"`
	Message string `json:"message"`
}
type fixtureValidationJSON struct {
	Valid    bool               `json:"valid"`
	Issues   []fixtureIssueJSON `json:"issues"`
	Warnings []fixtureIssueJSON `json:"warnings"`
}

func fixtureIssuesJSON(v model.ValidationIssues) []fixtureIssueJSON {
	out := make([]fixtureIssueJSON, len(v))
	for i, issue := range v {
		out[i] = fixtureIssueJSON{Code: string(issue.Code), Pointer: issue.Pointer, Message: issue.Message}
	}
	return out
}

func TestFixtureManifestCompleteness(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "reports", "v1")
	for _, name := range fixtureCases {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatalf("missing fixture %s: %v", name, err)
		}
	}
}
func TestFixture(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "reports", "v1")
	schemaPath := filepath.Join("..", "..", "..", "schema", "report", "v1.0.0", "schema.json")
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	invalid := map[string]bool{"claim-forward-invalid": true, "claim-cycle-invalid": true, "provenance-missing-invalid": true, "exact-unknown-field-invalid": true, "unknown-enum-invalid": true, "unknown-union-invalid": true, "missing-required-field-invalid": true, "unsupported-major-invalid": true}
	compat := map[string]bool{"newer-minor-ignored-fields": true, "newer-patch-known-readonly": true}
	for _, name := range fixtureCases {
		if invalid[name] || compat[name] {
			continue
		}
		path := filepath.Join(root, name, "report.json")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		d, issues := Decode(data, ReadValidate)
		if len(issues) != 0 {
			t.Fatalf("%s decode: %#v", name, issues)
		}
		v, issues := model.ValidatePersistedEvaluatedRun(d.Run)
		if len(issues) != 0 {
			t.Fatalf("%s model: %#v", name, issues)
		}
		var instance map[string]interface{}
		if err := json.Unmarshal(data, &instance); err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(instance); err != nil {
			t.Fatalf("%s schema: %v", name, err)
		}
		encoded, issues := EncodeCanonical(v)
		if len(issues) != 0 || !bytes.Equal(encoded, data) {
			t.Fatalf("%s canonical roundtrip: %v", name, issues)
		}
		if name == "valid-multibranch-no-global" || name == "ipv4-success-ipv6-refused-partial" || name == "tls-hostname-mismatch-http-skipped" || name == "upstream-refused-wrong-vantage" || name == "listener-absent-complete-scope" || name == "listener-absent-exact-zero-scope" || name == "listener-absent-partial-scope" || name == "two-proxy-upstreams-no-global" {
			base, issues := model.ValidateEvidenceRun(d.Run.Evidence)
			if len(issues) != 0 {
				t.Fatalf("%s base: %#v", name, issues)
			}
			reevaluated, issues := rules.NewEvaluator(rules.DefaultRegistry()).Evaluate(base, d.Run.Evaluation.EvaluatedAt)
			if len(issues) != 0 {
				t.Fatalf("%s evaluation: %#v", name, issues)
			}
			got := reevaluated.Value()
			if !reflect.DeepEqual(got.Claims, d.Run.Claims) || !reflect.DeepEqual(got.Findings, d.Run.Findings) {
				t.Fatalf("%s stored derived state differs from deterministic evaluation", name)
			}
		}
	}
	for name := range invalid {
		data, _ := os.ReadFile(filepath.Join(root, name, "report.json"))
		d, issues := Decode(data, ReadValidate)
		if len(issues) == 0 {
			_, issues = model.ValidatePersistedEvaluatedRun(d.Run)
		}
		if len(issues) == 0 {
			t.Fatalf("%s unexpectedly valid", name)
		}
		wantHuman, err := os.ReadFile(filepath.Join(root, name, "validate.txt"))
		if err != nil {
			t.Fatal(err)
		}
		var human strings.Builder
		for _, issue := range issues {
			fmt.Fprintf(&human, "%s %s: %s\n", issue.Code, issue.Pointer, issue.Message)
		}
		if !bytes.Equal([]byte(human.String()), wantHuman) {
			t.Fatalf("%s human validation mismatch", name)
		}
		wantJSON, err := os.ReadFile(filepath.Join(root, name, "validate.json"))
		if err != nil {
			t.Fatal(err)
		}
		gotJSON, err := json.Marshal(fixtureValidationJSON{Valid: false, Issues: fixtureIssuesJSON(issues), Warnings: []fixtureIssueJSON{}})
		if err != nil {
			t.Fatal(err)
		}
		gotJSON = append(gotJSON, '\n')
		if !bytes.Equal(gotJSON, wantJSON) {
			t.Fatalf("%s machine validation mismatch\nwant %s\ngot %s", name, wantJSON, gotJSON)
		}
	}
	minorData, _ := os.ReadFile(filepath.Join(root, "newer-minor-ignored-fields", "report.json"))
	minor, minorIssues := Decode(minorData, ReadValidate)
	if len(minorIssues) != 0 || len(minor.Warnings) == 0 {
		t.Fatalf("newer minor warnings: %#v %#v", minorIssues, minor.Warnings)
	}
	if _, issues := model.ValidatePersistedEvaluatedRun(minor.Run); len(issues) != 0 {
		t.Fatalf("newer minor projection: %#v", issues)
	}
	patchData, _ := os.ReadFile(filepath.Join(root, "newer-patch-known-readonly", "report.json"))
	patch, patchIssues := Decode(patchData, ReadValidate)
	if len(patchIssues) != 0 || len(patch.Warnings) != 0 || patch.Exact {
		t.Fatalf("newer patch: %#v %#v", patchIssues, patch)
	}
}

func TestFixtureSemanticBoundaries(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "reports", "v1")
	read := func(name string) model.EvaluatedRun {
		data, err := os.ReadFile(filepath.Join(root, name, "report.json"))
		if err != nil {
			t.Fatal(err)
		}
		d, issues := Decode(data, ReadValidate)
		if len(issues) != 0 {
			t.Fatalf("%s: %#v", name, issues)
		}
		return d.Run
	}
	tls := read("tls-hostname-mismatch-http-skipped")
	if len(tls.Evidence.Observations) != 1 || tls.Evidence.Observations[0].Kind != model.ObservationCertificateVerification || len(tls.Findings) != 1 || tls.Findings[0].RuleID != model.RuleID("tls.certificate_hostname_mismatch/v1") {
		t.Fatal("TLS fixture must retain typed peer verification evidence and its rule finding")
	}
	for _, o := range tls.Evidence.Observations {
		if o.Kind == model.ObservationHTTP {
			t.Fatal("TLS mismatch fixture must not invent an HTTP result")
		}
	}
	transport := read("tls-transport-endpoint-adversarial")
	if len(transport.Evidence.Observations) != 5 {
		t.Fatalf("TLS transport adversarial fixture observations: %d", len(transport.Evidence.Observations))
	}
	for i, observation := range transport.Evidence.Observations {
		if observation.Kind != model.ObservationTLSTransport || observation.Payload.TLSTransport == nil || observation.Payload.TLSTransport.EndpointEntityID != model.EntityID("entity-endpoint") {
			t.Fatalf("transport observation %d does not name exact endpoint: %#v", i, observation)
		}
		peer := observation.Payload.TLSTransport.PeerEntityID
		if i < 3 && peer != nil {
			t.Fatalf("pre-certificate transport observation %d fabricated peer %q", i, *peer)
		}
		if i >= 3 && (peer == nil || *peer != model.EntityID("entity-peer")) {
			t.Fatalf("certificate-derived transport observation %d lost peer attribution: %#v", i, observation.Payload.TLSTransport)
		}
	}
	if tcp := read("upstream-refused-wrong-vantage"); len(tcp.Findings) != 1 || tcp.Findings[0].RuleID != model.RuleID("tcp.connection_refused/v1") {
		t.Fatal("TCP fixture must retain only the exact-vantage refusal finding")
	}
	complete := read("listener-absent-complete-scope")
	if len(complete.Evidence.VisibilityAssessments) != 1 || complete.Evidence.VisibilityAssessments[0].Level != model.VisibilityCompleteForScope || len(complete.Findings) != 1 {
		t.Fatal("complete listener scope fixture must produce absence evidence")
	}
	exact := read("listener-absent-exact-zero-scope")
	if len(exact.Evidence.Observations) != 1 || exact.Evidence.Observations[0].Kind != model.ObservationListenerInventoryResult || len(exact.Findings) != 1 {
		t.Fatal("exact listener scope fixture must use a direct zero-count inventory result")
	}
	partial := read("listener-absent-partial-scope")
	if len(partial.Findings) != 0 {
		t.Fatal("partial listener visibility must not produce absence findings")
	}
	for _, name := range []string{"valid-multibranch-no-global", "ipv4-success-ipv6-refused-partial", "two-proxy-upstreams-no-global"} {
		run := read(name)
		if len(run.Evidence.ServicePath.Branches) != 2 || len(run.Evidence.Observations) != 2 || len(run.Findings) != 1 || run.Findings[0].Selection == model.SelectionGlobalPrimary {
			t.Fatalf("%s must preserve independent branches without a global primary", name)
		}
	}
}
