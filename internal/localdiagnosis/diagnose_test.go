package localdiagnosis

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"routedoc/internal/clientprobe"
	"routedoc/internal/model"
	"routedoc/internal/render"
	"routedoc/internal/schema/v1"
)

func TestDiagnoseAddsLocalEvidenceAndRunsClientProbeOnce(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	target, err := clientprobe.ParseTarget(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port := target.EffectivePort
	fs := procFixture(port, 12345)
	fs.dirs[""] = []string{"100"}
	fs.dirs["100/fd"] = []string{"3"}
	fs.links["100/fd/3"] = "socket:[12345]"
	fs.files["100/comm"] = []byte("fixture-service\n")
	calls := 0
	v, err := DiagnoseWith(context.Background(), server.URL, model.Producer{Name: "routedoc", Version: "test", Build: "test"}, fs, func(ctx context.Context, raw string, producer model.Producer) (model.ValidatedEvaluatedRun, error) {
		calls++
		return clientprobe.Diagnose(ctx, raw, producer)
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("client probe calls = %d, want 1", calls)
	}
	r := v.Value()
	if r.Evidence.RequestedScope.Kind != model.ScopeLocalOrigin || r.Evidence.Goal.Kind != model.GoalOriginPathDiagnosis {
		t.Fatalf("local scope/goal = %s/%s", r.Evidence.RequestedScope.Kind, r.Evidence.Goal.Kind)
	}
	if countObservationKind(r.Evidence.Observations, model.ObservationListenerInventory) != 1 || countObservationKind(r.Evidence.Observations, model.ObservationProcessOwnership) != 1 {
		t.Fatalf("local observations = %#v", r.Evidence.Observations)
	}
	for _, visibility := range r.Evidence.VisibilityAssessments {
		if visibility.Scope.Listener == nil || visibility.Scope.Listener.ProcessOwnershipRequired {
			t.Fatalf("process ownership was required for visibility scope: %#v", visibility.Scope)
		}
	}
	if !hasProcessLabel(r.Evidence.Entities, "fixture-service") {
		t.Fatalf("process entity missing: %#v", r.Evidence.Entities)
	}
	if _, issues := v1.EncodeCanonical(v); len(issues) != 0 {
		t.Fatal(issues)
	}
}

func TestDiagnoseRetainsListenerInventoryWhenOwnerUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "not found", http.StatusNotFound) }))
	defer server.Close()
	target, err := clientprobe.ParseTarget(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	fs := procFixture(target.EffectivePort, 54321)
	fs.dirs[""] = []string{"100"}
	fs.errors["100/fd"] = fmt.Errorf("permission denied")
	v, err := DiagnoseWith(context.Background(), server.URL, model.Producer{Name: "routedoc", Version: "test", Build: "test"}, fs, clientprobe.Diagnose)
	if err != nil {
		t.Fatal(err)
	}
	r := v.Value()
	if countObservationKind(r.Evidence.Observations, model.ObservationListenerInventory) != 1 {
		t.Fatal("listener inventory was lost when process attribution was unavailable")
	}
	for _, observation := range r.Evidence.Observations {
		if observation.Kind == model.ObservationProcessOwnership && observation.Payload.ProcessOwnership != nil && observation.Payload.ProcessOwnership.Result != model.OwnershipUnresolved {
			t.Fatalf("ownership = %#v", observation.Payload.ProcessOwnership)
		}
	}
}

func TestDiagnoseRetainsListenerInventoryWhenNamespaceIdentityIsUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	target, err := clientprobe.ParseTarget(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	fs := procFixture(target.EffectivePort, 54322)
	delete(fs.inodes, "self/ns/net")
	calls := 0
	v, err := DiagnoseWith(context.Background(), server.URL, model.Producer{Name: "routedoc", Version: "test", Build: "test"}, fs, func(ctx context.Context, raw string, producer model.Producer) (model.ValidatedEvaluatedRun, error) {
		calls++
		return clientprobe.Diagnose(ctx, raw, producer)
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("client probe calls = %d, want 1", calls)
	}
	r := v.Value()
	if countObservationKind(r.Evidence.Observations, model.ObservationListenerInventory) != 1 {
		t.Fatal("listener inventory was lost when namespace identity was unavailable")
	}
	if countObservationKind(r.Evidence.Observations, model.ObservationListenerInventoryResult) != 0 {
		t.Fatal("unqualified inventory result fabricated complete visibility")
	}
	if _, issues := v1.EncodeCanonical(v); len(issues) != 0 {
		t.Fatal(issues)
	}
}

func TestDiagnoseWildcardListenerCoversIPv4TargetWithoutFalseAbsence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	target, err := clientprobe.ParseTarget(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	fs := wildcardProcFixture(target.EffectivePort)
	v, err := DiagnoseWith(context.Background(), server.URL, model.Producer{Name: "routedoc", Version: "test", Build: "test"}, fs, clientprobe.Diagnose)
	if err != nil {
		t.Fatal(err)
	}
	r := v.Value()
	wildcardObserved := false
	wildcardIPv6Observed := false
	for _, entity := range r.Evidence.Entities {
		if entity.Kind != model.EntityListener || entity.Identity.Listener == nil {
			continue
		}
		switch entity.Identity.Listener.Endpoint.Address {
		case netip.MustParseAddr("0.0.0.0"):
			wildcardObserved = true
		case netip.MustParseAddr("::"):
			wildcardIPv6Observed = true
		}
	}
	if !wildcardObserved || !wildcardIPv6Observed {
		t.Fatalf("wildcard listener inventory was not retained: ipv4=%t ipv6=%t", wildcardObserved, wildcardIPv6Observed)
	}
	if got := countObservationKind(r.Evidence.Observations, model.ObservationListenerInventoryResult); got != 6 {
		t.Fatalf("listener binding bucket evidence count = %d, want 6", got)
	}
	for _, finding := range r.Findings {
		if finding.TitleCode == model.TitleNoMatchingListenerVisible {
			t.Fatalf("wildcard listener produced false absence blocker: %#v", finding)
		}
	}
	var output strings.Builder
	if err := render.Report(&output, v, render.Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Local service is reachable.") {
		t.Fatalf("concise output = %q", output.String())
	}
	b, issues := v1.EncodeCanonical(v)
	if len(issues) != 0 {
		t.Fatal(issues)
	}
	if strings.Contains(string(b), string(model.TitleNoMatchingListenerVisible)) {
		t.Fatalf("structured report contains false absence blocker: %s", b)
	}
}

func TestParseTargetKeepsExistingURLSemantics(t *testing.T) {
	target, err := clientprobe.ParseTarget("HTTP://LOCALHOST:8080/path?x=1#fragment")
	if err != nil {
		t.Fatal(err)
	}
	if target.Scheme != "http" || target.Hostname != "localhost" || target.EffectivePort != 8080 || !target.Path.QueryPresent {
		t.Fatalf("target = %#v", target)
	}
	if _, err := url.ParseRequestURI("http://" + target.Hostname); err != nil {
		t.Fatal(err)
	}
}

func procFixture(port uint16, inode uint64) *fakeProcFS {
	fs := newFakeProcFS()
	fs.files["net/tcp"] = []byte(fmt.Sprintf("  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n   0: 0100007F:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 %d 1\n", port, inode))
	fs.files["net/tcp6"] = []byte("  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n")
	fs.inodes["self/ns/net"] = 77
	return fs
}

func wildcardProcFixture(port uint16) *fakeProcFS {
	fs := newFakeProcFS()
	fs.files["net/tcp"] = []byte(fmt.Sprintf("  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n   0: 00000000:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345 1\n", port))
	fs.files["net/tcp6"] = []byte(fmt.Sprintf("  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n   0: 00000000000000000000000000000000:%04X 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 22345 1\n", port))
	fs.inodes["self/ns/net"] = 77
	return fs
}

func countObservationKind(observations []model.Observation, kind model.ObservationKind) int {
	count := 0
	for _, observation := range observations {
		if observation.Kind == kind {
			count++
		}
	}
	return count
}

func hasProcessLabel(entities []model.Entity, label string) bool {
	for _, entity := range entities {
		if entity.Kind == model.EntityProcess && strings.TrimSpace(entity.DisplayLabel) == label {
			return true
		}
	}
	return false
}
