package render

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"routedoc/internal/clientprobe"
	"routedoc/internal/localdiagnosis"
	"routedoc/internal/model"
)

func TestLocalRenderReachableWildcardListener(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	target, _ := clientprobe.ParseTarget(server.URL)
	v := localFixtureReport(t, server.URL, procFixtureForRender(target.EffectivePort, "00000000", 30001, nil))
	output := renderLocal(t, v)
	for _, want := range []string{"Listener   ✓ 0.0.0.0:", "TCP        ✓ connection accepted", "HTTP       ✓ 200", "Local service is reachable."} {
		if !strings.Contains(output, want) {
			t.Fatalf("missing %q in %q", want, output)
		}
	}
	if strings.Contains(output, "only on loopback") {
		t.Fatalf("wildcard listener was described as loopback-only: %q", output)
	}
}

func TestLocalRenderLoopbackOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	target, _ := clientprobe.ParseTarget(server.URL)
	v := localFixtureReport(t, server.URL, procFixtureForRender(target.EffectivePort, "0100007F", 30002, nil))
	output := renderLocal(t, v)
	if !strings.Contains(output, "The service is listening only on loopback.") || !strings.Contains(output, "non-loopback local addresses") {
		t.Fatalf("loopback conclusion missing: %q", output)
	}
}

func TestLocalRenderAbsentListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	serverURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	v := localFixtureReport(t, serverURL, procFixtureForRender(uint16(port), "", 0, nil))
	output := renderLocal(t, v)
	if !strings.Contains(output, "nothing listening on TCP port") || !strings.Contains(output, "No matching TCP listener was observed") {
		t.Fatalf("absence conclusion missing: %q", output)
	}
	if strings.Contains(output, "The service is listening only on loopback") {
		t.Fatalf("absence was described as loopback-only: %q", output)
	}
}

func TestLocalRenderListenerWithFailedHTTPProbe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	serverURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	v := localFixtureReport(t, serverURL, procFixtureForRender(uint16(port), "0100007F", 30004, nil))
	output := renderLocal(t, v)
	if !strings.Contains(output, "Listener   ✓ 127.0.0.1:") || !strings.Contains(output, "local TCP/TLS/HTTP probe did not succeed") {
		t.Fatalf("failed-probe conclusion missing: %q", output)
	}
	if strings.Contains(output, "nothing listening") {
		t.Fatalf("failed probe was turned into listener absence: %q", output)
	}
}

func TestLocalRenderOwnerUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusNotFound) }))
	defer server.Close()
	target, _ := clientprobe.ParseTarget(server.URL)
	fs := procFixtureForRender(target.EffectivePort, "0100007F", 30003, nil)
	fs.dirs[""] = []string{"100"}
	fs.errors["100/fd"] = errors.New("permission denied")
	v := localFixtureReport(t, server.URL, fs)
	output := renderLocal(t, v)
	if !strings.Contains(output, "Process    ⚠ ownership unavailable") || strings.Contains(output, "no process owns") {
		t.Fatalf("owner degradation missing or overstated: %q", output)
	}
}

func localFixtureReport(t *testing.T, rawURL string, fs *renderProcFS) model.ValidatedEvaluatedRun {
	t.Helper()
	v, err := localdiagnosis.DiagnoseWith(context.Background(), rawURL, model.Producer{Name: "routedoc", Version: "test", Build: "test"}, fs, clientprobe.Diagnose)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func renderLocal(t *testing.T, v model.ValidatedEvaluatedRun) string {
	t.Helper()
	var output strings.Builder
	if err := Report(&output, v, Options{}); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

type renderProcFS struct {
	files  map[string][]byte
	dirs   map[string][]string
	links  map[string]string
	inodes map[string]uint64
	errors map[string]error
}

func procFixtureForRender(port uint16, address string, inode uint64, _ error) *renderProcFS {
	fs := &renderProcFS{files: map[string][]byte{}, dirs: map[string][]string{"": {}}, links: map[string]string{}, inodes: map[string]uint64{"self/ns/net": 77}, errors: map[string]error{}}
	row := ""
	if address != "" {
		row = fmt.Sprintf("   0: %s:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 %d 1\n", address, port, inode)
	}
	fs.files["net/tcp"] = []byte("  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" + row)
	fs.files["net/tcp6"] = []byte("  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n")
	return fs
}

func (f *renderProcFS) ReadFile(name string) ([]byte, error) {
	if err := f.errors[name]; err != nil {
		return nil, err
	}
	data, ok := f.files[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte{}, data...), nil
}
func (f *renderProcFS) ReadDir(name string) ([]string, error) {
	if err := f.errors[name]; err != nil {
		return nil, err
	}
	data, ok := f.dirs[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]string{}, data...), nil
}
func (f *renderProcFS) Readlink(name string) (string, error) {
	if err := f.errors[name]; err != nil {
		return "", err
	}
	data, ok := f.links[name]
	if !ok {
		return "", errors.New("not found")
	}
	return data, nil
}
func (f *renderProcFS) StatInode(name string) (uint64, error) {
	if err := f.errors[name]; err != nil {
		return 0, err
	}
	data, ok := f.inodes[name]
	if !ok {
		return 0, errors.New("not found")
	}
	return data, nil
}
