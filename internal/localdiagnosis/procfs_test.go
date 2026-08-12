package localdiagnosis

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"routedoc/internal/model"
)

const (
	tcpFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12346 1
   2: 0200000A:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12347 1
   3: 0100007F:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12348 1
   4: 0100007F:1F90 00000000:0000 01 00000000:00000000 00:00000000 00000000 0 0 12349 1
`
	tcp6Fixture = `  sl  local_address                         rem_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 22345 1
   1: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 22346 1
   2: B80D0120000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 22347 1
`
)

func TestParseProcTableBindingsAndFilters(t *testing.T) {
	got := parseProcTable([]byte(tcpFixture), model.AddressFamilyIPv4, 8080)
	if len(got) != 3 {
		t.Fatalf("got %d listeners: %#v", len(got), got)
	}
	want := []struct {
		address netip.Addr
		binding model.BindSemantics
		inode   uint64
	}{
		{netip.MustParseAddr("0.0.0.0"), model.BindWildcard, 12346},
		{netip.MustParseAddr("10.0.0.2"), model.BindExact, 12347},
		{netip.MustParseAddr("127.0.0.1"), model.BindLoopback, 12345},
	}
	for i, want := range want {
		if got[i].Address != want.address || got[i].Binding != want.binding || got[i].Inode != want.inode {
			t.Fatalf("listener %d = %#v, want %#v", i, got[i], want)
		}
	}
}

func TestParseProcTableIPv6Bindings(t *testing.T) {
	got := parseProcTable([]byte(tcp6Fixture), model.AddressFamilyIPv6, 8080)
	if len(got) != 3 {
		t.Fatalf("got %d listeners: %#v", len(got), got)
	}
	want := []struct {
		address netip.Addr
		binding model.BindSemantics
	}{
		{netip.MustParseAddr("::"), model.BindWildcard},
		{netip.MustParseAddr("::1"), model.BindLoopback},
		{netip.MustParseAddr("2001:db8::1"), model.BindExact},
	}
	for i, item := range want {
		if got[i].Address != item.address || got[i].Binding != item.binding {
			t.Fatalf("listener %d = %#v, want %#v", i, got[i], item)
		}
	}
}

func TestParseProcTableMalformedAndEmptyInput(t *testing.T) {
	malformed := "0: 0100007F:ZZZZ 00000000:0000 0A x x x x x not-an-inode\n"
	if got := parseProcTable([]byte(malformed), model.AddressFamilyIPv4, 8080); len(got) != 0 {
		t.Fatalf("malformed row produced evidence: %#v", got)
	}
	malformedShape := "0: 0100007F:1F90 not-an-endpoint 0A 00000000:00000000 00:00000000 00000000 0 0 12345 1\n"
	if got := parseProcTable([]byte(malformedShape), model.AddressFamilyIPv4, 8080); len(got) != 0 {
		t.Fatalf("malformed row shape produced evidence: %#v", got)
	}
	if got := parseProcTable(nil, model.AddressFamilyIPv4, 8080); len(got) != 0 {
		t.Fatalf("empty input produced evidence: %#v", got)
	}
	if got := parseProcTable([]byte(tcpFixture), model.AddressFamilyIPv4, 8082); len(got) != 0 {
		t.Fatalf("unrelated port produced evidence: %#v", got)
	}
}

func TestParseProcTableTreatsOnlyCanonicalLoopbackAddressesAsLoopback(t *testing.T) {
	data := []byte("0: 0200007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345 1\n")
	got := parseProcTable(data, model.AddressFamilyIPv4, 8080)
	if len(got) != 1 {
		t.Fatalf("got %d listeners: %#v", len(got), got)
	}
	if got[0].Address != netip.MustParseAddr("127.0.0.2") || got[0].Binding != model.BindExact {
		t.Fatalf("listener = %#v, want exact 127.0.0.2", got[0])
	}
}

func TestCollectProcFSMultipleFamiliesAndCompleteness(t *testing.T) {
	fs := newFakeProcFS()
	fs.files["net/tcp"] = []byte(tcpFixture)
	fs.files["net/tcp6"] = []byte(tcp6Fixture)
	fs.inodes["self/ns/net"] = 77
	got := CollectWithProcFS(fs, 8080)
	if len(got.Listeners) != 6 || !got.TableComplete[model.AddressFamilyIPv4] || !got.TableComplete[model.AddressFamilyIPv6] {
		t.Fatalf("inventory = %#v", got)
	}
	if got.NamespaceInode != 77 || !got.NamespaceComplete {
		t.Fatalf("namespace = %#v", got)
	}
	if got.Listeners[0].Family != model.AddressFamilyIPv4 || got.Listeners[len(got.Listeners)-1].Family != model.AddressFamilyIPv6 {
		t.Fatalf("listeners were not deterministic: %#v", got.Listeners)
	}

	fs.files["net/tcp6"] = nil
	fs.errors["net/tcp6"] = errors.New("proc entry disappeared")
	partial := CollectWithProcFS(fs, 8080)
	if partial.TableComplete[model.AddressFamilyIPv6] || !partial.TableComplete[model.AddressFamilyIPv4] {
		t.Fatalf("partial inventory = %#v", partial.TableComplete)
	}
}

func TestCollectProcFSMarksMalformedTablePartialWithoutDroppingValidListeners(t *testing.T) {
	fs := newFakeProcFS()
	fs.files["net/tcp"] = []byte("  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		"0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345 1\n" +
		"1: malformed row\n" +
		"2: 0100007F:1F91 00000000:0000 ZZ 00000000:00000000 00:00000000 00000000 0 0 12346 1\n")
	fs.files["net/tcp6"] = []byte("  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n")
	fs.inodes["self/ns/net"] = 77

	got := CollectWithProcFS(fs, 8080)
	if len(got.Listeners) != 1 || got.TableComplete[model.AddressFamilyIPv4] {
		t.Fatalf("inventory = %#v, want one listener and partial IPv4 visibility", got)
	}
}

func TestCollectProcFSMarksInvalidStatePartial(t *testing.T) {
	fs := newFakeProcFS()
	fs.files["net/tcp"] = []byte("  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		"0: 0100007F:1F90 00000000:0000 ZZ 00000000:00000000 00:00000000 00000000 0 0 12345 1\n")
	fs.files["net/tcp6"] = []byte("  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n")
	fs.inodes["self/ns/net"] = 77

	got := CollectWithProcFS(fs, 8080)
	if len(got.Listeners) != 0 || got.TableComplete[model.AddressFamilyIPv4] {
		t.Fatalf("inventory = %#v, want empty listeners and partial IPv4 visibility", got)
	}
}

func TestProcessAttributionKnownOwner(t *testing.T) {
	fs := newFakeProcFS()
	fs.dirs[""] = []string{"101", "100", "hidden"}
	fs.dirs["100/fd"] = []string{"4"}
	fs.links["100/fd/4"] = "socket:[12345]"
	fs.files["100/comm"] = []byte("caddy\n")
	fs.dirs["101/fd"] = []string{"5"}
	fs.links["101/fd/5"] = "socket:[99999]"
	got := AttributeWithProcFS(fs, []Listener{{Inode: 12345}})
	if !got.Complete || !reflect.DeepEqual(got.Owners[12345], ProcessOwner{PID: 100, Label: "caddy"}) {
		t.Fatalf("attribution = %#v", got)
	}
}

func TestProcessAttributionGracefullyHandlesPermissionAndDisappearingFD(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*fakeProcFS)
	}{
		{name: "permission denied", setup: func(fs *fakeProcFS) {
			fs.dirs[""] = []string{"100"}
			fs.errors["100/fd"] = errors.New("permission denied")
		}},
		{name: "process disappears", setup: func(fs *fakeProcFS) {
			fs.dirs[""] = []string{"100"}
			fs.dirs["100/fd"] = []string{"4"}
			fs.errors["100/fd/4"] = errors.New("gone")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeProcFS()
			tc.setup(fs)
			got := AttributeWithProcFS(fs, []Listener{{Inode: 12345}})
			if len(got.Owners) != 0 || got.Complete {
				t.Fatalf("attribution = %#v", got)
			}
		})
	}
}

func TestProcessAttributionKeepsOwnershipWhenCommIsUnreadable(t *testing.T) {
	fs := newFakeProcFS()
	fs.dirs[""] = []string{"100"}
	fs.dirs["100/fd"] = []string{"4"}
	fs.links["100/fd/4"] = "socket:[12345]"
	fs.errors["100/comm"] = errors.New("permission denied")

	got := AttributeWithProcFS(fs, []Listener{{Inode: 12345}})
	owner, ok := got.Owners[12345]
	if !got.Complete || !ok || owner.PID != 100 || owner.Label != "process 100" {
		t.Fatalf("attribution = %#v, want bounded ownership with fallback label", got)
	}
}

type fakeProcFS struct {
	files  map[string][]byte
	dirs   map[string][]string
	links  map[string]string
	inodes map[string]uint64
	errors map[string]error
}

func newFakeProcFS() *fakeProcFS {
	return &fakeProcFS{files: map[string][]byte{}, dirs: map[string][]string{}, links: map[string]string{}, inodes: map[string]uint64{}, errors: map[string]error{}}
}

func (f *fakeProcFS) ReadFile(name string) ([]byte, error) {
	if err := f.errors[name]; err != nil {
		return nil, err
	}
	data, ok := f.files[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte{}, data...), nil
}

func (f *fakeProcFS) ReadDir(name string) ([]string, error) {
	if err := f.errors[name]; err != nil {
		return nil, err
	}
	data, ok := f.dirs[name]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]string{}, data...), nil
}

func (f *fakeProcFS) Readlink(name string) (string, error) {
	if err := f.errors[name]; err != nil {
		return "", err
	}
	data, ok := f.links[name]
	if !ok {
		return "", errors.New("not found")
	}
	return data, nil
}

func (f *fakeProcFS) StatInode(name string) (uint64, error) {
	if err := f.errors[name]; err != nil {
		return 0, err
	}
	data, ok := f.inodes[name]
	if !ok {
		return 0, errors.New("not found")
	}
	return data, nil
}
