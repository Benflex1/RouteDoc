package localdiagnosis

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"

	"routedoc/internal/model"
)

const (
	maxProcFileBytes = 8 << 20
	maxProcessLabel  = 256
	maxProcessCount  = 32768
	maxFDCount       = 65536
)

// ProcFS is the deliberately small filesystem seam used by the Linux
// collector. Paths are relative to the procfs root, so tests never need to
// inspect the developer's live /proc.
type ProcFS interface {
	ReadFile(string) ([]byte, error)
	ReadDir(string) ([]string, error)
	Readlink(string) (string, error)
	StatInode(string) (uint64, error)
}

type Listener struct {
	Family  model.AddressFamily
	Address netip.Addr
	Port    uint16
	UID     uint64
	Inode   uint64
	Binding model.BindSemantics
}

type ProcessOwner struct {
	PID   uint64
	Label string
}

type Attribution struct {
	Owners   map[uint64]ProcessOwner
	Complete bool
}

type Inventory struct {
	Port              uint16
	Listeners         []Listener
	TableComplete     map[model.AddressFamily]bool
	NamespaceInode    uint64
	NamespaceComplete bool
	Attribution       Attribution
}

func bindingFor(address netip.Addr) model.BindSemantics {
	if address.IsUnspecified() {
		return model.BindWildcard
	}
	if address == netip.MustParseAddr("127.0.0.1") || address == netip.MustParseAddr("::1") {
		return model.BindLoopback
	}
	return model.BindExact
}

func parseProcTable(data []byte, family model.AddressFamily, port uint16) []Listener {
	listeners, _ := parseProcTableWithStatus(data, family, port)
	return listeners
}

func parseProcTableWithStatus(data []byte, family model.AddressFamily, port uint16) ([]Listener, bool) {
	if len(data) > maxProcFileBytes {
		return nil, false
	}
	listeners := []Listener{}
	complete := true
	for _, rawLine := range bytes.Split(data, []byte{'\n'}) {
		fields := strings.Fields(string(rawLine))
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "sl" {
			continue
		}
		// Malformed rows are ignored individually and make this table
		// incomplete. In particular, no partially decoded row becomes
		// listener evidence.
		if len(fields) < 10 || !strings.HasSuffix(fields[0], ":") || !validProcRowID(fields[0]) || !validProcEndpoint(fields[1], family) || !validProcEndpoint(fields[2], family) || !validHexPair(fields[4]) || !validHexPair(fields[5]) || !validHex(fields[6]) || !validDecimal(fields[7]) || !validDecimal(fields[8]) || !validDecimal(fields[9]) {
			complete = false
			continue
		}
		if len(fields[3]) != 2 || !validHex(fields[3]) {
			complete = false
			continue
		}
		if fields[3] != "0A" {
			continue
		}
		address, rowPort, ok := parseProcLocal(fields[1], family)
		if !ok {
			complete = false
			continue
		}
		if rowPort != port {
			continue
		}
		uid, okUID := parseDecimalUint(fields[7])
		inode, okInode := parseDecimalUint(fields[9])
		if !okUID || !okInode || inode == 0 {
			complete = false
			continue
		}
		listeners = append(listeners, Listener{Family: family, Address: address, Port: rowPort, UID: uid, Inode: inode, Binding: bindingFor(address)})
	}
	sortListeners(listeners)
	return listeners, complete
}

func parseProcLocal(value string, family model.AddressFamily) (netip.Addr, uint16, bool) {
	address, port, ok := parseProcEndpoint(value, family)
	if !ok || port == 0 {
		return netip.Addr{}, 0, false
	}
	return address, port, true
}

func parseProcEndpoint(value string, family model.AddressFamily) (netip.Addr, uint16, bool) {
	if family != model.AddressFamilyIPv4 && family != model.AddressFamilyIPv6 {
		return netip.Addr{}, 0, false
	}
	separator := strings.LastIndexByte(value, ':')
	if separator <= 0 || separator == len(value)-1 {
		return netip.Addr{}, 0, false
	}
	addressText, portText := value[:separator], value[separator+1:]
	parsedPort, ok := parseHexUint(portText)
	if !ok || parsedPort == 0 || parsedPort > 65535 {
		return netip.Addr{}, 0, false
	}
	address, ok := decodeProcAddress(addressText, family)
	if !ok {
		return netip.Addr{}, 0, false
	}
	return address, uint16(parsedPort), true
}

func validProcEndpoint(value string, family model.AddressFamily) bool {
	if family != model.AddressFamilyIPv4 && family != model.AddressFamilyIPv6 {
		return false
	}
	separator := strings.LastIndexByte(value, ':')
	if separator <= 0 || separator == len(value)-1 {
		return false
	}
	port, ok := parseHexUint(value[separator+1:])
	if !ok || port > 65535 {
		return false
	}
	_, ok = decodeProcAddress(value[:separator], family)
	return ok
}

func validProcRowID(value string) bool {
	return strings.HasSuffix(value, ":") && validDecimal(strings.TrimSuffix(value, ":"))
}

func validHexPair(value string) bool {
	separator := strings.LastIndexByte(value, ':')
	return separator > 0 && separator < len(value)-1 && validHex(value[:separator]) && validHex(value[separator+1:])
}

func validHex(value string) bool {
	if value == "" {
		return false
	}
	_, err := strconv.ParseUint(value, 16, 64)
	return err == nil
}

func validDecimal(value string) bool {
	if value == "" {
		return false
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}

func decodeProcAddress(value string, family model.AddressFamily) (netip.Addr, bool) {
	want := 8
	if family == model.AddressFamilyIPv6 {
		want = 32
	}
	if len(value) != want {
		return netip.Addr{}, false
	}
	raw := make([]byte, len(value)/2)
	if _, err := hex.Decode(raw, []byte(value)); err != nil {
		return netip.Addr{}, false
	}
	// procfs prints each 32-bit address word in native byte order. Linux
	// hosts RouteDoctor supports here are little-endian, but reversing each
	// word also makes the intended procfs representation explicit and keeps
	// IPv4 and IPv6 handling symmetrical.
	for start := 0; start < len(raw); start += 4 {
		for left, right := start, start+3; left < right; left, right = left+1, right-1 {
			raw[left], raw[right] = raw[right], raw[left]
		}
	}
	if family == model.AddressFamilyIPv4 {
		return netip.AddrFrom4([4]byte{raw[0], raw[1], raw[2], raw[3]}), true
	}
	var octets [16]byte
	copy(octets[:], raw)
	return netip.AddrFrom16(octets), true
}

func parseHexUint(value string) (uint64, bool) {
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 16, 64)
	return parsed, err == nil
}

func parseDecimalUint(value string) (uint64, bool) {
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	return parsed, err == nil
}

func sortListeners(listeners []Listener) {
	sort.SliceStable(listeners, func(i, j int) bool {
		if listeners[i].Family != listeners[j].Family {
			return listeners[i].Family < listeners[j].Family
		}
		if listeners[i].Address != listeners[j].Address {
			return listeners[i].Address.Compare(listeners[j].Address) < 0
		}
		if listeners[i].Port != listeners[j].Port {
			return listeners[i].Port < listeners[j].Port
		}
		return listeners[i].Inode < listeners[j].Inode
	})
}

func parseSocketLink(value string) (uint64, bool) {
	if !strings.HasPrefix(value, "socket:[") || !strings.HasSuffix(value, "]") {
		return 0, false
	}
	inode, ok := parseDecimalUint(strings.TrimSuffix(strings.TrimPrefix(value, "socket:["), "]"))
	return inode, ok && inode != 0
}

func safeProcessLabel(raw []byte, pid uint64) string {
	raw = raw[:min(len(raw), maxProcessLabel)]
	label := strings.TrimSpace(string(raw))
	if label == "" {
		return "process " + strconv.FormatUint(pid, 10)
	}
	for _, r := range label {
		if r < 0x20 || r == 0x7f {
			return "process " + strconv.FormatUint(pid, 10)
		}
	}
	return label
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func collectWithProcFS(fs ProcFS, port uint16) Inventory {
	inventory := Inventory{Port: port, Listeners: []Listener{}, TableComplete: map[model.AddressFamily]bool{}}
	if fs == nil || port == 0 {
		return inventory
	}
	for _, table := range []struct {
		family model.AddressFamily
		path   string
	}{
		{model.AddressFamilyIPv4, "net/tcp"},
		{model.AddressFamilyIPv6, "net/tcp6"},
	} {
		data, err := fs.ReadFile(table.path)
		if err != nil || len(data) > maxProcFileBytes {
			inventory.TableComplete[table.family] = false
			continue
		}
		listeners, complete := parseProcTableWithStatus(data, table.family, port)
		inventory.TableComplete[table.family] = complete
		inventory.Listeners = append(inventory.Listeners, listeners...)
	}
	sortListeners(inventory.Listeners)
	inventory.NamespaceInode, _ = fs.StatInode("self/ns/net")
	inventory.NamespaceComplete = inventory.NamespaceInode != 0
	inventory.Attribution = attributeWithProcFS(fs, inventory.Listeners)
	return inventory
}

func attributeWithProcFS(fs ProcFS, listeners []Listener) Attribution {
	result := Attribution{Owners: map[uint64]ProcessOwner{}, Complete: false}
	if fs == nil || len(listeners) == 0 {
		result.Complete = fs != nil
		return result
	}
	wanted := map[uint64]bool{}
	for _, listener := range listeners {
		if listener.Inode != 0 {
			wanted[listener.Inode] = true
		}
	}
	pids, err := fs.ReadDir("")
	if err != nil {
		return result
	}
	sort.Strings(pids)
	result.Complete = true
	if len(pids) > maxProcessCount {
		result.Complete = false
		pids = pids[:maxProcessCount]
	}
	seenPIDs := 0
	for _, name := range pids {
		pid, ok := parseDecimalUint(name)
		if !ok || pid == 0 || seenPIDs >= maxProcessCount {
			continue
		}
		seenPIDs++
		fds, err := fs.ReadDir(path.Join(name, "fd"))
		if err != nil {
			result.Complete = false
			continue
		}
		if len(fds) > maxFDCount {
			fds = fds[:maxFDCount]
			result.Complete = false
		}
		sort.Strings(fds)
		for _, fd := range fds {
			target, err := fs.Readlink(path.Join(name, "fd", fd))
			if err != nil {
				// FDs can disappear between ReadDir and Readlink.
				result.Complete = false
				continue
			}
			inode, ok := parseSocketLink(target)
			if !ok || !wanted[inode] || result.Owners[inode].PID != 0 {
				continue
			}
			labelBytes, labelErr := fs.ReadFile(path.Join(name, "comm"))
			label := "process " + strconv.FormatUint(pid, 10)
			if labelErr == nil && len(labelBytes) <= maxProcessLabel {
				label = safeProcessLabel(labelBytes, pid)
			}
			result.Owners[inode] = ProcessOwner{PID: pid, Label: label}
		}
	}
	return result
}

var ErrUnsupportedPlatform = errors.New("local diagnosis is only supported on Linux")
