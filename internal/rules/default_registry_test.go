package rules

import "testing"

func TestDefaultRegistryExactlyThreeRules(t *testing.T) {
	r := DefaultRegistry()
	ids := r.RuleIDs()
	want := []string{"listener.no_matching_listener_visible/v1", "tcp.connection_refused/v1", "tls.certificate_hostname_mismatch/v1"}
	if len(ids) != 3 {
		t.Fatalf("%#v", ids)
	}
	for i, x := range want {
		if string(ids[i]) != x {
			t.Fatalf("got %#v", ids)
		}
	}
}
