package rules

import (
	"routedoc/internal/rules/listener"
	"routedoc/internal/rules/tcp"
	"routedoc/internal/rules/tls"
)

func DefaultRegistry() Registry {
	r, _ := NewRegistry(listener.NewNoMatchingListenerVisible(), tcp.NewConnectionRefused(), tls.NewHostnameMismatch())
	return r
}
