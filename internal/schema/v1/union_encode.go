package v1

import (
	"bytes"
	"encoding/json"
)

func marshalOrdered(v interface{}) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	x := b.Bytes()
	return x[:len(x)-1], nil
}
func (p wAssertionParams) MarshalJSON() ([]byte, error) {
	switch p.Kind {
	case "LOCAL_ORIGIN_PARTICIPATION":
		return marshalOrdered(struct {
			Kind              string `json:"kind"`
			URLTargetEntityID string `json:"url_target_entity_id"`
			HostVantageID     string `json:"host_vantage_id"`
		}{p.Kind, p.URLTargetEntityID, p.HostVantageID})
	case "EXPECTED_PATH_EDGE":
		return marshalOrdered(struct {
			Kind     string `json:"kind"`
			From     string `json:"from_entity_id"`
			To       string `json:"to_entity_id"`
			Relation string `json:"relation"`
		}{p.Kind, p.FromEntityID, p.ToEntityID, p.Relation})
	case "HTTP_EXPECTATION":
		return marshalOrdered(struct {
			Kind            string  `json:"kind"`
			ExpectationKind string  `json:"expectation_kind"`
			StatusMin       *uint16 `json:"status_min,omitempty"`
			StatusMax       *uint16 `json:"status_max,omitempty"`
			HeaderName      *string `json:"header_name,omitempty"`
		}{p.Kind, p.ExpectationKind, p.StatusMin, p.StatusMax, p.HeaderName})
	case "CONFIG_SOURCE_SELECTION":
		return marshalOrdered(struct {
			Kind          string `json:"kind"`
			ComponentKind string `json:"component_kind"`
			SourceKind    string `json:"source_kind"`
		}{p.Kind, p.ComponentKind, p.SourceKind})
	case "PRIVATE_REDIRECT_TRANSITION_ALLOWED":
		return marshalOrdered(struct {
			Kind string `json:"kind"`
			From string `json:"from_address_scope"`
			To   string `json:"to_address_scope"`
		}{p.Kind, p.FromAddressScope, p.ToAddressScope})
	}
	return marshalOrdered(struct {
		Kind string `json:"kind"`
	}{p.Kind})
}
func (i wEntityIdentity) MarshalJSON() ([]byte, error) {
	switch i.Kind {
	case "URL_TARGET":
		return marshalOrdered(struct {
			Kind   string `json:"kind"`
			Marker bool   `json:"marker"`
		}{i.Kind, i.Marker != nil && *i.Marker})
	case "HOSTNAME":
		return marshalOrdered(struct {
			Kind     string `json:"kind"`
			Hostname string `json:"hostname"`
		}{i.Kind, i.Hostname})
	case "IP_ADDRESS":
		return marshalOrdered(struct {
			Kind    string `json:"kind"`
			Address string `json:"address"`
		}{i.Kind, i.Address})
	case "SOCKET_ENDPOINT", "UPSTREAM_ENDPOINT":
		return marshalOrdered(struct {
			Kind     string     `json:"kind"`
			Endpoint *wEndpoint `json:"endpoint"`
		}{i.Kind, i.Endpoint})
	case "TLS_PEER":
		return marshalOrdered(struct {
			Kind        string `json:"kind"`
			Fingerprint string `json:"fingerprint"`
		}{i.Kind, i.Fingerprint})
	case "HTTP_EXCHANGE":
		return marshalOrdered(struct {
			Kind    string `json:"kind"`
			Ordinal uint64 `json:"ordinal"`
		}{i.Kind, i.Ordinal})
	case "PROXY_INSTANCE", "PROXY_ROUTE":
		return marshalOrdered(struct {
			Kind        string `json:"kind"`
			SyntheticID string `json:"synthetic_id"`
		}{i.Kind, i.SyntheticID})
	case "LISTENER":
		return marshalOrdered(struct {
			Kind     string     `json:"kind"`
			Endpoint *wEndpoint `json:"endpoint"`
		}{i.Kind, i.Endpoint})
	case "PROCESS":
		return marshalOrdered(struct {
			Kind string `json:"kind"`
			PID  uint64 `json:"pid"`
		}{i.Kind, i.PID})
	case "CONTAINER":
		return marshalOrdered(struct {
			Kind        string `json:"kind"`
			RuntimeID   string `json:"runtime_id"`
			ContainerID string `json:"container_id"`
		}{i.Kind, i.RuntimeID, i.ContainerID})
	case "NETWORK_NAMESPACE":
		return marshalOrdered(struct {
			Kind           string `json:"kind"`
			NamespaceInode uint64 `json:"namespace_inode"`
		}{i.Kind, i.NamespaceInode})
	}
	return marshalOrdered(struct {
		Kind string `json:"kind"`
	}{i.Kind})
}
func (p wPayload) MarshalJSON() ([]byte, error) {
	switch p.Kind {
	case "SYSTEM_RESOLUTION_RESULT":
		return marshalOrdered(struct {
			Kind     string  `json:"kind"`
			Hostname string  `json:"hostname_entity_id"`
			Address  *string `json:"address_entity_id,omitempty"`
			Family   string  `json:"address_family"`
			Result   string  `json:"result"`
		}{p.Kind, p.HostnameEntityID, p.AddressEntityID, p.AddressFamily, p.Result})
	case "TCP_CONNECTION_RESULT":
		return marshalOrdered(struct {
			Kind     string `json:"kind"`
			Endpoint string `json:"endpoint_entity_id"`
			Result   string `json:"result"`
			Duration int64  `json:"duration_ns"`
			Deadline bool   `json:"deadline_part_of_expected_condition"`
		}{p.Kind, p.EndpointEntityID, p.Result, p.DurationNS, p.DeadlinePartOfExpectedCondition})
	case "TLS_TRANSPORT_RESULT":
		return marshalOrdered(struct {
			Kind     string  `json:"kind"`
			Peer     string  `json:"peer_entity_id"`
			Result   string  `json:"result"`
			Version  string  `json:"protocol_version"`
			Cipher   string  `json:"cipher_suite"`
			ALPN     string  `json:"negotiated_alpn"`
			SNI      string  `json:"sni_sent"`
			Alert    *uint16 `json:"alert_code,omitempty"`
			Duration int64   `json:"duration_ns"`
		}{p.Kind, p.PeerEntityID, p.Result, p.ProtocolVersion, p.CipherSuite, p.NegotiatedALPN, p.SNISent, p.AlertCode, p.DurationNS})
	case "TLS_PEER_SUMMARY":
		return marshalOrdered(struct {
			Kind     string `json:"kind"`
			Peer     string `json:"peer_entity_id"`
			Count    uint64 `json:"certificate_count"`
			Leaf     string `json:"leaf_sha256"`
			Before   string `json:"not_before"`
			After    string `json:"not_after"`
			SAN      string `json:"san_type"`
			SANCount uint64 `json:"san_count"`
		}{p.Kind, p.PeerEntityID, p.CertificateCount, p.LeafSHA256, p.NotBefore, p.NotAfter, p.SANType, p.SANCount})
	case "CERTIFICATE_VERIFICATION_RESULT":
		return marshalOrdered(struct {
			Kind     string  `json:"kind"`
			Peer     string  `json:"peer_entity_id"`
			Hostname string  `json:"verified_hostname"`
			Time     string  `json:"verification_time"`
			Trust    string  `json:"trust_source"`
			Result   string  `json:"result"`
			Reason   *string `json:"failure_reason,omitempty"`
		}{p.Kind, p.PeerEntityID, p.VerifiedHostname, p.VerificationTime, p.TrustSource, p.Result, p.FailureReason})
	case "HTTP_RESULT":
		return marshalOrdered(struct {
			Kind       string   `json:"kind"`
			Exchange   string   `json:"exchange_entity_id"`
			Result     string   `json:"result_kind"`
			Status     uint16   `json:"status_code"`
			RedirectID *string  `json:"redirect_target_entity_id,omitempty"`
			Redirect   *wTarget `json:"redirect_target,omitempty"`
		}{p.Kind, p.ExchangeEntityID, p.ResultKind, p.StatusCode, p.RedirectTargetEntityID, p.RedirectTarget})
	case "ACTIVE_PROXY_ROUTE_SUMMARY", "CONFIGURED_PROXY_ROUTE_SUMMARY":
		return marshalOrdered(struct {
			Kind     string  `json:"kind"`
			Route    string  `json:"proxy_route_entity_id"`
			Upstream *string `json:"upstream_entity_id,omitempty"`
			Matcher  string  `json:"matcher_kind"`
			Match    string  `json:"match_result"`
		}{p.Kind, p.ProxyRouteEntityID, p.UpstreamEntityID, p.MatcherKind, p.MatchResult})
	case "UPSTREAM_SELECTION_SUMMARY":
		return marshalOrdered(struct {
			Kind     string  `json:"kind"`
			Route    string  `json:"proxy_route_entity_id"`
			Upstream *string `json:"upstream_entity_id,omitempty"`
			Result   string  `json:"result"`
		}{p.Kind, p.ProxyRouteEntityID, p.UpstreamEntityID, p.Result})
	case "LISTENER_INVENTORY_ENTRY":
		return marshalOrdered(struct {
			Kind      string `json:"kind"`
			Listener  string `json:"listener_entity_id"`
			Namespace string `json:"namespace_entity_id"`
			Protocol  string `json:"protocol"`
			Family    string `json:"address_family"`
			Bind      string `json:"bind_semantics"`
			Port      uint16 `json:"port"`
		}{p.Kind, p.ListenerEntityID, p.NamespaceEntityID, p.Protocol, p.AddressFamily, p.BindSemantics, p.Port})
	case "LISTENER_INVENTORY_RESULT":
		return marshalOrdered(struct {
			Kind      string `json:"kind"`
			Namespace string `json:"namespace_entity_id"`
			Protocol  string `json:"protocol"`
			Family    string `json:"address_family"`
			Bind      string `json:"bind_semantics"`
			PortStart uint16 `json:"port_start"`
			PortEnd   uint16 `json:"port_end"`
			Count     uint64 `json:"matching_listener_count"`
		}{p.Kind, p.NamespaceEntityID, p.Protocol, p.AddressFamily, p.BindSemantics, p.PortStart, p.PortEnd, p.MatchingListenerCount})
	case "PROCESS_OWNERSHIP_ENTRY":
		return marshalOrdered(struct {
			Kind     string  `json:"kind"`
			Listener string  `json:"listener_entity_id"`
			Process  *string `json:"process_entity_id,omitempty"`
			Result   string  `json:"result"`
		}{p.Kind, p.ListenerEntityID, p.ProcessEntityID, p.Result})
	case "DOCKER_RUNTIME_SUMMARY":
		var namespace, endpoint *string
		if p.NamespaceEntityID != "" {
			namespace = &p.NamespaceEntityID
		}
		if p.EndpointEntityID != "" {
			endpoint = &p.EndpointEntityID
		}
		return marshalOrdered(struct {
			Kind      string  `json:"kind"`
			Fact      string  `json:"fact_kind"`
			Container string  `json:"container_entity_id"`
			Namespace *string `json:"namespace_entity_id,omitempty"`
			Endpoint  *string `json:"endpoint_entity_id,omitempty"`
			State     string  `json:"runtime_state"`
		}{p.Kind, p.FactKind, p.ContainerEntityID, namespace, endpoint, p.RuntimeState})
	case "CAPABILITY_PERMISSION_RESULT":
		return marshalOrdered(struct {
			Kind       string `json:"kind"`
			Capability string `json:"capability_id"`
			Result     string `json:"result"`
			Reason     string `json:"reason_code"`
		}{p.Kind, p.CapabilityID, p.Result, p.ReasonCode})
	}
	return marshalOrdered(struct {
		Kind string `json:"kind"`
	}{p.Kind})
}
func (p wClaimParams) MarshalJSON() ([]byte, error) {
	switch p.Kind {
	case "TLS_CERTIFICATE_HOSTNAME_MISMATCH":
		return marshalOrdered(struct {
			Kind     string `json:"kind"`
			Peer     string `json:"peer_entity_id"`
			Hostname string `json:"hostname"`
			Time     string `json:"verification_time"`
			Trust    string `json:"trust_source"`
		}{p.Kind, p.PeerEntityID, p.Hostname, p.VerificationTime, p.TrustSource})
	case "TCP_CONNECTION_REFUSED":
		return marshalOrdered(struct {
			Kind     string `json:"kind"`
			Endpoint string `json:"endpoint_entity_id"`
			Vantage  string `json:"vantage_id"`
			At       string `json:"observed_at"`
		}{p.Kind, p.EndpointEntityID, p.VantageID, p.ObservedAt})
	case "NO_MATCHING_LISTENER_VISIBLE":
		return marshalOrdered(struct {
			Kind      string `json:"kind"`
			Namespace string `json:"namespace_entity_id"`
			Vantage   string `json:"vantage_id"`
			Protocol  string `json:"protocol"`
			Family    string `json:"address_family"`
			Bind      string `json:"bind_semantics"`
			Port      uint16 `json:"port"`
		}{p.Kind, p.NamespaceEntityID, p.VantageID, p.Protocol, p.AddressFamily, p.BindSemantics, p.Port})
	}
	return marshalOrdered(struct {
		Kind string `json:"kind"`
	}{p.Kind})
}
func (m wMissing) MarshalJSON() ([]byte, error) {
	return marshalOrdered(struct {
		Kind                  string            `json:"kind"`
		ObservationKind       *string           `json:"observation_kind,omitempty"`
		VisibilitySubjectKind *string           `json:"visibility_subject_kind,omitempty"`
		VisibilityScope       *wVisibilityScope `json:"visibility_scope,omitempty"`
		VantageID             *string           `json:"vantage_id,omitempty"`
	}{m.Kind, m.ObservationKind, m.VisibilitySubjectKind, m.VisibilityScope, m.VantageID})
}
