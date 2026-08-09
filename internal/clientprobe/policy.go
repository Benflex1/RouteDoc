package clientprobe

import "time"

const (
	resolutionTimeout       = 5 * time.Second
	tcpTimeout              = 5 * time.Second
	tlsTimeout              = 5 * time.Second
	httpTimeout             = 10 * time.Second
	totalRunTimeout         = 30 * time.Second
	coherenceWindow         = 60 * time.Second
	maxResponseHeaderBytes  = 64 << 10
	maxResponseBodyPrefix   = 32 << 10
	maxRetainedPerFamily    = 8
	maxPinnedPerFamily      = 1
	maxConcurrentStrategies = 3
	redirectFollowCap       = 0
)

const (
	reasonAddressAttemptCap       = "address_attempt_cap"
	reasonResolutionResultCap     = "resolution_result_cap"
	reasonProxyEnvironmentIgnored = "proxy_environment_detected_ignored"
)
