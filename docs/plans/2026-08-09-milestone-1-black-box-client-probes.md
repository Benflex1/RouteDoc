# RouteDoctor Milestone 1: Black-Box Client Probes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `routedoc https://example.com` perform a bounded, evidence-backed client diagnosis from the current client vantage and render a useful validated RouteDoctor report.

**Architecture:** Add one focused `internal/clientprobe` package that parses a transient URL, resolves and retains endpoint alternatives, runs one ordinary hostname attempt plus one pinned attempt per available family, and assembles only existing architecture-1.3 evidence. Service-path branches represent endpoint alternatives, never probe modes. The package validates and evaluates the report with the frozen M0 model; exit status is derived only from the resulting `ValidatedEvaluatedRun`.

**Tech Stack:** Go 1.26.5 standard library (`context`, `net`, `net/netip`, `net/http`, `net/url`, `crypto/tls`, `crypto/x509`, `errors`, `time`) plus the repository's existing internal model, rules, renderer, and schema packages. Existing third-party modules remain test-only; add no production dependency.

## Global Constraints

- Authoritative base: `main` at `250aca9f34b78451c415ef9a77afd2a726d5b67d`.
- Architecture remains design `1.3`; report schema remains exactly `1.0.0`.
- Milestone 0 validation, canonical JSON, rule, selection, and compatibility behavior is frozen and must not weaken.
- M1 runs one ordinary hostname attempt, one pinned IPv4 attempt when available, and one pinned IPv6 attempt when available.
- Retain at most eight resolved addresses per family; pin only the first deterministic address per family.
- Redirect responses are observed and sanitized but never followed; redirect-follow cap is `0`.
- No new persisted observation, claim, finding, enum, payload field, rule version, schema version, or arbitrary metadata.
- No Linux origin inspection, `/proc`, Caddy, Docker, proxy use, plugins, monitoring, daemon behavior, privilege escalation, or M2 multi-address/redirect hardening.
- Reject URL credentials; send no authentication or cookies; disable HTTP proxy environment use and automatic decompression.
- Preserve the URL hostname for TLS SNI and HTTP Host on pinned connections.
- Never send HTTP after failed or unknown certificate verification.
- Persist no raw path segments, query values, fragment, response body, response headers, certificate chain, or raw error strings.
- All required tests run offline. Production imports remain Go-standard-library-only.

---

## Fixed M1 policy

Implement these as unexported constants in `internal/clientprobe/policy.go`; do not add flags or configuration:

```go
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
```

`maxConcurrentStrategies` bounds RouteDoctor's three logical strategies. The normal standard-library dial remains one strategy even if the Go dialer internally races address families.

## Package and file map

```text
cmd/routedoc/
  app.go                 add live URL dispatch and validated-report exit mapping
  flags.go               parse URL [--verbose] [--json]
  app_test.go            CLI boundary and exit tests
  probe_test.go          offline CLI probe tests

internal/clientprobe/
  policy.go              fixed M1 constants and safe reason-code constants
  target.go              transient URL parsing and PathSummary construction
  normalize.go           typed error/x509 normalization; never string parsing
  probe.go               orchestration, resolver retention, strategy scheduling
  transport.go           pinned/normal TCP, TLS, verification, bounded HTTP
  assemble.go            deterministic IDs, topology, checks, observations, evaluation
  status.go              pure ValidatedEvaluatedRun -> report status
  target_test.go
  normalize_test.go
  topology_test.go
  transport_test.go
  status_test.go
  integration_test.go
  testcert_test.go        generated test CA/certificate helpers only

internal/render/
  client.go              safe branch/check summaries for client reports
  concise.go             invoke client summary without changing selection
  verbose.go             include direct check evidence and normalized reasons
  render_test.go

testdata/reports/v1/
  client-probe-http-success/{report.json,concise.txt,verbose.txt}
  client-probe-tls-untrusted/{report.json,concise.txt,verbose.txt}
  client-probe-unattempted-address/{report.json,concise.txt,verbose.txt}
  README.md

README.md                document shorthand, bounds, redirects, and GET warning
cmd/routedoc/version.go  advance producer label to Milestone 1
```

Dependency direction is:

```text
cmd/routedoc -> internal/clientprobe -> internal/rules -> internal/selection
      |                    |
      +-> internal/render  +-> internal/model
      +-> internal/schema/v1
```

`internal/clientprobe` must not import `render` or `schema/v1`. Renderer and schema never run probes. CLI contains dispatch/output wiring only.

## Fixed internal interfaces

Use these names unless an existing Go compiler constraint requires a mechanical adjustment:

```go
package clientprobe

type ReportStatus uint8

const (
	StatusIndeterminate ReportStatus = iota
	StatusSatisfied
	StatusBlocked
)

type InputError struct{ Code string }

func (e *InputError) Error() string

func Diagnose(
	ctx context.Context,
	rawURL string,
	producer model.Producer,
) (model.ValidatedEvaluatedRun, error)

func Status(v model.ValidatedEvaluatedRun) ReportStatus
```

Tests in package `clientprobe` use an unexported dependency bundle; it is not a public adapter API:

```go
type dependencies struct {
	now         func() time.Time
	lookupNetIP func(context.Context, string, string) ([]netip.Addr, error)
	dialContext func(context.Context, string, string) (net.Conn, error)
	systemRoots func() (*x509.CertPool, error)
}

func diagnose(
	ctx context.Context,
	rawURL string,
	producer model.Producer,
	d dependencies,
) (model.ValidatedEvaluatedRun, error)
```

`Diagnose` supplies production dependencies and delegates to `diagnose`. Network failures are report evidence, not returned errors. Return an error only for `InputError` or an internal construction/validation/evaluation failure.

Transient orchestration values may use `attemptMode` (`normal` or `pinned`) and `endpointKey`, but neither is persisted. Persisted branches are keyed only by concrete endpoint alternatives.

## Topology contract used by every task

For each retained resolution result, create a `HOSTNAME`, `IP_ADDRESS`, and effective-port `SOCKET_ENDPOINT`. The branch initially contains only the legitimate directly observed edge:

```text
HOSTNAME --RESOLVES_TO / SYSTEM_RESOLUTION_RESULT--> IP_ADDRESS
```

The branch's TCP check definition names its exact `SOCKET_ENDPOINT`. If the endpoint is not attempted because of the pin cap, the TCP execution is `NOT_RUN/SKIPPED` with `address_attempt_cap`; HTTPS/HTTP dependents are skipped. Do not invent an `IP_ADDRESS -> SOCKET_ENDPOINT` edge before a TCP observation exists.

When a pinned or normal attempt proves a concrete endpoint, add:

```text
IP_ADDRESS --CONNECTS_TO / TCP_CONNECTION_RESULT--> SOCKET_ENDPOINT
```

for a retained address. A refused/timed-out/failed exact TCP result also legitimately supports the attempted `CONNECTS_TO` path edge, as in the existing M0 branch fixtures; the observation states the result and the rule remains endpoint-local.

If the normal hostname attempt succeeds at an endpoint absent from the retained resolution set, create a `SOCKET_ENDPOINT` entity and a new endpoint branch with:

```text
URL_TARGET --CONNECTS_TO / accepted TCP_CONNECTION_RESULT--> SOCKET_ENDPOINT
```

This is directly observed connection topology and matches the existing fixture pattern. Do not create an `IP_ADDRESS`, `SYSTEM_RESOLUTION_RESULT`, or `RESOLVES_TO` edge for that endpoint because the earlier resolver observation did not establish it. Later TLS/verification/HTTP edges may extend that branch using their own observations.

The normal strategy has its own `TCP_CONNECTION` check definition with `NETWORK` input naming the persisted hostname entity. If it fails before `net.Conn.RemoteAddr()` establishes a concrete TCP endpoint, emit only its normalized unscoped `CheckExecution`: no branch ID, endpoint entity, TCP observation, or path edge. This check definition records what was attempted without claiming which resolved alternative failed.

Allocate all persisted IDs only after resolution and strategy collection finish. Use `run-000001` for the report-local run ID and allocate every other ID as its existing type prefix plus a zero-padded sequence (`entity-000001`, `branch-000001`, `check-000001`, and so on). Sort endpoint branches by IPv4 before IPv6, then `netip.Addr.Compare`, then port; the normal-discovered outside endpoint enters the same topology sort. Sort transient facts by endpoint, stage, attempt mode, and observation time before assigning IDs. Allocate the fixed target, hostname, and client-vantage records before sorted endpoint records. Goroutine completion order must never select IDs or wire order.

---

### Task 1: Freeze target parsing, policy, and error normalization

**Files:**
- Create: `internal/clientprobe/policy.go`
- Create: `internal/clientprobe/target.go`
- Create: `internal/clientprobe/normalize.go`
- Create: `internal/clientprobe/target_test.go`
- Create: `internal/clientprobe/normalize_test.go`

**Interfaces:**
- Produces: `requestTarget`, `parseTarget(string)`, fixed policy constants, safe normalization helpers, and `InputError`.
- Consumes: only Go standard library and existing `model.Target`, `model.PathSummary`, and result enums.

- [ ] **Step 1: Write failing target and policy tests**

Cover table cases for HTTP/HTTPS defaults, explicit ports, lowercase/trailing-dot normalization, empty path becoming `/`, segment/trailing/query summary, fragment removal, userinfo rejection, unsupported scheme, missing host, invalid port, control characters, non-ASCII/unrepresentable hostname, and secret path/query absence from `InputError.Error()`.

```go
func TestParseTargetSanitizesPersistedTarget(t *testing.T) {
	got, err := parseTarget("https://Example.Test/a/secret/?token=do-not-store#fragment")
	if err != nil { t.Fatal(err) }
	if got.persisted.Hostname != "example.test" || got.persisted.EffectivePort != 443 {
		t.Fatalf("target = %#v", got.persisted)
	}
	if got.persisted.Path != (model.PathSummary{
		Present: true, IsRoot: false, SegmentCount: 2,
		TrailingSlash: true, QueryPresent: true,
	}) { t.Fatalf("path summary = %#v", got.persisted.Path) }
	if strings.Contains(fmt.Sprint(got.persisted), "secret") || strings.Contains(errText(err), "do-not-store") {
		t.Fatal("persisted target or safe error leaked transient URL data")
	}
}
```

Assert every fixed numerical value exactly.

- [ ] **Step 2: Run the red tests**

Run:

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/clientprobe -run 'TestParseTarget|TestM1Policy'
```

Expected: FAIL because `parseTarget` and policy constants do not exist.

- [ ] **Step 3: Implement the minimal transient parser and constants**

Define:

```go
type requestTarget struct {
	requestURL *url.URL // transient only
	persisted  model.Target
}
```

Use `net/url`; require an absolute `http` or `https` URL, no userinfo, a normalized architecture-valid ASCII hostname, and port `1..65535`. Clear fragments. Preserve raw path/query only in `requestURL`. Build `PathSummary` without copying segment or query values. Use safe fixed `InputError.Code` tokens such as `invalid_url`, `unsupported_scheme`, `url_credentials_disallowed`, `invalid_hostname`, and `invalid_port`; never include the input URL.

Add typed normalization helpers with this precedence:

```go
func normalizeTCPError(error) (model.TCPResult, string)
func normalizeTLSError(error) (model.TLSTransportResult, string)
func normalizeHTTPError(error) string
func normalizeVerification(*x509.Certificate, error, time.Time) model.CertificateVerificationResult
```

Use `context`/`net.Error` timeout, then `errors.Is` for `syscall.ECONNREFUSED`, `ENETUNREACH`, and `EHOSTUNREACH`, then generic failure. Use `errors.As` for `x509.HostnameError`, `x509.UnknownAuthorityError`, and `x509.CertificateInvalidError`; compare the leaf validity interval to the injected clock before generic certificate classification. Do not parse error strings. Only set TLS alert code if a public typed error exposes it; otherwise omit it.

- [ ] **Step 4: Run focused green tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/clientprobe -run 'TestParseTarget|TestM1Policy|TestNormalize'
```

Expected: PASS, including timeout/refused/unreachable/generic and all certificate classifications.

- [ ] **Step 5: Commit**

```bash
git add internal/clientprobe/policy.go internal/clientprobe/target.go internal/clientprobe/normalize.go internal/clientprobe/target_test.go internal/clientprobe/normalize_test.go
git commit -m "feat: define bounded client probe inputs"
```

---

### Task 2: Build retained endpoint topology without overclaiming

**Files:**
- Create: `internal/clientprobe/probe.go`
- Create: `internal/clientprobe/assemble.go`
- Create: `internal/clientprobe/topology_test.go`
- Modify: `internal/clientprobe/policy.go`

**Interfaces:**
- Consumes: `requestTarget`, fixed policy, injected resolver and clock.
- Produces: transient `runFacts`, retained `endpointPlan` values, deterministic `assembleEvidence(runFacts)`, and the topology contract above.

- [ ] **Step 1: Write failing resolver/topology tests**

Required cases:

```go
func TestRetainedAddressesAllBecomeBranches(t *testing.T) { /* A,B,C retained; only A pinned */ }
func TestResolutionOrderingIsIPv4ThenIPv6Numeric(t *testing.T) { /* randomized resolver order */ }
func TestUnattemptedEndpointHasSkippedTCPAndDependencies(t *testing.T) {}
func TestResolutionTruncationAddsPartialVisibility(t *testing.T) {}
func TestNoProbeModeBranchExists(t *testing.T) {}
func TestNormalOutsideRetainedUsesDirectConnectEdgeOnly(t *testing.T) {}
```

For `A,B,C`, assert three branches and endpoint check definitions; `B` and `C` have `NOT_RUN/SKIPPED` TCP executions with `address_attempt_cap`. Assert no edge to their socket endpoints. Assert the outside endpoint branch has only directly observed connection topology and no fabricated resolution observation/edge.

- [ ] **Step 2: Run the red topology tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/clientprobe -run 'TestRetained|TestResolution|TestUnattempted|TestNoProbeMode|TestNormalOutside'
```

Expected: FAIL because topology planning and evidence assembly do not exist.

- [ ] **Step 3: Implement resolution retention and the assembly skeleton**

Use one `LookupNetIP(ctx, "ip", hostname)` under `resolutionTimeout`. Unmap IPv4-mapped addresses, deduplicate, split families, numeric-sort, and retain the first eight per family. Emit one `SYSTEM_RESOLUTION_RESULT` per retained address and `NO_RESULT` for a successfully completed family with no result. A timeout/failure records only the normalized failed resolution execution/result and creates no endpoint branch.

Define transient, non-persisted keys:

```go
type endpointKey struct {
	address netip.Addr
	port    uint16
}

type endpointPlan struct {
	key       endpointKey
	retained  bool
	pinned    bool
	resolved  bool
}
```

Create all required non-nil M0 collections, the single `CLIENT_NETWORK` vantage, target/hostname/address/endpoint entities, resolution edges, branches, check DAGs, and explicit skipped executions. A resolver result above eight per family adds a run-scoped `model.LimitationPartialVisibility`; the resolution execution reason is `resolution_result_cap` but remains completed if retained results are valid.

Use check version `1.0.0`, network inputs, empty capability lists, fixed deadlines, and expected result tokens: `RESOLVED`, `ACCEPTED`, `COMPLETED`, `PRESENTED`, `VERIFIED`, and `RESPONSE`.

- [ ] **Step 4: Run topology/model validation tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/clientprobe -run 'TestRetained|TestResolution|TestUnattempted|TestNoProbeMode|TestNormalOutside'
GOTOOLCHAIN=go1.26.5 go test ./internal/model ./internal/selection
```

Expected: PASS. Every constructed evidence value must pass `model.CanonicalizeAndValidateEvidenceRun`.

- [ ] **Step 5: Commit**

```bash
git add internal/clientprobe/probe.go internal/clientprobe/assemble.go internal/clientprobe/topology_test.go internal/clientprobe/policy.go
git commit -m "feat: retain client endpoint topology"
```

---

### Task 3: Execute pinned and ordinary TCP strategies

**Files:**
- Create: `internal/clientprobe/transport.go`
- Create: `internal/clientprobe/transport_test.go`
- Modify: `internal/clientprobe/probe.go`
- Modify: `internal/clientprobe/assemble.go`

**Interfaces:**
- Consumes: `endpointPlan`, injected `dialContext`, stage/total contexts.
- Produces: exact pinned TCP facts, normal strategy facts, actual endpoint association, and at most three concurrent strategies.

- [ ] **Step 1: Write failing TCP strategy tests**

Cover accepted/refused/timed-out/failed pinned connections; one pinned address per family; normal plus pinned attempts to the same endpoint sharing one branch; normal success outside retained addresses; normal failure before endpoint discovery; and completion-order permutations.

```go
func TestNormalFailureWithoutRemoteEndpointIsUnscoped(t *testing.T) {
	v := runWithDialError(t, errors.New("synthetic opaque failure"))
	r := v.Value().Evidence
	assertNoNormalTopologyBranch(t, r)
	assertNoFabricatedTCPObservation(t, r)
	assertUnscopedExecution(t, r, model.CheckTCPConnection, "connection_failed")
}
```

- [ ] **Step 2: Run the red TCP tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/clientprobe -run 'TestPinnedTCP|TestNormal|TestStrategyOrder'
```

Expected: FAIL because TCP strategies are not implemented.

- [ ] **Step 3: Implement the bounded strategy runner**

After a successful resolution that yields at least one retained address, start at most three goroutines: normal hostname dial, first retained IPv4 pinned dial, and first retained IPv6 pinned dial. Each uses a `tcpTimeout` child context and reports through a fixed-size channel; no scheduler, worker pool, or public interface. A failed or empty overall resolution performs no TCP strategy.

Pinned failures always know the endpoint and emit exact `TCP_CONNECTION_RESULT`. Normal success parses `conn.RemoteAddr()` as `*net.TCPAddr`, unmaps the address, and associates facts with the matching retained endpoint or the direct-connect outside branch. If `RemoteAddr` is not an exact TCP endpoint, close the connection and record unscoped `ERROR/UNKNOWN` reason `normal_endpoint_unknown`. A normal dial error before a connection exists is also unscoped and emits no TCP observation.

Retain accepted connections only within their owning strategy so Task 4 can continue the same TCP session. Never share one connection between normal and pinned attempts.

- [ ] **Step 4: Run focused green tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/clientprobe -run 'TestPinnedTCP|TestNormal|TestStrategyOrder|TestNoProbeMode'
GOTOOLCHAIN=go1.26.5 go test ./internal/rules/tcp ./internal/selection
```

Expected: PASS. Refused findings remain attached only to exact endpoint branches; coherent accepted evidence continues to contradict a refused claim for that endpoint.

- [ ] **Step 5: Commit**

```bash
git add internal/clientprobe/transport.go internal/clientprobe/transport_test.go internal/clientprobe/probe.go internal/clientprobe/assemble.go
git commit -m "feat: probe ordinary and pinned TCP paths"
```

---

### Task 4: Add architecture-1.3 TLS transport and verification

**Files:**
- Modify: `internal/clientprobe/transport.go`
- Modify: `internal/clientprobe/assemble.go`
- Create: `internal/clientprobe/testcert_test.go`
- Modify: `internal/clientprobe/transport_test.go`

**Interfaces:**
- Consumes: accepted TCP connection, exact endpoint, normalized hostname, injected roots/clock.
- Produces: `TLS_TRANSPORT_RESULT`, optional certificate-derived `TLS_PEER`, `TLS_PEER_SUMMARY`, and separate `CERTIFICATE_VERIFICATION_RESULT`.

- [ ] **Step 1: Write failing TLS tests**

Generate local CA/leaf certificates for valid, wrong-name, untrusted, expired, not-yet-valid, and invalid server usage. Add controlled plaintext, immediate-reset, and handshake-timeout servers.

Assert:

- every TLS result has the exact `endpoint_entity_id`;
- pre-certificate failure/timeout has nil peer and no `TLS_PEER` entity;
- completed transport with a certificate may name the fingerprint peer;
- peer summaries contain no SAN values or raw DER;
- verification is a separate observation with `SYSTEM` or test `EXPLICIT` trust source;
- HTTP execution is skipped with `tls_peer_unverified` on every verification failure.

- [ ] **Step 2: Run red TLS tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/clientprobe -run 'TestTLS|TestCertificate|TestPlaintextHTTPS'
```

Expected: FAIL because TLS is not implemented.

- [ ] **Step 3: Implement separated handshake, peer extraction, and verification**

Perform `tls.Client(conn, &tls.Config{ServerName: hostname, InsecureSkipVerify: true})` and `HandshakeContext` under `tlsTimeout`. `InsecureSkipVerify` is used only to separate transport observation from verification; no connection reaches HTTP until explicit verification succeeds.

On transport completion, record protocol version, cipher suite, negotiated ALPN, SNI, duration, and the exact endpoint. If a leaf exists, compute `sha256:<lowercase hex DER digest>`, create one `TLS_PEER`, and emit bounded SAN summaries for DNS, IP, and OTHER counts without values. Run:

```go
leaf.Verify(x509.VerifyOptions{
	DNSName:       hostname,
	Roots:         roots,
	Intermediates: intermediates,
	CurrentTime:   now.UTC(),
	KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
})
```

Record the existing certificate result enum and failure reason. Verification failure returns a private sentinel to the HTTP layer, closes the connection, and produces `NOT_RUN/SKIPPED tls_peer_unverified`; never propagate the wrapped `url.Error` text.

Add path edges only when their facts exist: endpoint-to-peer `NEGOTIATES_TLS_WITH` on completed transport with a peer, and peer-to-hostname `VERIFIES` on verification. These edges cite only their direct observations.

- [ ] **Step 4: Run TLS and frozen contract tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/clientprobe -run 'TestTLS|TestCertificate|TestPlaintextHTTPS'
GOTOOLCHAIN=go1.26.5 go test ./internal/model ./internal/schema/v1 ./internal/rules/tls
```

Expected: PASS, including architecture-1.3 adversarial fixtures and proof that endpoint/peer kinds remain enforced.

- [ ] **Step 5: Commit**

```bash
git add internal/clientprobe/transport.go internal/clientprobe/assemble.go internal/clientprobe/transport_test.go internal/clientprobe/testcert_test.go
git commit -m "feat: observe and verify TLS client paths"
```

---

### Task 5: Perform bounded GET and observe redirects without traversal

**Files:**
- Modify: `internal/clientprobe/transport.go`
- Modify: `internal/clientprobe/assemble.go`
- Modify: `internal/clientprobe/transport_test.go`

**Interfaces:**
- Consumes: accepted plain TCP connection or explicitly verified TLS connection plus transient request URL.
- Produces: bounded `HTTP_RESULT`, sanitized optional redirect target, and HTTP check execution.

- [ ] **Step 1: Write failing HTTP tests**

Use `httptest.Server`, `httptest.NewUnstartedServer`, and controlled handlers. Cover HTTP/HTTPS success, 401/403/404 satisfying `HTTP_RESPONSE`, Host preservation on pinned IP, fixed User-Agent, proxy environment ignored, no cookies/auth, no automatic decompression, oversized headers, large/streaming bodies, timeout, malformed response, and redirect destination request count remaining zero.

```go
func TestRedirectIsObservedButNotFollowed(t *testing.T) {
	var destination atomic.Int64
	v := diagnoseRedirect(t, &destination, "/private/path?token=secret")
	if destination.Load() != 0 { t.Fatal("redirect was followed") }
	assertSanitizedRedirect(t, v)
	assertReportDoesNotContain(t, v, "private", "token", "secret")
}
```

- [ ] **Step 2: Run red HTTP tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/clientprobe -run 'TestHTTP|TestRedirect|TestProxy|TestResponseBounds'
```

Expected: FAIL because HTTP is not implemented.

- [ ] **Step 3: Implement one bounded standard-library request per successful strategy**

Use a fresh `http.Transport` per strategy with `Proxy: nil`, `DisableCompression: true`, `DisableKeepAlives: true`, `MaxResponseHeaderBytes: maxResponseHeaderBytes`, and the already-established connection supplied through a private one-use dial callback. Use no cookie jar. Set only the fixed RouteDoctor User-Agent and normal Go-required request fields; leave authorization and cookies absent. Preserve the parsed URL hostname/port in the request so Host remains correct while pinned dialing uses the IP.

Use `http.Client.CheckRedirect` returning `http.ErrUseLastResponse`; `redirectFollowCap` remains zero. Bound response-header waiting and body-prefix reading with `httpTimeout`; read at most `maxResponseBodyPrefix` bytes to `io.Discard`, then close. Body truncation does not fail `HTTP_RESPONSE` because content is outside the goal.

Any final status is `HTTPResponse`, except a 3xx with a syntactically valid, credential-free, architecture-valid HTTP(S) `Location`, which is `HTTPRedirect` with a sanitized `Target` and a new `URL_TARGET` entity referenced by `redirect_target_entity_id`. Never add a `REDIRECTS_TO` edge or destination branch because the destination was not contacted. Malformed, unsupported, or credential-bearing Location data is not persisted.

Add a `REQUESTS_HTTP_FROM` edge supported by the HTTP observation. Never retain response headers or body bytes.

- [ ] **Step 4: Run focused green tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/clientprobe -run 'TestHTTP|TestRedirect|TestProxy|TestResponseBounds'
```

Expected: PASS, including proof that verification failures delivered zero HTTP requests.

- [ ] **Step 5: Commit**

```bash
git add internal/clientprobe/transport.go internal/clientprobe/assemble.go internal/clientprobe/transport_test.go
git commit -m "feat: add bounded client HTTP observations"
```

---

### Task 6: Finalize deterministic reports, evaluation, and report-derived status

**Files:**
- Modify: `internal/clientprobe/probe.go`
- Modify: `internal/clientprobe/assemble.go`
- Create: `internal/clientprobe/status.go`
- Create: `internal/clientprobe/status_test.go`
- Create: `internal/clientprobe/integration_test.go`

**Interfaces:**
- Produces: `Diagnose`, `Status`, deterministic canonical validated evaluated reports.
- Consumes: Tasks 1-5 facts plus `rules.DefaultRegistry()` and existing model validators.

- [ ] **Step 1: Write failing assembly/status tests**

Construct validated reports directly and through fake dependencies. Cover:

```go
func TestStatusSatisfiedByOneValidHTTPBranch(t *testing.T) {}
func TestStatusBlockedByTCPRefusalCoverageOfEveryBranch(t *testing.T) {}
func TestStatusBlockedByHostnameMismatchCoverageOfEveryBranch(t *testing.T) {}
func TestStatusIndeterminateForPartialFindingCoverage(t *testing.T) {}
func TestStatusIndeterminateForDirectCheckFailuresOnly(t *testing.T) {}
func TestStatusIndeterminateForUnattemptedBranch(t *testing.T) {}
func TestStatusIndeterminateForResolutionTruncation(t *testing.T) {}
func TestCanonicalReportIgnoresCompletionOrder(t *testing.T) {}
```

Assert `Status` accepts only `model.ValidatedEvaluatedRun`; there is no overload taking transient facts.

- [ ] **Step 2: Run red status/integration tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/clientprobe -run 'TestStatus|TestCanonicalReport|TestDiagnose'
```

Expected: FAIL because final orchestration/status is incomplete.

- [ ] **Step 3: Implement final orchestration and pure status**

`Diagnose` creates the total timeout, parses, resolves, plans retained topology, executes strategies, assembles facts, calls `model.CanonicalizeAndValidateEvidenceRun`, then:

```go
evaluated, issues := rules.NewEvaluator(rules.DefaultRegistry()).Evaluate(
	validatedEvidence,
	evaluationTime,
)
```

Return an internal error if either validation phase returns issues. No live network failure escapes as an internal error.

Implement `Status(v)` only from `v.Value()`:

1. Relevant branches are leaf service-path branches with goal `HTTP_RESPONSE`.
2. A branch satisfies the goal only when a branch-scoped completed/pass `CheckHTTP` execution cites an `HTTP_RESULT`; HTTPS additionally requires a branch-scoped completed/pass certificate-verification execution citing `CertVerified`.
3. Any satisfying branch returns `StatusSatisfied`, even with limitations or blockers elsewhere.
4. If there are no relevant branches, return `StatusIndeterminate`.
5. A validated `GLOBAL_PRIMARY` blocker covers all relevant branches.
6. Otherwise only validated `BRANCH_PRIMARY` blocker findings cover the branches named by their branch/path positions; every relevant branch must be covered for `StatusBlocked`.
7. Any uncovered branch—including one with only unattempted or direct-failure checks and no selected blocker—or run-scoped `partial_visibility` yields `StatusIndeterminate`. An unscoped normal failure is displayed but neither creates blocker coverage nor cancels independently established all-branch blocker coverage.

Do not inspect transient attempt state or create new claims/findings. The existing evaluator alone produces blockers.

- [ ] **Step 4: Run package and evaluator green tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/clientprobe ./internal/rules ./internal/selection ./internal/model
```

Expected: PASS with byte-identical canonical JSON after encoding reports built from permuted resolver and goroutine completion orders (fake clock/durations fixed).

- [ ] **Step 5: Commit**

```bash
git add internal/clientprobe/probe.go internal/clientprobe/assemble.go internal/clientprobe/status.go internal/clientprobe/status_test.go internal/clientprobe/integration_test.go
git commit -m "feat: evaluate deterministic client reports"
```

---

### Task 7: Render endpoint branches, direct checks, and blockers distinctly

**Files:**
- Create: `internal/render/client.go`
- Modify: `internal/render/concise.go`
- Modify: `internal/render/verbose.go`
- Modify: `internal/render/render_test.go`
- Modify: `internal/render/fixtures_test.go`

**Interfaces:**
- Consumes: only `model.ValidatedEvaluatedRun`.
- Produces: deterministic safe human summaries; it does not calculate selection or exit status.

- [ ] **Step 1: Write failing render tests**

Assert concise output groups retained endpoint branches, prints typed stage/result and normalized reason, marks `address_attempt_cap`, prints unscoped normal failure separately, shows HTTP status, and labels rule-produced selected findings as primary blockers. Assert direct TLS/untrusted/timeout failures are not called findings or blockers.

```go
func TestConciseSeparatesDirectFailureFromRuleBlocker(t *testing.T) {
	out := renderClientFixture(t)
	assertContains(t, out, "CHECK CERTIFICATE_VERIFICATION: FAIL untrusted_issuer")
	assertContains(t, out, "PRIMARY [BRANCH_PRIMARY] TCP connection refused")
	assertNotContains(t, out, "PRIMARY", "untrusted_issuer")
}
```

Add leakage assertions for raw path/query and raw error material.

- [ ] **Step 2: Run red renderer tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/render -run 'TestConcise|TestVerbose|TestClient'
```

Expected: FAIL because client-aware summaries do not exist.

- [ ] **Step 3: Implement minimal report-only summaries**

Build lookup maps for definitions, executions, entities, observations, and branches. Render branches in stored canonical order; identify endpoints from check inputs and path nodes, never attempt mode. Concise output includes stage, verdict, safe reason, endpoint, status, and selected blocker. Verbose adds check/execution/observation IDs and evidence refs already permitted by M0.

For no rule-produced selection, say `No rule-produced primary finding.` rather than implying direct failed checks are successful. Render unscoped checks under `UNATTRIBUTED CHECKS`. Do not derive or print exit status in the renderer.

- [ ] **Step 4: Run renderer and existing golden tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./internal/render
GOTOOLCHAIN=go1.26.5 go test ./... -run 'Fixture|Golden'
```

Expected: PASS. Update only goldens whose intentionally improved check wording changes.

- [ ] **Step 5: Commit**

```bash
git add internal/render/client.go internal/render/concise.go internal/render/verbose.go internal/render/render_test.go internal/render/fixtures_test.go testdata/reports/v1
git commit -m "feat: render client probe branch evidence"
```

---

### Task 8: Add the URL shorthand and report-based exit mapping

**Files:**
- Modify: `cmd/routedoc/app.go`
- Modify: `cmd/routedoc/flags.go`
- Modify: `cmd/routedoc/app_test.go`
- Create: `cmd/routedoc/probe_test.go`
- Modify: `cmd/routedoc/version.go`

**Interfaces:**
- Consumes: `clientprobe.Diagnose`, `clientprobe.Status`, `render.Report`, `v1.EncodeCanonical`.
- Produces: `routedoc URL [--verbose] [--json]` while preserving every M0 command.

- [ ] **Step 1: Write failing CLI tests**

Use an injectable app-level function field only as the existing `ReadFile` seam is used; it is not a public framework:

```go
type DiagnoseFunc func(context.Context, string, model.Producer) (model.ValidatedEvaluatedRun, error)
```

Test exact parsing, duplicate/unknown flags, unchanged stored-report commands, safe input errors, human/verbose/canonical JSON, and status mapping `Satisfied->0`, `Blocked->1`, `Indeterminate->2`. Test that the mapping calls `clientprobe.Status` on the returned validated report and cannot be overridden by fake live state.

- [ ] **Step 2: Run red CLI tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./cmd/routedoc -run 'TestCLIURL|TestProbeExit|TestCLIExactCommandBoundary'
```

Expected: FAIL because URL dispatch does not exist and the old boundary rejects it.

- [ ] **Step 3: Implement dispatch, output, and exit codes**

Add `ExitBlocked = 1`; keep existing `ExitData = 2`, `ExitUsage = 3`, and `ExitInternal = 4`. Dispatch known M0 commands first; otherwise parse exactly one URL plus optional `--verbose`/`--json`. Add usage:

```text
routedoc URL [--verbose] [--json]
```

Call `Diagnose` with producer metadata. `InputError` returns exit `3` with only its safe code. Internal errors return `4` without printing raw URL-bearing wrapped errors. For JSON call `v1.EncodeCanonical`; for human output call `render.Report`. Finally map `clientprobe.Status(validatedReport)` to `0`, `1`, or `2`. Output errors override with `4`.

Do not add timeout, insecure, resolver, address, redirect, proxy, or concurrency flags.

- [ ] **Step 4: Run CLI and package tests**

```bash
GOTOOLCHAIN=go1.26.5 go test ./cmd/routedoc ./internal/clientprobe ./internal/render
```

Expected: PASS; existing render/explain/validate/version tests remain unchanged except the intentionally updated URL boundary.

- [ ] **Step 5: Commit**

```bash
git add cmd/routedoc/app.go cmd/routedoc/flags.go cmd/routedoc/app_test.go cmd/routedoc/probe_test.go cmd/routedoc/version.go
git commit -m "feat: diagnose URLs from the client vantage"
```

---

### Task 9: Complete offline protocol, fixture, privacy, and acceptance coverage

**Files:**
- Modify: `internal/clientprobe/integration_test.go`
- Modify: `internal/clientprobe/transport_test.go`
- Modify: `cmd/routedoc/probe_test.go`
- Create: `testdata/reports/v1/client-probe-http-success/report.json`
- Create: `testdata/reports/v1/client-probe-http-success/concise.txt`
- Create: `testdata/reports/v1/client-probe-http-success/verbose.txt`
- Create: `testdata/reports/v1/client-probe-tls-untrusted/report.json`
- Create: `testdata/reports/v1/client-probe-tls-untrusted/concise.txt`
- Create: `testdata/reports/v1/client-probe-tls-untrusted/verbose.txt`
- Create: `testdata/reports/v1/client-probe-unattempted-address/report.json`
- Create: `testdata/reports/v1/client-probe-unattempted-address/concise.txt`
- Create: `testdata/reports/v1/client-probe-unattempted-address/verbose.txt`
- Modify: `testdata/reports/v1/README.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: complete M1 CLI and report pipeline.
- Produces: reviewed offline acceptance corpus and user documentation.

- [ ] **Step 1: Add failing end-to-end acceptance and leakage assertions**

Drive real loopback HTTP/TCP/TLS servers and fake only system resolution/clock where determinism requires it. Cover all approved cases: successful HTTP/HTTPS, refused, deterministic timeout/failure, TLS pre-certificate failures, hostname mismatch, untrusted/expired/not-yet-valid, HTTP suppression, header/body bounds, multiple retained addresses, normal outside retained, output permutation, redirect no-follow, proxy environment ignored, and maximum three GETs.

Run every output form against a target such as:

```text
https://example.test/private/segment?token=do-not-persist#fragment
```

Assert canonical JSON, concise, verbose, stderr, IDs, reason codes, and test goldens contain none of `private`, `segment`, `token`, `do-not-persist`, raw response data, `Authorization`, `Cookie`, `Set-Cookie`, or raw OS error text.

- [ ] **Step 2: Run the acceptance tests red**

```bash
GOTOOLCHAIN=go1.26.5 go test ./... -run 'ClientProbe|Privacy|Fixture|Golden|SchemaContract'
```

Expected: FAIL until all fixtures, goldens, documentation, and edge cases are present.

- [ ] **Step 3: Add only the required fixtures/docs and close focused gaps**

Generate fixture reports through fixed fake clock/dependencies, then encode them with `v1.EncodeCanonical`; do not hand-author ordering. Add the three fixture families listed above and register their expected validity in the existing fixture harness/README convention. Update README with shorthand, default bounds, direct/no-proxy behavior, at-most-three GET warning, redirect observe-only behavior, and exit meanings.

Do not regenerate unrelated M0 goldens. If a focused test exposes a real implementation defect, add its red regression to the owning package, make the minimum fix there, and rerun that package before continuing.

- [ ] **Step 4: Run the complete verification suite**

```bash
GOTOOLCHAIN=go1.26.5 go test ./...
GOTOOLCHAIN=go1.26.5 go vet ./...
GOTOOLCHAIN=go1.26.5 go test ./... -run 'Fixture|Golden|SchemaContract'

GOTOOLCHAIN=go1.26.5 go test ./internal/schema/v1 -run=^$ -fuzz=FuzzDecode -fuzztime=30s
GOTOOLCHAIN=go1.26.5 go test ./internal/model -run=^$ -fuzz=FuzzIDReferences -fuzztime=30s
GOTOOLCHAIN=go1.26.5 go test ./internal/model -run=^$ -fuzz=FuzzJustification -fuzztime=30s

GOTOOLCHAIN=go1.26.5 go list -deps ./cmd/routedoc
go mod verify
git diff --check
git status --short
```

Additionally inspect:

```bash
GOTOOLCHAIN=go1.26.5 go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./cmd/routedoc
```

Expected: only module-local `routedoc/...` packages are non-standard production dependencies; the JSON Schema validator and its transitive modules remain test-only. No required test contacts the public Internet.

- [ ] **Step 5: Self-review the implementation against scope**

Verify explicitly:

- no redirect destination is contacted;
- no second pinned address per family is attempted;
- probe mode never becomes a topology branch or persisted field;
- all retained endpoints remain branches, and cap-skipped branches prevent false coverage;
- outside-retained normal success has only directly observed connection topology;
- normal unattributed failure has no endpoint/TCP observation;
- exit status reads only `ValidatedEvaluatedRun`;
- check-only failures never cause exit `1`;
- no new claim/finding/rule/schema value exists;
- no Linux/Caddy/Docker/proxy/plugin/configuration machinery was added;
- no secret-bearing transient value enters reports, logs, errors, IDs, or testdata.

- [ ] **Step 6: Commit the acceptance boundary**

```bash
git add internal/clientprobe cmd/routedoc testdata/reports/v1 README.md
git commit -m "test: prove Milestone 1 client probe contract"
```

After the commit, rerun `git diff --check` and `git status --short`; status must be empty.

---

## Assumptions the implementation must verify early

1. A retained address branch containing a supported `RESOLVES_TO` edge plus a branch-scoped skipped TCP execution validates without inventing an endpoint edge. Task 2 must prove this before transport code proceeds.
2. The existing direct `URL_TARGET -> SOCKET_ENDPOINT / CONNECTS_TO` fixture pattern legitimately represents a normal-dial endpoint outside retained resolution when supported by its accepted TCP observation. Task 2 must stop for architecture review if model validation or rule positioning disproves this.
3. On supported platforms, a successful normal TCP connection exposes an exact `*net.TCPAddr` through `RemoteAddr`; otherwise the safe fallback is an unscoped unknown execution, never guessed attribution.
4. A one-use connection callback in `http.Transport` does not cause a second request/dial for one GET. Protocol tests must count dials and requests; if Go's transport behavior differs, use the smallest standard-library `RoundTripper` seam without changing persisted semantics.
5. Resolver truncation can be represented with the existing run-scoped `partial_visibility` limitation and safe execution reason `resolution_result_cap`; no schema field is required.
6. Existing selection marks only rule-produced observed/inferred blockers as branch/global primary. `Status` must consume that validated selection and must not reproduce selection logic from raw checks.
7. Go's public TLS errors may not expose an alert code. Omitting optional `alert_code` is correct; string parsing is forbidden.

If assumptions 1 or 2 fail, stop and report the precise topology-model contradiction before proposing any architecture change. Other failed assumptions require only a smaller implementation adjustment within the approved contract.

## Commit sequence

1. `feat: define bounded client probe inputs`
2. `feat: retain client endpoint topology`
3. `feat: probe ordinary and pinned TCP paths`
4. `feat: observe and verify TLS client paths`
5. `feat: add bounded client HTTP observations`
6. `feat: evaluate deterministic client reports`
7. `feat: render client probe branch evidence`
8. `feat: diagnose URLs from the client vantage`
9. `test: prove Milestone 1 client probe contract`

Each commit must pass its focused commands before the next task begins. Do not squash architecture/M0 history, rewrite frozen contracts, or start M2 after Task 9.
