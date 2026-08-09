# RouteDoctor V1 Architecture

Status: authoritative design for V1

Design version: 1.3

Approved direction: 2026-08-08

Revision 1.3 correction: 2026-08-09

This document is the architectural source of truth for RouteDoctor V1. If a
later implementation plan or code change conflicts with it, this document wins
until an explicit design revision is approved.

## 1. Purpose and product claim

RouteDoctor is a deterministic, evidence-driven CLI for diagnosing why a URL
does not behave as expected along a public-URL-to-self-hosted-application
service path.

RouteDoctor does not claim to discover the complete Internet route or the
ultimate historical cause of a failure. It reports behavior observed from
explicitly identified vantage points, correlates that behavior with explicitly
authorized local runtime evidence, and identifies the earliest confirmed
blocking condition on each supported service-path branch.

The public wording is:

> RouteDoctor identifies where observed behavior first diverges from an
> expected service path, shows the evidence for that conclusion, and keeps
> observations, inferences, and suspicions visibly separate.

`PRIMARY FINDING` and `CONFIRMED BLOCKING CONDITION` are preferred report
terms. `ROOT CAUSE` is permitted only when a rule's evidence contract proves a
causal statement rather than merely a current blocker. V1 is not expected to
emit many, if any, root-cause conclusions.

Every reachability statement is scoped to its named vantage point and
observation time. A successful client probe does not prove general or
"external" reachability.

`RouteDoctor` is a provisional working name until package, repository, domain,
and trademark clearance is completed.

## 2. Normative terminology

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
normative requirements in this document.

- **Expected path**: topology asserted by the operator or obtained from a
  source whose semantics are known. It is not silently guessed.
- **Vantage point**: the typed network context from which an observation was
  made.
- **Branch**: one ordered alternative through the service-path graph, such as
  one resolved IP address, address family, redirect destination, proxy route,
  or upstream.
- **Blocking condition**: a condition observed or strictly inferred to prevent
  the requested goal on a particular branch at the observation time.
- **Configured intent**: configuration that may be intended for use but is not
  proven active.
- **Active runtime state**: state read from the running component or operating
  system. It outranks conflicting configured intent.
- **Complete for scope**: visibility sufficient to support a particular
  negative proposition within a precisely described scope. It never means
  complete knowledge of the machine or network.

## 3. Settled product decisions

1. `routedoc URL` performs client-only diagnosis.
2. Local-origin participation requires `routedoc diagnose URL --origin local`.
3. Client probes are portable; deep origin inspection is Linux-only in V1.
4. Caddy v2 and Docker Engine are the only V1 deep integrations.
5. Active runtime state outranks configured intent.
6. Missing permissions, tools, integrations, or vantage points produce
   `UNKNOWN` or `SKIPPED`, never invented conclusions.
7. RouteDoctor never automatically uses sudo or re-executes itself with more
   privilege.
8. RouteDoctor does not use Docker exec, create debug containers, capture
   packets, execute arbitrary user commands, or perform repairs.
9. V1 rules are ordinary, statically registered, versioned Go code operating
   on typed observations. There is no rule DSL, generic inference framework,
   public plugin system, or external rule loading.
10. V1 does not perform HTTP over an unverified TLS connection. There is no
    insecure override in V1.
11. Reports never use a global primary finding when only branch-specific
    evidence exists.
12. Most behavior is tested with deterministic fixtures and controlled local
    protocol servers; required tests never depend on the public Internet.

## 4. V1 scope

### 4.1 Client-only diagnosis

The shorthand command:

```text
routedoc https://app.example.com
```

MUST support:

- HTTP and HTTPS URL parsing and normalization;
- system name resolution, with IPv4 and IPv6 results kept distinct;
- direct TCP connection attempts to selected resolved endpoints;
- a normal client connection attempt plus isolated address/family attempts;
- TLS transport handshake observation with the URL hostname as SNI;
- TLS peer and certificate metadata observation even when certificate
  verification fails, subject to minimization rules;
- certificate verification as a separate check covering hostname, trust chain,
  intended server usage, and validity time;
- ordinary HTTP only after successful certificate verification for HTTPS;
- bounded HTTP GET behavior and bounded redirect traversal;
- branch-local divergence and blocker reporting;
- concise human output, verbose human output, and versioned JSON output.

"System resolution" is the required term unless RouteDoctor made an explicit
DNS protocol query. A system result may have come from DNS, a hosts file, NSS,
an OS cache, a VPN, or another resolver mechanism.

Certificate verification in V1 excludes active OCSP or CRL retrieval,
Certificate Transparency auditing, DNSSEC, DANE, and TLS hardening assessment.

### 4.2 Explicit local-origin diagnosis

The command form is:

```text
routedoc diagnose https://app.example.com --origin local [origin options]
```

When origin mode is requested, V1 MUST define checks for the following
capabilities. A check whose platform, permission, integration, or evidence
requirements are unavailable remains present as `UNKNOWN` or `SKIPPED`:

- Linux listening-socket inventory;
- best-effort socket-to-process correlation;
- active Caddy JSON inspection;
- explicitly supplied Caddyfile adaptation and inspection as configured
  intent;
- evaluation of a deliberately limited, documented subset of Caddy matchers;
- extraction of concrete static upstreams;
- upstream connectivity from a precisely identified vantage point;
- opt-in, read-only Docker container and network discovery;
- correlation of Docker IP addresses, network membership, runtime state, and
  published ports with concrete upstreams.

Container metadata such as `EXPOSE` and published-port mappings is not listener
evidence. Reports MUST say `declares`, `publishes`, or `maps` unless a socket
inventory or connection observation proves listening behavior.

### 4.3 Initial support matrix

| Capability | V1 support |
|---|---|
| Client resolution/TCP/TLS/HTTP | Linux, macOS, Windows |
| Deep socket/process inspection | Linux only |
| Reverse proxy integration | Caddy v2 only |
| Container runtime integration | Docker Engine only |
| Caddy on the host | Supported matcher subset |
| Caddy in a container | Topology analysis; namespace-dependent checks may remain unknown |
| nginx, Traefik, HAProxy | Not supported in V1 |
| Podman, Kubernetes, systemd, nftables | Not supported in V1 |
| CDN or tunnel origin discovery | Not supported in V1 |
| Managed remote-vantage service | Not supported in V1 |

## 5. Explicit non-goals

V1 is not:

- an IP traceroute or MTR replacement;
- a packet capture or packet-analysis tool;
- a port, subnet, host, or vulnerability scanner;
- a firewall-rule analyzer;
- a TLS security scanner;
- a browser emulator;
- a log aggregation or log-mining system;
- a generic support-bundle framework;
- an AI wrapper around commands or logs;
- a repair, configuration-writing, or remediation executor;
- a monitoring daemon, scheduler, dashboard, alerting system, asset inventory,
  or historical analytics store;
- a public plugin host, rule marketplace, rule DSL, or generic inference
  engine;
- an automatic external-vantage service;
- a guarantee that behavior from one vantage represents behavior from any
  other client, network, browser, or point in time.

V1 does not invoke Docker exec, launch containers, enter container network
namespaces, install privileged helpers, auto-sudo, or run arbitrary configured
commands.

## 6. Architectural decomposition

RouteDoctor uses three related structures instead of one overloaded graph.

### 6.1 Service-path graph

The service-path graph contains typed entities and directed edges describing
expected and observed topology. It may branch for address families, resolved
addresses, redirects, proxy routes, load-balanced upstreams, and alternative
vantage points.

An edge has a provenance class:

- `OPERATOR_ASSERTED`;
- `DIRECTLY_OBSERVED`;
- `ACTIVE_RUNTIME_CONFIG`;
- `CONFIGURED_INTENT`.

Persisted V1 path edges are base evidence. An operator-asserted edge MUST cite
an operator assertion; every other edge MUST cite an observation. Inferred
relationships are rule-derived claims and are not written back into base
service-path topology. No configured-intent edge may be relabeled as directly
observed.

### 6.2 Check dependency DAG

The check dependency DAG controls execution. It expresses prerequisites such as
TCP before TLS transport, TLS transport before peer inspection, certificate
verification after peer inspection, and verified TLS before HTTPS application
traffic.

A failed prerequisite causes dependent checks to be explicitly skipped with a
stable reason code. It does not cause those checks to disappear from the run.

### 6.3 Justification graph

The justification graph has one fixed shape:

```text
Finding -> Claim -> Claim | Observation | VisibilityAssessment | OperatorAssertion
```

There is no generic graph framework and no separate justification-node type.
Findings cite claims. Claims use typed `EvidenceRef` values for supporting and
contradicting evidence. Rule provenance is stored directly on every claim and
finding produced by evaluation.

Every claim and every finding MUST have at least one justification path through
claim `supporting_evidence`. A `SUSPECTED` claim MUST also identify the typed
missing-evidence requirements that prevent stronger classification. Every
derived finding MUST have a complete, acyclic path to admissible base evidence.
Contradicting evidence remains attached and auditable but is not itself a
support path.

## 7. Typed conceptual model

The model below is normative conceptually. Milestone 0 will translate it into
Go types without changing its semantics.

### 7.1 Run

```text
Run
- report_schema_version
- producer { name, version, build }
- run_id
- target
- goal
- requested_scope
- policy
- started_at
- finished_at
- vantage_points[]
- capabilities[]
- operator_assertions[]
- entities[]
- service_path
- check_definitions[]
- check_executions[]
- observations[]
- visibility_assessments[]
- evaluation
- claims[]
- findings[]
- limitations[]
```

All IDs are unique within their typed ID domain in a run. An evidence reference
contains both its kind and ID, so `observation-000001` and `claim-000001` cannot
be confused. Cross-run identity is not implied.

Every item in a set-like top-level collection has a typed ID. In particular,
capability records have `capability_id` and limitation records have
`limitation_id`; they are not persisted as unkeyed strings.

### 7.2 Target and goal

`Target` contains a sanitized target summary: scheme, normalized hostname,
effective port, and conservative path/query structure. URL user information,
query values, fragments, and raw path segments MUST NOT be persisted.

The persisted path summary is:

```text
PathSummary
- present
- is_root
- segment_count
- trailing_slash
- query_present
```

`segment_count` counts non-empty path segments after URL parsing; it does not
retain segment values or lengths. The real normalized request path and query
may exist only in transient probe/matcher input needed to issue the request,
follow redirects, or evaluate supported Caddy matchers. They are excluded from
the persisted model, logs, errors, IDs, candidate sort keys, and fixtures.
Derived evidence may record `MATCHED`, `NOT_MATCHED`, or `UNKNOWN` for a Caddy
path matcher without retaining either the request path or matcher value.

`Goal` describes what the run is evaluating. V1 goal kinds are:

- `HTTP_RESPONSE`: receive an HTTP response through the required transport;
- `HTTP_EXPECTATION`: receive a response satisfying explicit status or header
  expectations;
- `ORIGIN_PATH_DIAGNOSIS`: correlate the URL with an explicitly asserted local
  origin.

An HTTP status by itself is not a connectivity failure. A 401, 403, or 404
proves that an HTTP response was received from that vantage. A status becomes
an expectation failure only when an explicit expectation or a narrowly defined
rule says so.

### 7.3 Vantage point

Network/vantage identity is first-class and MUST NOT be represented as a free
text note.

```text
VantagePoint
- vantage_id
- kind
- role
- display_label
- identity
- parent_vantage_id?
- establishment
- limitations[]
```

`kind` is a closed V1 enum:

- `CLIENT_NETWORK`: the client-side network context relative to the asserted
  origin; this includes the machine running client-only diagnosis;
- `HOST_NAMESPACE`: a specifically identified origin-host network namespace;
- `CONTAINER_NAMESPACE`: a namespace tied to a specific runtime/container
  identity;
- `UNKNOWN_NAMESPACE`: a network context whose namespace identity cannot be
  established.

`role` is separate from `kind` and is one of `CLIENT`, `ORIGIN_HOST`, `PROXY`,
`UPSTREAM`, or `UNSPECIFIED`. Separating role from network context prevents
"proxy" from being mistaken for a namespace identity.

`identity` is a discriminated value appropriate to the kind. Examples include
a Linux network namespace inode for `HOST_NAMESPACE`, a Docker daemon and
container ID for `CONTAINER_NAMESPACE`, or a user-supplied label for
`CLIENT_NETWORK`. `CLIENT_NETWORK` does not mean public, remote, or external;
it identifies the caller-side vantage relative to the target. Hostnames and
labels alone are not namespace proof.

`establishment` records whether the identity was directly observed, supplied
by the operator, correlated from runtime metadata, or remains unknown.

Every resolution, route, TCP, TLS, HTTP, listener, and upstream-connectivity
observation MUST reference exactly one vantage ID. Rules MUST compare vantage
IDs and MUST NOT silently equate different kinds or identities.

### 7.4 Operator assertion

Operator assertions are persisted base evidence. They represent choices or
expected relationships supplied by the operator; they are not observations and
are never silently upgraded to observed facts.

```text
OperatorAssertion
- assertion_id
- kind
- parameters
- established_at
- source
```

`kind` is a closed discriminant. V1 kinds are
`LOCAL_ORIGIN_PARTICIPATION`, `EXPECTED_PATH_EDGE`,
`HTTP_EXPECTATION`, `CONFIG_SOURCE_SELECTION`, and
`PRIVATE_REDIRECT_TRANSITION_ALLOWED`. `parameters` is a closed payload chosen
by `kind`, never an arbitrary map.

The V1 payloads are:

```text
LOCAL_ORIGIN_PARTICIPATION
- url_target_entity_id
- host_vantage_id

EXPECTED_PATH_EDGE
- from_entity_id
- to_entity_id
- relation

HTTP_EXPECTATION
- expectation_kind: STATUS_RANGE | HEADER_PRESENT
- status_min?       # required only for STATUS_RANGE
- status_max?       # required only for STATUS_RANGE
- header_name?      # normalized name, required only for HEADER_PRESENT

CONFIG_SOURCE_SELECTION
- component_kind: CADDY | DOCKER
- source_kind: ACTIVE_API | EXPLICIT_FILE | ENGINE_ENDPOINT

PRIVATE_REDIRECT_TRANSITION_ALLOWED
- from_address_scope
- to_address_scope
```

Multiple expectations or expected edges use multiple assertions; no assertion
payload contains an array. Header values, source endpoints, and source file
paths are not persisted in assertions.

`source` is `COMMAND_LINE`, `EXPLICIT_CONFIG`, or `SYNTHETIC_FIXTURE`. It does
not retain raw argv, environment values, configuration file paths, or
configuration contents. `established_at` is supplied by the run clock.

Assertions are immutable evaluation input. Rules may cite them through
`EvidenceRef`, but rules cannot create or alter them.

### 7.5 Entity

V1 entity kinds are:

- `URL_TARGET`;
- `HOSTNAME`;
- `IP_ADDRESS`;
- `SOCKET_ENDPOINT`;
- `TLS_PEER`;
- `HTTP_EXCHANGE`;
- `PROXY_INSTANCE`;
- `PROXY_ROUTE`;
- `UPSTREAM_ENDPOINT`;
- `LISTENER`;
- `PROCESS`;
- `CONTAINER`;
- `NETWORK_NAMESPACE`.

Entities contain identity and sanitized display fields, not evidence. Facts
about them live in observations. Sensitive source payloads MUST NOT be attached
to an entity as generic metadata.

### 7.6 Service path and branch

```text
ServicePath
- nodes[] { entity_id }
- edges[] { edge_id, from, to, relation, provenance, evidence_refs[] }
- branches[] { branch_id, parent_branch_id?, ordered_edge_ids[], goal }
```

Each path-edge evidence reference MUST target an `OBSERVATION` or `ASSERTION`.
Claims and visibility assessments cannot become base-topology support.

Each branch has its own ordering. A node before a branch split may block all
descendants; a node after the split blocks only that branch unless equivalent
evidence exists for the others.

Redirects are ordered path transitions, not transparent mutations of the
original target. A redirect destination gets its own resolution and endpoint
branches.

The normal dual-stack client attempt is a distinct observed branch. It does
not erase isolated IPv4 or IPv6 branch results.

### 7.7 Check definition

```text
CheckDefinition
- check_id
- kind
- version
- inputs
- dependency_check_ids[]
- required_capabilities[]
- execution_policy
- expected_condition
```

Check definitions are immutable during a run. Their `version` changes when the
check's observable semantics change.

### 7.8 Check execution

```text
CheckExecution
- execution_id
- check_id
- branch_id?
- vantage_id?
- started_at?
- finished_at?
- lifecycle
- verdict
- reason_code?
- observation_ids[]
- visibility_assessment_ids[]
```

Lifecycle is one of:

- `NOT_RUN`;
- `COMPLETED`;
- `UNAVAILABLE`;
- `DENIED`;
- `TIMED_OUT`;
- `ERROR`.

Verdict is one of:

- `PASS`: the defined expected condition was observed;
- `FAIL`: the defined expected condition was contradicted;
- `UNKNOWN`: execution occurred or was attempted, but evidence is insufficient
  or ambiguous;
- `SKIPPED`: execution was intentionally not attempted because a dependency,
  policy, capability, platform, or scope condition prevented it.

Lifecycle and verdict are separate but their valid combinations are fixed:

| Lifecycle | Allowed verdicts |
|---|---|
| `NOT_RUN` | `SKIPPED` |
| `COMPLETED` | `PASS`, `FAIL`, `UNKNOWN` |
| `UNAVAILABLE` | `SKIPPED` |
| `DENIED` | `SKIPPED` |
| `TIMED_OUT` | `FAIL` when the deadline is part of the expected condition; otherwise `UNKNOWN` |
| `ERROR` | `UNKNOWN` |

A dependency or policy skip is `NOT_RUN` plus `SKIPPED`. An internal `ERROR`
cannot produce `PASS`, and failed certificate verification is `COMPLETED` plus
`FAIL`, not an execution error.

### 7.9 Observation

```text
Observation
- observation_id
- kind
- subject_entity_ids[]
- vantage_id?
- observed_at
- payload
- acquisition_method
- source_component
- sensitivity
- limitations[]
```

All network-relevant observation kinds require a vantage ID. Non-network
observations, such as producer metadata, may omit it.

An observation is a typed fact produced directly by a probe or collector.
`payload` is a closed discriminated union selected by `kind`, not an arbitrary
map. Raw command output, `map[string]any`, and untyped log text are not
observations. The same rule applies to check inputs and claim parameters:
persistent model values are typed and schema-bounded.

Required initial observation families are:

- system resolution result;
- TCP connection result;
- TLS transport result;
- TLS peer summary;
- certificate verification result;
- HTTP response or redirect result;
- active proxy route summary;
- configured proxy route summary;
- upstream selection summary;
- listener inventory result;
- listener inventory entry;
- process ownership entry;
- Docker container/network/port summary;
- capability and permission result.

`LISTENER_INVENTORY_RESULT` is the direct observation that a listener
inventory operation completed successfully for one exact typed scope. Its
closed payload, in schema declaration order, is:

```text
LISTENER_INVENTORY_RESULT
- namespace_entity_id
- protocol
- address_family
- bind_semantics
- port_start
- port_end
- matching_listener_count
```

`namespace_entity_id` MUST resolve to the `NETWORK_NAMESPACE` represented by
the observation's vantage. `protocol`, `address_family`, and `bind_semantics`
use the same closed typed values as listener inventory entries and visibility
scopes. Ports are inclusive, `port_start` MUST be no greater than `port_end`,
and `matching_listener_count` is a non-negative integer. The count is the
number of listeners matching every payload dimension in that inclusive port
range; it is not a count of all sockets visible to the collector.

The observation kind itself attests that enumeration for the represented
scope completed successfully. A collector MUST emit it only after successful
completion. Partial, denied, unavailable, timed-out, failed, racing, or
otherwise incomplete enumeration MUST NOT emit a
`LISTENER_INVENTORY_RESULT`; those outcomes remain represented by
`CheckExecution`, non-complete visibility, limitations, and capability or
permission evidence. A limitation that makes coverage of any represented
dimension uncertain also precludes emission for that scope. The payload has no
`complete` boolean because completeness is part of the kind's contract, not a
self-declared flag.

A zero count directly proves that the completed operation observed no matching
listener in exactly that scope. Individual positive listeners continue to use
`LISTENER_INVENTORY_ENTRY`; the result kind neither replaces those entries nor
persists a raw socket table, command output, process list, arbitrary metadata,
or collector source payload.

### 7.10 TLS transport, peer, verification, and HTTP

TLS is explicitly decomposed:

1. `TLS_TRANSPORT_RESULT` records whether a TLS handshake completed for one
   exact attempted socket endpoint and, when available, the protocol version,
   cipher suite, negotiated ALPN, SNI sent, alerts, and timing. Its closed
   payload, in schema declaration order, is:

   ```text
   TLS_TRANSPORT_RESULT
   - endpoint_entity_id
   - peer_entity_id?
   - result
   - protocol_version
   - cipher_suite
   - negotiated_alpn
   - sni_sent
   - alert_code?
   - duration_ns
   ```

   `endpoint_entity_id` is required for every result and MUST resolve to an
   entity of kind `SOCKET_ENDPOINT`. `peer_entity_id` is optional; when
   present, it MUST resolve to an entity of kind `TLS_PEER` whose identity was
   derived from a presented certificate. A failed or timed-out handshake
   before certificate presentation MUST omit `peer_entity_id` and MUST NOT
   fabricate a sentinel fingerprint, placeholder peer, or endpoint-as-peer
   identity. Failed and timed-out handshakes still produce direct
   `TLS_TRANSPORT_RESULT` observations; a `CheckExecution` alone is not a
   substitute. Handshake completion proves cryptographic transport
   negotiation, not peer presentation or certificate validity.
2. `TLS_PEER_SUMMARY` records minimal derived peer-certificate evidence such as
   certificate count, leaf SHA-256 fingerprint, relevant validity timestamps,
   and SAN type/count summaries. SAN values are not persisted by default;
   hostname verification reports only whether the requested hostname matched.
   Raw DER, PEM, SAN lists, and full certificate chains are not persisted in a
   normal report.
3. `CERTIFICATE_VERIFICATION_RESULT` separately records the verified hostname,
   verification time, trust source, result, and normalized failure reasons such
   as hostname mismatch, expired, not yet valid, untrusted issuer, invalid
   usage, or verifier unavailable.
4. HTTPS application probing depends on successful certificate verification.
   If verification fails or is unknown, the HTTP check is `SKIPPED` with reason
   `tls_peer_unverified`. TLS transport and peer evidence remain reportable.

V1 has no option to send ordinary HTTP over unverified TLS.

The result-dependent cases are:

- TCP success followed by a TLS timeout before certificate presentation names
  the attempted endpoint, omits the peer, and is valid timed-out transport
  evidence.
- TCP success followed by a reset during the handshake names the attempted
  endpoint, omits the peer when no certificate identity was obtained, and is
  valid failed transport evidence.
- A plaintext server on an HTTPS port produces a failed transport result for
  the attempted endpoint and no fabricated peer.
- When the handshake completes and a certificate is presented, the endpoint
  remains required and the optional peer may identify the certificate-derived
  `TLS_PEER`; peer summary and certificate verification remain separate
  observations.
- When certificate presentation succeeds but verification fails, transport
  may be `COMPLETED`, the certificate-derived `TLS_PEER` exists and remains
  reportable, verification separately records the failure, and HTTP remains
  skipped.

Semantic validation MUST reject `endpoint_entity_id` when it resolves to any
entity kind other than `SOCKET_ENDPOINT`, and MUST reject a present
`peer_entity_id` when it resolves to any entity kind other than `TLS_PEER`.
Both failures use `reference.kind_mismatch`; the fact that all entity IDs share
one lexical ID type does not permit cross-kind substitution.

### 7.11 Visibility assessment

Absence is never inferred from an empty or inaccessible collection.

```text
VisibilityAssessment
- visibility_id
- subject_kind
- vantage_id
- scope
- level
- basis_observation_ids[]
- limitations[]
- assessed_at
```

`level` is:

- `COMPLETE_FOR_SCOPE`;
- `PARTIAL`;
- `UNKNOWN`;
- `NOT_APPLICABLE`.

`scope` is typed and narrow. A socket-inventory scope includes at least the
network namespace, protocol, address family, address/bind semantics, port
range, and whether process ownership is required. Completeness for listener
existence does not imply completeness for process ownership.

For listener existence, a `COMPLETE_FOR_SCOPE` assessment is admissible only
when `basis_observation_ids` contains at least one
`LISTENER_INVENTORY_RESULT` that has the same vantage, namespace, protocol,
address family, and bind semantics as the assessment and whose inclusive port
range contains the assessment's entire port range. An entry observation, an
unrelated observation, an attempted collection, a `COMPLETED` check lifecycle,
or the assessment's own `level` cannot establish completeness. The result
observation remains the typed base fact even when a check execution links to
it.

`process_ownership_required = false` makes the completed inventory result
sufficient for the listener-existence dimension; ownership evidence is not
required. When `process_ownership_required = true` and the qualifying result
has a nonzero count, its port range MUST exactly equal the assessment's port
range and `basis_observation_ids` MUST additionally contain distinct positive
`LISTENER_INVENTORY_ENTRY` observations whose distinct concrete listener
identities account for exactly that count, plus matching
`PROCESS_OWNERSHIP_ENTRY` observations for every such listener. Distinct
observation IDs do not establish distinct listeners: multiple entries or
ownership observations describing the same concrete listener identity count
once. Exact range is required in this case because a nonzero aggregate over a
broader range does not state how many listeners fall inside the narrower
assessment. When a qualifying result has count zero, there is no matching
listener whose ownership must be established, so no ownership entry is
required. A completed listener inventory result never by itself proves process
ownership.

A negative rule MUST name the visibility dimensions it requires and MUST link
to a matching, properly grounded `COMPLETE_FOR_SCOPE` assessment. Partial or
unknown visibility can support a limitation or suspicion, never a negative
fact.

### 7.12 Evidence reference and claim

```text
EvidenceRef
- kind
- id
```

`kind` is exactly `OBSERVATION`, `CLAIM`, `VISIBILITY`, or `ASSERTION`. `id`
MUST resolve to the corresponding typed collection in the same run. An
evidence reference cannot target a finding, check, entity, rule, or another
untyped identifier.

```text
Claim
- claim_id
- statement_code
- level
- subject_entity_ids[]
- branch_ids[]
- parameters
- supporting_evidence[] EvidenceRef
- contradicting_evidence[] EvidenceRef
- required_missing_evidence[]
- rule_id
```

`parameters` and each missing-evidence requirement are closed payloads selected
by `statement_code`; neither is free text or an arbitrary object. Missing
evidence has no fabricated ID and cannot be used as positive support.

`level` is rigid:

- `OBSERVED`: a faithful typed restatement of one or more direct observations;
- `INFERRED`: entailed by a versioned rule under explicit assumptions;
- `SUSPECTED`: plausible but not entailed; missing evidence is named.

All V1 claims are produced by rule evaluation, so `rule_id` is mandatory even
for an `OBSERVED` restatement rule. An `OBSERVED` claim cannot cite another
claim as its sole support. An `INFERRED` claim MUST have a complete support
path to admissible base evidence. A `SUSPECTED` claim cannot be used as
required support for a confirmed finding.

A `CLAIM` evidence reference MUST point to a claim allocated earlier in the
same deterministic evaluation. This makes claim ancestry acyclic by
construction; validation still detects and rejects forward references and
cycles in loaded reports.

### 7.13 Finding

```text
Finding
- finding_id
- kind
- title_code
- level
- branch_ids[]
- path_positions[] { branch_id, position }
- claim_ids[]
- rule_id
- limitations[]
- suggested_experiments[]
- selection
```

`kind` is `BLOCKER`, `EXPECTATION_FAILURE`, `PARTIAL_REACHABILITY`, `ADVISORY`,
or `LIMITATION`.

`level` uses the same rigid `OBSERVED`, `INFERRED`, or `SUSPECTED` vocabulary as
claims. A blocker at `OBSERVED` or `INFERRED` level is rendered as a confirmed
blocking condition only when its complete evidence contract is met. A
`SUSPECTED` finding is never presented or selected as confirmed.

All V1 findings are rule-produced, so `rule_id` is mandatory. A finding MUST
cite at least one claim, and each cited claim MUST exist in the same evaluated
run. V1 has no non-rule finding representation: base results that do not need a
rule are rendered as checks or observations, not promoted to findings. Finding
selection may change only `selection`; it does not change producing-rule
identity.

`path_positions` replaces a map-shaped wire value. It contains at most one
entry per `branch_id`, is sorted by canonical branch order, and each position
indexes that branch's semantic `ordered_edge_ids` sequence.

`selection` is `GLOBAL_PRIMARY`, `BRANCH_PRIMARY`, `ADDITIONAL`, or `NONE`.

### 7.14 Rule identity and version

Every rule has an immutable stable ID in this form:

```text
<domain>.<conclusion>/v<integer>
```

Examples:

```text
tls.certificate_hostname_mismatch/v1
tcp.connection_refused/v1
listener.no_matching_listener_visible/v1
```

Changing evidence requirements, conclusion strength, branch semantics, or
wording meaning requires a new rule version. Refactoring that preserves all
observable behavior does not.

Architecture revision 1.2 defines the corrected initial evidence contract for
`listener.no_matching_listener_visible/v1` before Milestone 0 freeze. Because
that rule has not passed independent review or been released, this correction
does not create a `/v2`; after the initial rule contract is frozen, the normal
versioning rule above applies.

Rules are ordinary Go values behind an internal interface equivalent to:

```text
ID() RuleID
Evaluate(EvidenceRun) []RuleCandidate
```

The registry is compiled into the binary and ordered by rule ID. It is not a
public extension point. Rules consume only validated typed model values and
produce candidates with auditable typed evidence references.

Each `RuleCandidate` has a rule-local stable `candidate_key`, a topologically
ordered claim bundle, and a deterministically ordered set of one or more
findings that cite claims from that bundle. Candidate keys MUST be unique within
a rule evaluation; duplicates fail with `rule.duplicate_candidate_key` rather
than falling back to goroutine or insertion order. A claim may cite only an
earlier claim produced by the same rule. A finding may cite only claims with
the same producing rule ID. A rule evaluates base evidence only. V1 rules do
not consume findings or claims emitted by other rules, do not iterate to a
fixpoint, and do not write inferred relationships into base topology. This
keeps evaluation an ordinary deterministic pass rather than a generic
inference framework.

### 7.15 Evaluation phases

The internal model has two phases:

```text
EvidenceRun
- run metadata, target, goal, scope, policy, and clock-derived times
- vantage points, capabilities, and operator assertions
- entities and base service-path topology
- check definitions and executions
- observations and visibility assessments
- no evaluation record, claims, findings, or selections

EvaluatedRun
- evidence EvidenceRun
- evaluation { evaluated_at, ordered_rule_ids[] }
- claims[]
- findings[] including selections
```

`Evaluate(EvidenceRun) -> EvaluatedRun` is recomputational. It evaluates the
exact statically registered rules listed in `ordered_rule_ids`, derives claims
and findings, performs branch/global selection, and validates the result. It
never appends to existing derived state.

The V1 persisted report schema is a coherent flattened representation of
`EvaluatedRun`; `evaluation`, `claims`, and `findings` are required. An
`EvidenceRun` is an internal phase value and is not serialized as a completed
V1 report.

Rule-produced IDs are allocated only after all candidates have been sorted by
rule ID and then by rule-local `candidate_key`. Claims within a candidate keep
their declared topological order. The evaluator assigns zero-padded run-local
IDs sequentially:

```text
claim-000001
claim-000002
finding-000001
```

The numeric suffix is one-based decimal padded to at least six digits; values
above 999999 expand without truncation and are compared numerically. Findings
are allocated after all claims so their claim references are stable. No UUID or
content hash is used. Candidate keys and generated IDs MUST NOT contain
sensitive or transient request data. Repeated evaluation of the same validated
base evidence, rule registry, policy, clock, and producer metadata produces the
same derived IDs.

Persisted-report operations have fixed semantics. Exact-version reports are
strictly decoded and fully validated. Newer-minor reports follow the read-only
compatibility projection in section 15.2 and surface every ignored-field
warning:

- `render` renders the stored known claims, findings, and selections without
  evaluating rules; canonical `--json` output requires the exact version;
- `explain` traverses the stored known finding-to-claim-to-evidence references
  without evaluating rules;
- `validate` checks the stored report as written to the extent understood,
  including derived IDs, rule provenance, reference resolution, acyclicity,
  canonical ordering of known fields, and selection invariants, without
  evaluating rules;
- rule re-evaluation strictly decodes and fully validates the stored report,
  extracts a fresh `EvidenceRun` by discarding the prior evaluation record,
  claims, findings, and selections, and calls `Evaluate` once with the current
  registry and explicitly supplied clock. Existing derived state is never
  retained or appended.

Rule re-evaluation is permitted only for the exact supported report schema
version. A newer-minor report that was read through compatibility projection
cannot be re-evaluated because ignored base fields might affect semantics.

## 8. Architectural invariants

Every implementation and report MUST preserve these invariants:

1. **Vantage invariant:** every network-relevant observation names exactly one
   typed vantage point.
2. **No vantage substitution:** evidence from one vantage or namespace cannot
   satisfy a rule requiring another unless an explicit, rule-approved identity
   relation is observed.
3. **Temporal invariant:** observations include time; rules requiring a coherent
   snapshot enforce a documented maximum observation window.
4. **TLS separation invariant:** every TLS transport result is attributed to
   the exact attempted socket endpoint. TLS transport success, peer evidence,
   and certificate verification are distinct; none implies another. A
   pre-certificate transport failure has no fabricated TLS peer.
5. **Verified-HTTP invariant:** HTTPS application traffic is not sent after
   failed or unknown certificate verification in V1.
6. **Absence invariant:** every negative conclusion based on inventory absence
   requires matching `COMPLETE_FOR_SCOPE` visibility grounded in a successful
   typed completion observation for the claimed inventory scope. Visibility
   cannot authenticate its own completeness.
7. **Provenance invariant:** configured intent, active runtime state, direct
   observation, operator assertion, inference, and suspicion remain distinct.
8. **Runtime precedence invariant:** conflicting active runtime evidence
   outranks configured intent; the conflict remains visible.
9. **Branch invariant:** blocker ordering occurs independently on each branch.
10. **Global-selection invariant:** `GLOBAL_PRIMARY` is allowed only when one
    existing rule-produced finding blocks the goal before all relevant branch
    splits or explicitly covers every relevant branch. Selection never creates
    or merges findings. Otherwise the report has branch-primary findings and no
    global primary.
11. **No negative permission inference:** denied or unavailable collection is
    not evidence that the target object is absent.
12. **No metadata-to-runtime promotion:** declarations, labels, exposed ports,
    and published mappings are not listener or process-execution proof.
13. **Justification invariant:** every claim has a complete acyclic path through
    typed supporting `EvidenceRef` values to observations, visibility
    assessments, or operator assertions. Every finding reaches base evidence
    only through its cited claims.
14. **No suspicion promotion:** suspected claims cannot justify confirmed or
    inferred conclusions.
15. **Sensitive-input invariant:** collectors persist only allowlisted derived
    fields. Unknown fields from collector source payloads are discarded, not
    copied into generic metadata. Report-schema unknown fields follow section
    15.2 instead.
16. **Determinism invariant:** identical validated input models, rule versions,
    policy, and clock produce byte-equivalent canonical JSON and equivalent
    human output.
17. **Stable-order invariant:** concurrency completion order never affects
    entity, observation, branch, claim, or finding order.
18. **Read-only invariant:** V1 collectors and adapters perform no external
    configuration or runtime mutation.
19. **Failure-domain invariant:** collector or RouteDoctor errors yield
    `UNKNOWN`, `SKIPPED`, or execution `ERROR`; they are never attributed to the
    diagnosed target.
20. **Minimization invariant:** secrets, credentials, cookies, authorization
    values, URL user information, query values, raw path segments, Caddy path
    matcher values, raw proxy configuration, raw certificate chains, and
    unrelated configuration never enter normal reports.
21. **Rule-provenance invariant:** every persisted claim and finding has a
    mandatory producing `rule_id`; V1 has no non-rule derived claims or
    findings.
22. **Evaluation-phase invariant:** rules accept only `EvidenceRun`; evaluation
    discards and recomputes all derived state rather than appending to it.
23. **Derived-ID invariant:** claim and finding IDs are allocated sequentially
    after deterministic candidate ordering and remain run-local.
24. **Closed-reference invariant:** support and contradiction use `EvidenceRef`
    only, all targets resolve to the declared typed collection, and a claim may
    reference only an earlier claim produced by the same rule. Every finding
    cites only claims produced by its own `rule_id`.
25. **Evaluation-provenance invariant:** every claim and finding `rule_id`
    appears exactly once in the evaluation record's `ordered_rule_ids`. Stored
    reports remain explainable even if that rule is absent from the current
    binary; only re-evaluation uses the current registry.

## 9. Evidence contracts for conclusions

The following table defines the strongest conclusion allowed by each evidence
class. Rules may be more conservative but not stronger.

Admissible base evidence consists only of observations, matching scoped
visibility assessments, and operator assertions. An assertion can establish an
expected path, goal, or authorized scope; it cannot prove observed runtime or
network behavior. A rule-produced claim may cite an earlier claim, but its
ancestry MUST terminate in admissible base evidence. A finding cites claims
only and carries the producing rule ID; it cannot bypass the claim layer by
citing an observation directly.

Supporting and contradicting evidence are both typed and auditable. A rule
MUST either resolve relevant contradiction or reduce/withhold its conclusion;
it cannot omit known contradictory evidence from the produced claim.

| Conclusion | Minimum allowed evidence | Forbidden overclaim |
|---|---|---|
| Name resolved at vantage | Completed system-resolution observation at that vantage | “Public DNS is correct” |
| No IPv4/IPv6 result observed | Completed resolver result for that family and vantage | “No A/AAAA record exists” unless an explicit DNS query proves it |
| TCP accepted | Successful TCP connection to exact endpoint from exact vantage | Reachable from other vantages |
| TCP refused | Normalized refused result to exact endpoint from exact vantage | No listener exists; firewall is absent |
| TCP timed out | Timed-out attempt with deadline and endpoint | Firewall drop, routing failure, or remote outage as fact |
| TLS transport completed | Completed TLS handshake observation | Certificate valid; peer authenticated |
| TLS peer presented certificate | TLS peer summary derived in memory | Certificate trusted or valid |
| Certificate invalid | Completed verifier result with normalized reason, hostname, time, and trust source | TLS transport unavailable |
| HTTP response received | Plain HTTP response, or HTTPS response after successful verification, from named vantage | General/external availability; application correctness |
| Redirect target observed | HTTP response with sanitized valid Location | Redirect destination reachable |
| Active Caddy route contains upstream | Minimal derived evidence from active Caddy runtime JSON | Route matched the request |
| Configured Caddy route contains upstream | Minimal derived evidence from an explicitly supplied adapted config | Configuration is active |
| Caddy route definitively matches | Active config plus a fully supported matcher tree evaluated against transient request inputs, with only the result persisted | Match for unsupported/dynamic matcher semantics or persistence of matcher/path values |
| Upstream selected | Definitive active route match plus deterministic selection semantics for a single concrete upstream | Actual load-balancer choice when multiple/dynamic choices remain |
| Upstream refused connection | Exact endpoint probe from the exact proxy namespace/vantage | Same result from host or another container namespace |
| No matching listener visible | A zero-count `LISTENER_INVENTORY_RESULT` whose completed scope covers the target, plus a matching `COMPLETE_FOR_SCOPE` assessment grounded in that result | Absence from an omitted entry, a non-target entry, an attempt or execution lifecycle, a nonzero aggregate over a broader range, or self-declared visibility; process stopped; firewall cause; historical cause |
| Listener owned by process | Positive socket-to-process identity mapping | No owner exists when mapping is partial |
| Endpoint associated with container | Exact current runtime IP/network match or exact published-port mapping | Process is listening inside container |
| Container stopped | Active Docker runtime state | Stopped container is the intended application without path evidence |
| IPv4/IPv6 partial reachability | Successful goal on at least one family branch and confirmed blocker or failure on another, from same client vantage and coherent window | All clients experience the difference |
| Global primary blocker | One existing rule-produced finding before all relevant branch splits, or one aggregate finding with supported coverage of every relevant branch | Promotion or synthetic merging from one or more branch-only findings |
| Root cause | Versioned rule whose contract proves both current blocker and causal relation with no contradiction | Merely likely correction or temporal correlation |

The standard `tcp.connection_refused/v1` conclusion is therefore:

> The endpoint refused a TCP connection from this vantage at this time.

It is not:

> Nothing is listening.

The latter requires `listener.no_matching_listener_visible/v1` and scoped
visibility completeness.

The exact persisted contract for a `NO_MATCHING_LISTENER_VISIBLE` claim, and
therefore for any finding that cites it, is:

1. The target proposition identifies one vantage, namespace, protocol, address
   family, bind semantics, and the existing single target `port` value `P`.
   This contract does not add `port_start` or `port_end` to the claim payload.
   For comparison with ranged inventory results and visibility scopes, the
   claim port is treated as the degenerate inclusive range `[P, P]`.
2. `supporting_evidence` cites a `VISIBILITY` reference to a
   `COMPLETE_FOR_SCOPE` assessment at the same vantage. The assessment's
   namespace, protocol, address family, and bind semantics exactly equal the
   target's, and its inclusive port range contains `[P, P]`, equivalently
   `scope.port_start <= P` and `scope.port_end >= P`.
3. `supporting_evidence` also cites an `OBSERVATION` reference to a
   `LISTENER_INVENTORY_RESULT` named in that assessment's
   `basis_observation_ids`. The result has the same vantage, namespace,
   protocol, address family, and bind semantics as the assessment, its port
   range contains the assessment's entire port range, and
   `matching_listener_count` is zero.
4. No temporally coherent `LISTENER_INVENTORY_ENTRY` positively identifies a
   listener matching the target's vantage, namespace, protocol, address
   family, bind semantics, and port `P`.
5. No temporally coherent `LISTENER_INVENTORY_RESULT` with a nonzero count has
   the target's exact vantage, namespace, protocol, address family, and bind
   semantics and a represented port range contained by `[P, P]`. Because the
   target is a single port, this containment requires
   `result.port_start = P` and `result.port_end = P`. Such a result directly
   establishes one or more matching listeners at the claimed-absent port even
   when no individual `LISTENER_INVENTORY_ENTRY` is persisted.
6. Evidence matching item 4 or 5 is contradicting evidence. The evaluator MUST
   withhold the absence claim; a persisted report containing the claim despite
   either contradiction is invalid even if the observation was omitted from
   the claim's `contradicting_evidence` references.
7. All ordinary reference-resolution, typed-vantage, namespace identity,
   branch, temporal-coherence, support-level, rule-provenance, and selection
   requirements continue to apply.

Scope containment is deliberately directional. For absence proof, a result or
visibility port range contains claim port `P` when
`port_start <= P <= port_end`; a zero-count result such as `1..65535` may
therefore prove absence at port `443`, while `1..100` cannot. For presence
contradiction, the nonzero result's represented range must instead be contained
by the claim's degenerate `[P, P]` range. A broader nonzero aggregate that
merely contains `P` does not locate its listeners and is not by itself
contradictory. Vantage, namespace, protocol, address family, and bind semantics
require exact equality in both directions and are never widened or
substituted.

The evaluator and persisted-report validator MUST apply this same contract.
The validator does not merely check that referenced IDs resolve: it rejects a
stored absence claim or finding whose visibility is ungrounded, whose result
does not cover the target, whose required supporting result count is not zero,
or whose target is contradicted by a positive listener entry or a qualifying
coherent nonzero inventory result.

## 10. Blocker ordering and selection

For each branch, rules first produce eligible finding candidates. A candidate
is eligible only when all required evidence and visibility contracts are met
and no contradiction invalidates it.

Branch ordering is deterministic:

1. exclude `SUSPECTED` candidates from blocker selection;
2. choose the earliest blocking path position on that branch;
3. at the same position, prefer `OBSERVED` over `INFERRED` when the findings
   have the same statement code and affected goal;
4. for semantically equivalent candidates, use stable rule ID and then stable
   finding ID as tie-breakers;
5. retain non-equivalent eligible blockers at the same position as co-primary
   branch findings rather than inventing a specificity score.

An `INFERRED` blocker is eligible only when its rule's complete evidence
contract is met. Suspicions remain unselected explanations.

Global selection is a separate operation after branch selection. A global
primary is emitted only when:

- a single eligible finding is positioned before the split shared by every
  relevant branch; or
- a single eligible aggregate finding already produced by a rule explicitly
  covers every relevant branch and cites the supporting claims for that
  coverage.

Selection changes only the `selection` field of existing findings. It never
creates, merges, rewrites, or widens a finding. Equivalent separate branch
findings remain branch-primary unless a rule produced an independently
justified aggregate finding.

If one IPv6 address fails but another succeeds, or IPv6 fails while IPv4
succeeds, the relevant output is branch-specific or partial reachability. It is
not a global connectivity root cause.

Unexplored branches caused by caps, permissions, unsupported matchers, or
missing vantage points prevent global coverage unless a blocker occurs before
those branches diverge.

## 11. Probe and execution policy

Production probes are outside Milestone 0, but their required behavior is fixed
here:

- use in-process DNS, TCP, TLS, and HTTP primitives;
- retain the URL hostname for TLS SNI and HTTP Host while pinning selected IPs;
- bound concurrency, addresses per family, redirects, header bytes, body bytes,
  per-check duration, and total run duration;
- disable automatic response decompression by default;
- issue no authentication and persist no cookies;
- never forward authorization or cookies across redirects;
- treat redirect destinations as new path segments with their own branches;
- keep normalized request and redirect paths only in transient probe input;
- reapply address-scope policy at every redirect;
- block redirects into loopback, link-local, or private scopes unless the
  initial target was in that scope or explicit policy permits the transition;
- ensure output ordering is independent of goroutine completion order;
- record normalized errors, not OS-specific error strings as rule inputs.

HTTP GET is the V1 request method. It uses an explicit RouteDoctor user agent,
does not send credentials, and reads only a bounded response prefix. RouteDoctor
documents that nominally safe GET requests can still trigger side effects in a
misbehaving application.

Detected HTTP proxy environment variables are reported as a capability or
limitation but are not honored in V1. V1 diagnoses a direct client path.

## 12. Sensitive data and Caddy handling

Active Caddy configuration is sensitive input even when obtained from a local
admin endpoint.

The Caddy adapter MUST:

1. retrieve or receive the source only after explicit origin-mode authorization;
2. apply response-size and time limits;
3. parse the payload in memory;
4. traverse only allowlisted fields needed for server listeners, supported
   request matchers, handler order, reverse-proxy transport, and upstream
   identity;
5. create minimal typed observations;
6. discard the raw byte buffer and parsed source tree after derivation;
7. persist neither raw JSON nor arbitrary unknown source fields;
8. sanitize addresses and discard matcher values according to report policy;
9. never persist headers, credentials, tokens, certificate key material,
   unrelated routes, storage configuration, environment expansions, or module
   configuration;
10. persist only the matcher kind and result (`MATCHED`, `NOT_MATCHED`, or
    `UNKNOWN`) when path matching is evaluated; and
11. use synthetic, reviewed Caddy fixtures in the repository rather than
    captured production configuration.

An active Caddy API read proves runtime configuration state at retrieval time,
not that a particular request selected a route. An adapted Caddyfile proves
configured intent only. Unsupported matchers, placeholders, expressions,
dynamic upstreams, and third-party modules make the affected selection
`UNKNOWN` unless their semantics are explicitly added in a later approved
design revision.

## 13. Privilege and capability policy

RouteDoctor runs unprivileged by default and never escalates itself.

| Condition | Required result |
|---|---|
| Root required for a check | `SKIPPED` with stable reason `insufficient_privilege` |
| User voluntarily runs whole CLI as root | Continue read-only and emit an elevated-run warning |
| Docker endpoint inaccessible | `SKIPPED` or `UNKNOWN` with permission evidence |
| Docker endpoint accessible but not explicitly enabled | Do not access it |
| Docker enabled | Read-only list/inspect operations only |
| Process ownership hidden | Report visible listener only; ownership remains unknown |
| Namespace identity unavailable | Use `UNKNOWN_NAMESPACE`; do not substitute host vantage |
| External/client comparison absent | Say no observation exists from that vantage |
| Required helper binary missing | `UNAVAILABLE`; continue independent branches |
| Internal collector error | Lifecycle `ERROR`, verdict `UNKNOWN`; do not blame target |

Access to the Docker socket is security-sensitive and commonly equivalent to
host-level control. RouteDoctor MUST NOT recommend changing socket permissions,
joining a privileged group, or exposing the daemon merely to enable diagnosis.

## 14. Reporting and redaction

The default report is concise and organized by vantage and branch. Verbose
output adds evidence references, assumptions, and limitations. JSON contains
the same semantic model and never contains a hidden raw-data appendix.

Reports MUST:

- name the vantage for every network result;
- distinguish TLS transport, peer presentation, verification, and HTTP;
- group branch-primary findings under their address, family, redirect, route,
  or upstream branch;
- omit a global primary when coverage does not justify one;
- label every conclusion `OBSERVED`, `INFERRED`, or `SUSPECTED` in verbose and
  machine-readable forms;
- show why a skipped check was skipped;
- show limitations that reduce conclusion strength;
- omit URL user information, query values, fragments, and raw path segments;
- use an allowlist for retained HTTP headers; the V1 default allowlist is empty;
- never persist Authorization, Cookie, Set-Cookie, Proxy-Authorization, raw
  Caddy configuration, Docker environment variables, or secrets;
- sanitize redirect locations by retaining scheme, normalized host, effective
  port, and `PathSummary` only.

Human output is deterministic for a fixed report. Color is presentation only
and can be disabled. JSON is the archival and interchange form.

Exit codes for the eventual probe CLI are:

- `0`: requested goal satisfied with no confirmed blocker;
- `1`: at least one confirmed blocker prevents the requested goal on every
  relevant branch, or an explicit expectation failed;
- `2`: the goal is indeterminate because evidence or capability is insufficient;
- `3`: invalid invocation or configuration;
- `4`: RouteDoctor internal failure.

Partial reachability with at least one goal-satisfying branch is not exit `1`
unless the explicit goal requires all branches or families. It is reported
prominently and exits `0` by default.

## 15. Report and schema versioning

### 15.1 Versions

Three versions are independent:

- `report_schema_version`: semantic version of serialized report structure and
  meanings, initially `1.0.0` in Milestone 0;
- `producer.version`: RouteDoctor binary version;
- rule and check versions: stable IDs described above.

Architecture revision 1.2 corrected the listener-inventory gap before the
initial Milestone 0 freeze. Architecture revision 1.3 narrowly reopens that
internally frozen contract after Milestone 1 planning exposed a genuine TLS
transport representation defect: pre-certificate handshake failures could not
name their attempted endpoint without fabricating a certificate-derived peer.
Revision 1.3 adds required endpoint attribution, makes peer attribution
optional and certificate-dependent, and adds typed entity-kind validation.

Report schema remains `1.0.0`. No Git tag, release, or stable public `1.0.0`
report contract exists, so revisions 1.2 and 1.3 are corrections to the
still-unreleased initial contract rather than post-release schema changes.
After independent verification of revision 1.3 and its implementation,
Milestone 0 is re-frozen. This exception does not weaken the compatibility
policy below: after a public `1.0.0` release, adding a required field, changing
requiredness, or changing typed-reference semantics requires the version change
dictated by that policy. Writers and readers continue to support exactly one
report version; this correction introduces no second-version projection.

### 15.2 Compatibility policy

- A schema **major** change removes or reinterprets fields, changes required
  invariants, or changes the meaning of an existing enum value.
- A schema **minor** change adds optional fields, new observation kinds, or new
  enum values without changing existing meanings.
- A schema **patch** change clarifies validation or serialization without
  changing accepted semantic content.
- Writers emit exactly one schema version.
- Readers MUST reject unsupported major versions.
- For a document claiming the exact supported schema version, an unknown member
  at any object level is an error `schema.unknown_field`. Exact-version decoding
  is closed and strict; every 1.0.0 object schema uses
  `additionalProperties: false`.
- For a document claiming a newer minor version in the same supported major,
  unknown members are treated as optional additions under the minor-version
  contract. A reader may discard them only for read-only human `render`,
  `explain`, and known-field `validate`, and MUST emit the compatibility warning
  `schema.newer_minor_field_ignored` for every ignored member in canonical JSON
  Pointer order. The original document is not rewritten.
- Canonical JSON output and rule re-evaluation require the exact supported
  schema version. They reject a newer-minor compatibility projection with
  `schema.exact_version_required`, because an ignored base field might affect
  semantics.
- A newer patch version with no unknown member or semantic value is accepted
  for strict read-only `render`, `explain`, and `validate` under the known
  field contract. It is not the exact supported version for canonical JSON
  output or rule re-evaluation and therefore receives
  `schema.exact_version_required` for those operations. A patch version cannot
  introduce fields, enum values, or changed semantics.
- An unknown enum value is always `schema.unknown_enum_value`. An unknown
  discriminated-union `kind` is always `schema.unknown_union_kind`. These are
  errors for exact, patch, and newer-minor documents; they are never ignored or
  mapped to an existing value.
- Required fields are never inferred from missing data during decoding.
- Ignored newer-minor members are not stored in generic extension maps, copied
  into reports, included in evidence, or used by rules.

### 15.3 Canonical form

Milestone 0 defines the RouteDoctor Canonical JSON Profile 1. It uses Go's
standard `encoding/json` behavior with a small explicit profile; no separate
serialization framework is required.

#### 15.3.1 Document and token encoding

- The document is UTF-8 without a byte-order mark. Invalid UTF-8 in an in-memory
  string is a validation error rather than being replaced during serialization.
- Output is compact: no spaces or indentation occur outside JSON strings.
- The serialized document ends with exactly one LF byte (`0x0a`). There are no
  bytes after that LF.
- Object members appear in the declaration order fixed by schema 1.0.0, never
  Go map iteration order and never ad hoc lexical ordering.
- Top-level member order is exactly:
  `report_schema_version`, `producer`, `run_id`, `target`, `goal`,
  `requested_scope`, `policy`, `started_at`, `finished_at`,
  `vantage_points`, `capabilities`, `operator_assertions`, `entities`,
  `service_path`, `check_definitions`, `check_executions`, `observations`,
  `visibility_assessments`, `evaluation`, `claims`, `findings`, `limitations`.
- Nested object member order is the declaration order in
  `schema/report/v1.0.0/schema.json`. Because JSON Schema property order is not
  semantically significant, every object schema also declares an
  `x-routedoc-member-order` array. A union emits `kind` first, followed by the
  fields of that kind in that declared order. For models shown in section 7,
  the displayed field order is the required schema declaration order.
- The `LISTENER_INVENTORY_RESULT` union member order after `kind` is exactly
  `namespace_entity_id`, `protocol`, `address_family`, `bind_semantics`,
  `port_start`, `port_end`, `matching_listener_count`. Its payload contains no
  arrays, so it adds no collection-order rule.
- The `TLS_TRANSPORT_RESULT` union member order after `kind` is exactly
  `endpoint_entity_id`, `peer_entity_id`, `result`, `protocol_version`,
  `cipher_suite`, `negotiated_alpn`, `sni_sent`, `alert_code`, `duration_ns`.
  Optional absent members are omitted without changing the relative order of
  members that remain.
- Field names are `snake_case`. Typed IDs and enums use JSON strings; enum
  tokens are the exact uppercase tokens defined by the schema.
- JSON string escaping follows Go `encoding/json` with HTML escaping disabled.
  `<`, `>`, and `&` are emitted as UTF-8 rather than `\u003c`, `\u003e`, and
  `\u0026`. Quote, reverse solidus, and control characters use Go's standard
  escapes. U+2028 and U+2029 are always emitted as `\u2028` and `\u2029`.
  Other valid non-ASCII characters remain UTF-8. Unicode normalization is not
  performed.
- Persisted numeric values are signed or unsigned integers only. They use the
  shortest base-10 lexical form with no leading plus, no unnecessary leading
  zeros, and `0` rather than negative zero. Floats, exponent notation, NaN, and
  infinity are forbidden.
- Timestamps use UTC Go `time.RFC3339Nano` form; durations are integer
  nanoseconds.
- Optional absent fields are omitted. Required empty collections are `[]`, not
  `null`. Optional absent objects are omitted, not emitted as `null`.
- No persisted object has arbitrary keys. `path_positions` is an ordered array
  of closed `{branch_id, position}` objects, not a branch-keyed object.

#### 15.3.2 Collection ordering

Every schema array is classified as `SET` or `ORDERED`; adding an array in a
later schema requires declaring that classification. The JSON Schema records
it with `x-routedoc-array-kind`; each `SET` also declares
`x-routedoc-sort-key`. Profile 1 ordering is:

| Collection | Classification and canonical order |
|---|---|
| `vantage_points` | `SET`, ascending `vantage_id` |
| vantage limitations | `SET`, ascending `limitation_id` |
| `capabilities` | `SET`, ascending `capability_id` |
| `operator_assertions` | `SET`, ascending `assertion_id` |
| `entities` | `SET`, ascending `entity_id` |
| service-path `nodes` | `SET`, ascending `entity_id` |
| service-path `edges` | `SET`, ascending `edge_id` |
| service-path `branches` | `SET`, parents before descendants, then ascending `branch_id` among peers |
| branch `ordered_edge_ids` | `ORDERED`, preserve service-path semantics exactly |
| edge `evidence_refs` | `SET`, evidence-kind enum order then ascending ID |
| `check_definitions` | `SET`, ascending `check_id` |
| check dependencies/capabilities | `SET`, ascending typed ID |
| `check_executions` | `SET`, ascending `execution_id` |
| execution observation/visibility IDs | `SET`, ascending typed ID |
| `observations` | `SET`, ascending `observation_id` |
| observation subject IDs | `SET`, ascending `entity_id` |
| observation limitations | `SET`, ascending `limitation_id` |
| `visibility_assessments` | `SET`, ascending `visibility_id` |
| visibility basis observations | `SET`, ascending `observation_id` |
| visibility limitations | `SET`, ascending `limitation_id` |
| evaluation `ordered_rule_ids` | `ORDERED`, unique ascending rule ID; the order is persisted and used for evaluation |
| `claims` | `SET`, ascending generated numeric claim ID |
| claim subject/branch IDs | `SET`, entity ID ascending / canonical branch order |
| claim support/contradiction refs | `SET`, evidence-kind enum order then ascending ID |
| claim missing-evidence requirements | `SET`, requirement-kind enum order, then scalar field values in schema declaration order using string byte order and numeric order |
| `findings` | `SET`, ascending generated numeric finding ID |
| finding branch IDs and `path_positions` | `SET`, canonical branch order |
| finding claim IDs | `SET`, ascending claim ID |
| finding suggested experiments | `ORDERED`, preserve rule-authored recommendation order |
| top-level and nested limitations | `SET`, ascending `limitation_id` |

No other arrays are permitted in schema 1.0.0. Initial assertion parameters,
observation payloads, claim parameters, and missing-evidence requirement
payloads are array-free closed unions; repeated facts are represented by
separate typed records. A later schema that adds an array MUST classify and
order it normatively. There is no implicit default.

Canonical byte equivalence is required for a fixed validated model, policy,
clock, producer metadata, and exact rule versions. A report validator checks
IDs, references, vantage requirements, lifecycle/verdict combinations,
justification acyclicity, visibility contracts, collection ordering, and
selection invariants before serialization. Serialization itself does not sort
or repair an invalid model.

Model construction and evaluation use a deterministic canonicalization step
before final validation: it sorts every `SET` collection by the table above and
preserves every `ORDERED` collection exactly. Decoding a persisted document
preserves its wire order so `validate` can report `ordering.noncanonical` rather
than silently repairing it. The serializer accepts only a canonical, validated
`EvaluatedRun` produced by construction/evaluation or explicit
canonicalize-and-validate API.

Golden fixtures are immutable once released under a schema version. Corrections
that change semantic content add a new fixture and document the replaced case.

## 16. Configuration

The planned configuration format is strict, versioned TOML. Precedence is:

```text
CLI flags > explicit --config file > conservative built-in defaults
```

V1 does not automatically load configuration from the current directory.
Unknown keys are errors. Configuration values are operator assertions or
policy, not observations.

The initial config surface is limited to:

- schema/config version;
- time, response-size, address, and redirect limits;
- explicit local-origin assertion;
- explicit Caddy active API or config-file source;
- explicit Docker enablement and endpoint;
- explicit HTTP expectations;
- private-address redirect policy;
- output/redaction policy where a safe choice exists.

Configuration cannot define commands, scripts, rules, plugins, collectors, or
repair actions.

## 17. Technology and dependency policy

### 17.1 Language and toolchain

RouteDoctor is implemented in Go.

The Milestone 0 baseline is Go `1.26.5`. The future `go.mod` MUST declare Go
1.26 semantics and the repository MUST pin the exact Go 1.26 patch toolchain
used by CI. Patch releases within Go 1.26 are adopted promptly, especially for
`net`, `net/http`, `crypto/tls`, and `crypto/x509` security fixes. A move to Go
1.27 or later requires a reviewed maintenance change, not an architecture
revision unless observable diagnostic semantics change.

Supported build platforms for client probes are the Go-supported Linux,
macOS, and Windows targets selected by the release matrix. Deep origin packages
use explicit Linux build constraints and expose unsupported capability results
elsewhere.

### 17.2 Dependency policy

No dependencies are added during this design phase.

Implementation policy is:

1. Prefer the Go standard library.
2. Every third-party dependency requires a written purpose, license check,
   maintenance check, and explanation of why a small internal implementation or
   standard library is insufficient.
3. Pin direct dependencies in `go.mod`/`go.sum`; do not use floating versions.
4. Keep protocol and report model packages independent of Caddy and Docker
   dependencies.
5. Do not expose third-party types in core package APIs.
6. Do not add a dependency-injection framework, rule engine, plugin framework,
   logging framework, terminal UI framework, or generic graph database.
7. Use `govulncheck` and license review in release CI once dependencies exist.
8. Dependency upgrades require tests proving unchanged report semantics or an
   explicit schema/check/rule version change.

Expected candidates, to be confirmed in implementation planning, are:

- standard library for core CLI, JSON, networking, TLS, HTTP, time, and
  concurrency;
- `golang.org/x/net/idna` for IDNA processing;
- `github.com/BurntSushi/toml` for strict TOML decoding;
- `github.com/moby/moby/client` behind the Docker adapter.

Caddy is not linked as a library. The adapter consumes active JSON or invokes
the explicitly selected `caddy adapt` binary with a fixed argument vector and
parses bounded structured output. Subprocess invocation is not a generic
command facility.

## 18. Testing strategy

Required CI does not use the public Internet.

### 18.1 Deterministic model and rule tests

- typed-model validation tests for every invariant;
- table tests for lifecycle/verdict combinations;
- justification DAG validation and cycle rejection;
- typed evidence-reference target and forward-claim rejection;
- mandatory claim/finding producing-rule provenance;
- re-evaluation replacement and deterministic generated-ID tests;
- vantage mismatch rejection;
- scoped completeness tests proving that listener visibility is grounded only
  by a qualifying `LISTENER_INVENTORY_RESULT`, that a zero-count range
  containing claim port `P` can support absence at `P`, and that partial
  visibility, a positive entry, or an execution lifecycle cannot support
  completeness;
- listener-absence contract tests for wrong vantage, namespace, protocol,
  address family, bind semantics, port coverage, nonzero results offered as
  absence proof, contradictory positive target listeners, and exact-port
  nonzero results with no individual listener entry. Tests MUST also prove that
  a broader nonzero aggregate is not treated as locating a listener at `P`.
  These cases apply identically to evaluator output and persisted-report
  validation;
- branch-local and global-primary selection tests;
- stable ordering under randomized insertion and completion order;
- redaction and sensitive-field allowlist tests;
- proof that raw request/redirect paths and matcher values never serialize;
- canonical JSON golden files;
- byte-level canonical tests for member order, compact whitespace, UTF-8,
  escaping, integer lexemes, collection order, semantic-order preservation,
  and the single trailing LF;
- human rendering golden files;
- schema compatibility fixtures;
- exact/newer-minor unknown-field and unknown-semantic-value tests;
- fake-clock tests for time-dependent claims.

### 18.2 Controlled protocol tests after Milestone 0

- in-process resolver, TCP, TLS, and HTTP servers;
- generated test CAs and certificates for valid, expired, not-yet-valid,
  wrong-name, SNI-dependent, and untrusted cases;
- proof that peer evidence survives verification failure;
- proof that HTTP receives no request after verification failure;
- redirect loops, cross-scope redirects, malformed locations, oversized data,
  and timeouts.

### 18.3 Adapter tests after Milestone 0

- hand-authored, minimal Caddy JSON parser inputs containing supported and
  unsupported matchers, stored separately from report fixtures and never
  captured from a production instance;
- tests that secret-bearing unrelated fields never enter observations or
  serialized fixtures;
- a fake bounded Docker Engine API with synthetic container/network responses;
- Linux proc/socket fixtures for complete, zero-result, partial, denied, and
  racing views, proving that only successfully completed enumeration emits
  `LISTENER_INVENTORY_RESULT`;
- error normalization fixtures for supported operating systems.

### 18.4 Optional integration tests

Separate non-required jobs may use Linux network namespaces, Docker Compose,
and a real Caddy process. They validate adapter assumptions but do not replace
deterministic unit and contract tests.

## 19. Milestone 0: diagnostic contract

Milestone 0 implements no DNS, TCP, TLS, HTTP, Caddy, Docker, socket, process,
or platform probes. It makes the diagnostic contract executable against
synthetic reports.

### 19.1 Deliverables

The implementation agent MUST deliver:

1. A Go module using the provisional module path `routedoc` and the toolchain
   policy in section 17. The module path is intentionally private to the
   architecture phase and MUST be replaced before the first public package or
   release if naming clearance selects a different canonical path.
2. Core Go types for every concept in section 7, using closed typed enums and
   typed IDs rather than free-form strings at API boundaries, including
   `OperatorAssertion`, `EvidenceRef`, `EvidenceRun`, and `EvaluatedRun`.
3. Constructors or validators that enforce all invariants applicable without
   live probes.
4. A `1.0.0` JSON codec and RouteDoctor Canonical JSON Profile 1 serializer
   following section 15, including exact member/collection order, escaping,
   whitespace, and trailing-LF tests.
5. A machine-readable JSON Schema at
   `schema/report/v1.0.0/schema.json`, using JSON Schema draft 2020-12, that
   documents the closed persisted shape. Tests MUST prove every valid golden
   fixture conforms to it using a pinned test-only validator reviewed under
   section 17. Runtime validation remains in Go; the validator does not enter
   the production binary.
6. A report validator that returns stable machine-readable validation codes and
   deterministic, human-readable error ordering.
7. The internal, statically registered versioned rule interface from section
   7.14, with no DSL or external registration.
8. A deterministic `Evaluate(EvidenceRun) -> EvaluatedRun` implementation using
   section 7.15 semantics: stable rule/candidate ordering, topological claim
   bundles, sequential generated IDs, branch/global selection, and full output
   validation. It MUST also expose re-evaluation of a validated exact-version
   `EvaluatedRun` by extracting base evidence and replacing all derived state.
9. Three exemplar V1 rules solely to prove architecture:
   - `tls.certificate_hostname_mismatch/v1`;
   - `tcp.connection_refused/v1`;
   - `listener.no_matching_listener_visible/v1`.
10. The exact evidence contracts in section 9 for those rules. The listener
    rule and persisted-report validator MUST enforce the identical
    `NO_MATCHING_LISTENER_VISIBLE` contract, including the direct result,
    visibility grounding, range coverage of the existing single claim port,
    zero-count, contradiction, process-ownership, vantage, and
    temporal-coherence requirements. Tests MUST prove that the listener rule
    does not fire and a stored claim does not validate when any required
    element is absent or mismatched.
11. A renderer for deterministic concise human output and a verbose renderer
    that exposes vantage, branch, level, rule ID, evidence links, and
    limitations.
12. A non-network CLI with exactly these commands:

    ```text
    routedoc render REPORT.json [--verbose] [--json]
    routedoc explain REPORT.json FINDING_ID [--json]
    routedoc validate REPORT.json [--json]
    routedoc version [--json]
    ```

    `render` reads a completed synthetic report and formats it. `explain`
    traverses only the stored finding-to-claim-to-evidence graph. `validate`
    performs schema and invariant validation. None evaluates rules, evaluates a
    URL, or accesses local runtime state. `render --json` emits canonical JSON
    only for the exact supported schema version.
13. Synthetic fixtures covering:
    - valid multi-branch reachability with no global finding;
    - IPv4 success and IPv6 failure with branch-local partial reachability;
    - TCP success followed independently by a TLS timeout and a reset before
      certificate presentation, each with the exact socket endpoint, no peer,
      and a direct failed or timed-out transport observation;
    - a plaintext server on an HTTPS port represented as failed TLS transport
      for the exact socket endpoint with no fabricated peer;
    - TLS transport completion with a presented certificate, exact endpoint,
      optional certificate-derived peer attribution, separate peer summary,
      and separate successful verification;
    - TLS transport completion plus certificate verification failure, retained
      endpoint and peer evidence, and skipped HTTP;
    - malicious cross-kind TLS references where `endpoint_entity_id` names a
      `TLS_PEER` or `peer_entity_id` names a `SOCKET_ENDPOINT`, both rejected as
      `reference.kind_mismatch`;
    - Caddy configured intent conflicting with active derived state;
    - refused upstream from a wrong vantage, which cannot justify the proxy
      namespace conclusion;
    - absent listener with a direct zero-count
      `LISTENER_INVENTORY_RESULT` for the exact typed scope and grounded
      complete-for-scope visibility, which may fire without fabricating a
      positive listener entry;
    - absent listener with a broader zero-count completed result whose port
      range contains the otherwise-equal target port, which may fire;
    - absent listener with partial visibility, which may not fire;
    - complete-for-scope listener visibility with no completed-result basis,
      which is invalid and may not fire;
    - completed listener-inventory results with, independently, the wrong
      vantage, namespace, protocol, address family, bind semantics, or a port
      range that does not cover the target, each of which may not fire;
    - a broader completed result with a nonzero count that does not establish
      target-port absence, which may not fire;
    - an exact-target-port `LISTENER_INVENTORY_RESULT` with count one and no
      corresponding individual listener entry, which contradicts absence and
      makes a persisted absence claim invalid;
    - a valid zero-count target-port proof accompanied by a broader coherent
      nonzero result, which remains valid when no other contradiction exists
      because the broader aggregate does not locate a listener at the target
      port;
    - a positive target `LISTENER_INVENTORY_ENTRY` contradicting the proposed
      absence, which may not fire and makes a persisted absence claim invalid;
    - two independent proxy upstream branches with no global primary;
    - operator assertions supporting an expected path without being promoted
      to observations;
    - a multi-claim acyclic justification path plus rejected forward/cyclic
      claim references;
    - mandatory and recoverable claim/finding rule provenance;
    - re-evaluation replacing prior derived state without duplicate claims or
      findings and reproducing sequential IDs;
    - raw request and redirect paths represented only by `PathSummary`;
    - sensitive input represented only by sanitized derived observations;
    - exact-version unknown fields, newer-minor ignored optional fields, and
      unknown enum/union values with the required outcomes.
14. Golden JSON and human outputs for every fixture.
15. Fuzz tests for JSON decoding, ID/reference validation, and justification
    graph validation.
16. Documentation describing how to add an internal rule while preserving rule
    ID/version and evidence requirements. It MUST explicitly state that this is
    not a plugin API.

### 19.2 Required stable validation codes

Milestone 0 MUST define, at minimum:

```text
schema.unsupported_major
schema.missing_required_field
schema.unknown_field
schema.newer_minor_field_ignored
schema.unknown_enum_value
schema.unknown_union_kind
schema.exact_version_required
id.duplicate
id.invalid_generated_sequence
reference.missing
reference.kind_mismatch
reference.forward_claim
reference.cross_rule_claim
vantage.required
vantage.mismatch
execution.invalid_state
justification.missing
justification.cycle
visibility.scope_mismatch
visibility.insufficient_for_absence
assertion.invalid_source
rule.duplicate_candidate_key
rule.unlisted_provenance
claim.rule_required
claim.invalid_support_level
finding.rule_required
finding.claim_required
finding.rule_mismatch
finding.invalid_global_primary
sensitive.disallowed_field
ordering.noncanonical
```

Display wording may improve without changing these code meanings.

For the listener-absence contract, a wrong result or assessment vantage uses
`vantage.mismatch`; a wrong namespace, protocol, address family, bind
semantics, or non-covering port range uses `visibility.scope_mismatch`; and a
missing completed-result basis, nonzero result offered as absence proof,
contradictory positive target listener, or coherent exact-target-port nonzero
result uses
`visibility.insufficient_for_absence`. The evaluator withholds the candidate
under the same conditions that make a persisted candidate invalid.

### 19.3 Package boundaries

Milestone 0 uses internal packages so the diagnostic contract does not
accidentally become a public Go API. The implementation plan may split focused
files further, but it MUST preserve this layout and ownership:

```text
go.mod                         module and Go 1.26/toolchain declarations
schema/report/v1.0.0/schema.json  machine-readable persisted report shape
cmd/routedoc/main.go           non-network CLI entry point
internal/model/                typed IDs, enums, report concepts, validation
internal/schema/v1/            schema 1.0.0 decode and canonical encode
internal/rules/                internal rule interface, registry, evaluation
internal/rules/tls/            certificate hostname-mismatch exemplar
internal/rules/tcp/            connection-refused exemplar
internal/rules/listener/       scoped-absence exemplar
internal/selection/            branch and global finding selection
internal/render/               concise, verbose, and explanation rendering
testdata/reports/v1/           synthetic report inputs and canonical goldens
docs/internal-rules.md         internal rule authoring/versioning guide
```

`internal/model` owns semantic validation. `internal/schema/v1` owns wire
compatibility and MUST NOT duplicate or weaken model validation. Rules do not
render text, renderers do not select findings, and the CLI contains no domain
logic. `internal/model` exposes distinct `EvidenceRun` and `EvaluatedRun` types;
only a canonical, validated `EvaluatedRun` is accepted by the report serializer.
`internal/rules` owns evaluation and re-evaluation; `internal/schema/v1` never
runs rules.

No package in Milestone 0 imports a Caddy, Docker, DNS, raw-socket, or OS process
inspection dependency.

### 19.4 Acceptance criteria

Milestone 0 is complete only when:

- all required fixtures validate or fail with their expected stable code;
- canonical JSON is byte-stable across repeated runs and randomized insertion
  order followed by canonicalization, and matches every byte-level rule in
  section 15.3;
- all human goldens are stable with color disabled;
- every finding has a mandatory producing rule, cites at least one claim, and
  has a complete acyclic path through typed evidence references to admissible
  base evidence;
- every claim has a mandatory producing rule, all evidence-reference kinds and
  targets match, claim references point only backward, and every claim has a
  complete support path to admissible base evidence;
- every claim/finding rule ID is present exactly once in the stored evaluation
  rule list and remains explainable without consulting the current registry;
- re-evaluation replaces all prior claims, findings, evaluation metadata, and
  selections, emits no duplicates, and reproduces deterministic generated IDs;
- every network observation in fixtures has a valid typed vantage;
- every TLS transport result names an existing `SOCKET_ENDPOINT`; a present
  peer reference names an existing `TLS_PEER`, and either cross-kind
  substitution is rejected as `reference.kind_mismatch`;
- TLS timeout, reset, and plaintext-on-HTTPS failures before certificate
  presentation are directly representable with exact endpoint attribution and
  no peer, sentinel fingerprint, placeholder entity, or endpoint-as-peer
  reinterpretation;
- completed TLS with certificate presentation keeps transport, optional peer
  attribution, peer summary, and verification separate; verification failure
  retains sanitized transport/peer evidence and skips HTTP;
- zero matching listeners are representable by a direct successful
  `LISTENER_INVENTORY_RESULT` with count zero and no fabricated positive
  listener entry;
- listener absence is produced and validates only with both a matching
  complete-for-scope assessment and its qualifying zero-count completed-result
  basis; a non-target listener entry is never treated as inventory-completion
  evidence;
- the existing claim `port` value `P` is treated only for containment as
  `[P, P]`; listener results and visibility retain ranges, and the claim wire
  payload gains no `port_start` or `port_end` fields;
- wrong-vantage evidence, wrong listener-scope dimensions, non-covering port
  ranges, nonzero results offered as absence proof, incomplete or
  self-authenticating visibility, contradictory positive target listeners, and
  coherent exact-target-port nonzero results fail to produce and fail to
  validate prohibited absence findings, while a broader nonzero aggregate is
  not treated as locating a target-port listener;
- listener-existence completeness does not require process ownership when the
  scope does not request it or when the qualifying completed result has count
  zero; requested ownership completeness for existing listeners counts
  distinct concrete listener identities rather than observation IDs and
  remains separately evidenced;
- no fixture contains raw Caddy JSON, credentials, headers, secrets, URL query
  values, raw path segments, Caddy matcher values, Docker environment
  variables, raw certificate material, raw socket tables, command output,
  process lists, arbitrary metadata, or collector source payloads;
- exact-version unknown fields are rejected, newer-minor optional fields are
  ignored only in the documented read-only operations with warnings, and
  unknown enums/union kinds are always rejected;
- `go test ./...`, `go vet ./...`, and the repository's fixture validation
  command pass without network access;
- the CLI commands in section 19.1 perform no network or runtime discovery.

## 20. Later milestones

The sequence after Milestone 0 remains:

1. black-box URL client probes;
2. dual-stack and redirect safety hardening;
3. Linux local-origin visibility;
4. Caddy v2 integration;
5. Docker Engine topology correlation;
6. release hardening and naming clearance.

Each milestone requires its own implementation plan and review. Later
integrations do not weaken the model, vantage, visibility, sensitivity, or
causal invariants established in Milestone 0.

## 21. Remaining decisions

No unresolved architectural decision blocks Milestone 0.

Before the client-probe milestone, its implementation plan must pin numerical
defaults for timeouts, body/header limits, address caps, redirect caps, and the
coherence window. Those values do not affect Milestone 0 because fixtures carry
explicit policy and timestamps.

Before public release, the project must complete naming clearance, choose a
license, define the supported OS/architecture release matrix, and establish a
security-reporting process. None blocks the diagnostic-contract milestone.
