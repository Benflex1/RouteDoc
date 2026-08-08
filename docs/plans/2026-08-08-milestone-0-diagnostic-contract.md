# RouteDoctor Milestone 0: Diagnostic Contract Implementation Plan

Date: 2026-08-08

Architecture: `docs/architecture.md`, design 1.1

Report schema: 1.0.0

Scope: Milestone 0 only; synthetic evidence and stored-report workflows; no probes or runtime discovery

## Authority and outcome

`docs/architecture.md` is normative. If this plan and that document differ, the architecture wins. The implementation must stop and request an architecture correction only if a genuine contradiction makes Milestone 0 impossible; it must not resolve such a contradiction by silently changing wire or evaluation semantics.

The milestone is complete when a Go 1.26.5 module can strictly decode, semantically validate, canonically serialize, evaluate, re-evaluate, render, explain, and CLI-process synthetic RouteDoctor 1.0.0 reports; all architecture fixtures, goldens, compatibility cases, and fuzz targets pass without network access. This plan adds no live-probe code.

## Non-goals and dependency policy

Do not add DNS, resolver, TCP, TLS, HTTP, Caddy, Docker, socket/process, namespace, platform-discovery, external-vantage, repair, privileged-helper, monitoring, dashboard, plugin, generic graph, rule-engine, DI, logging-framework, or TUI code/dependencies. The TLS/TCP/listener packages below only inspect typed synthetic observations.

Production code uses the Go standard library only. The sole proposed third-party module is `github.com/santhosh-tekuri/jsonschema/v6 v6.0.2`, imported only by schema conformance tests. It is needed because the standard library does not implement JSON Schema Draft 2020-12; v6 supports Draft 2020-12 and the official test suite, is maintained, and uses Apache-2.0. Keep it out of all non-test imports and therefore out of the CLI dependency graph. Record the purpose, license, maintenance check, and test-only status in a comment beside the schema conformance test and in the eventual dependency-review commit message. No production direct dependency is proposed.

`go.mod` must contain exactly the provisional module identity and toolchain policy:

```go
module routedoc

go 1.26

toolchain go1.26.5
```

The test-only validator is pinned by `require github.com/santhosh-tekuri/jsonschema/v6 v6.0.2`; commit the resulting `go.sum`. Do not downgrade semantics or change the exact toolchain because a developer machine lacks Go 1.26.5.

## Package dependency direction

```text
cmd/routedoc ──> internal/schema/v1 ──> internal/model
      │                   │
      └────────> internal/render ─────> internal/model

internal/rules/{tls,tcp,listener} ──> internal/rules/ruleapi ──> internal/model
                 │                                  ▲
                 ▼                                  │
          internal/rules ───────────────────────────┘
                 │
                 └──> internal/selection ──> internal/model
```

`internal/model` imports no internal package. `internal/selection` owns selection and imports only `model`. The focused `internal/rules/ruleapi` subpackage owns only the internal `Rule`/candidate contracts needed to break Go's parent/subpackage import cycle. The parent `internal/rules` package re-exports aliases for those contracts and owns built-in registry assembly, evaluation, and re-evaluation; it imports `ruleapi`, `selection`, and the three exemplar subpackages. Exemplars import `ruleapi` and `model`, never the parent evaluator and never render. This remains wholly inside the architecture's `internal/rules/` ownership boundary and is not a public extension point. Milestone 0 CLI commands never construct or invoke an evaluator. No public package is created.

## Fixed implementation vocabulary and APIs

Later tasks must use these names exactly.

### IDs, versions, errors, and phase values

In `internal/model/ids.go`, define distinct string-backed types: `RunID`, `VantageID`, `CapabilityID`, `AssertionID`, `EntityID`, `EdgeID`, `BranchID`, `CheckID`, `ExecutionID`, `ObservationID`, `VisibilityID`, `ClaimID`, `FindingID`, `LimitationID`, and `RuleID`. Do not accept plain `string` where one ID domain is expected. Define `SchemaVersion{Major, Minor, Patch uint64}` with strict ASCII decimal parsing (no signs or leading zeroes except `0`) and `String()`.

In `internal/model/validation.go`, define:

```go
type ValidationCode string
type ValidationIssue struct { Code ValidationCode; Pointer, Message string }
type ValidationIssues []ValidationIssue
func (v ValidationIssues) Err() error
func SortValidationIssues(ValidationIssues)
```

Order issues by canonical JSON Pointer byte order, then validation-code byte order, then message byte order. Define constants for every code in architecture section 19.2—no anonymous string codes. Stable code is the machine contract; wording may change. The wire decoder also returns these model-owned issue values so there is one error representation.

The exact architecture-required minimum constant values are:

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

Also define `schema.invalid_json`, `schema.duplicate_field`, `schema.invalid_value`, and `rule.registry_duplicate` for malformed JSON/token values and registry construction failures that the architecture requires handling but does not name in its minimum list. Do not overload an architecture code with a different meaning. These additional codes become stable once schema 1.0.0 ships.

In `internal/model/run.go`, define distinct `EvidenceRun` and `EvaluatedRun` values. `EvaluatedRun` contains `Evidence EvidenceRun`, `Evaluation Evaluation`, `Claims []Claim`, and `Findings []Finding`; flattening is only a wire concern. Define opaque successful-validation wrappers with unexported fields:

```go
type ValidatedEvidenceRun struct{ run EvidenceRun }
type ValidatedEvaluatedRun struct{ run EvaluatedRun }
func ValidateEvidenceRun(EvidenceRun) (ValidatedEvidenceRun, ValidationIssues)
func ValidatePersistedEvaluatedRun(EvaluatedRun) (ValidatedEvaluatedRun, ValidationIssues)
func CanonicalizeAndValidateEvidenceRun(EvidenceRun) (ValidatedEvidenceRun, ValidationIssues)
func CanonicalizeAndValidateEvaluatedRun(EvaluatedRun) (ValidatedEvaluatedRun, ValidationIssues)
func (v ValidatedEvidenceRun) Value() EvidenceRun
func (v ValidatedEvaluatedRun) Value() EvaluatedRun
```

Return defensive values (or document immutable-by-convention slices and never expose a mutating pointer). `ValidatePersistedEvaluatedRun` preserves collection order and reports `ordering.noncanonical`; canonicalize-and-validate sorts only `SET` arrays during construction/evaluation. Neither changes `ORDERED` arrays.

### Closed model shape

Use string-backed closed enums with constants and `Valid()` methods; never use `map[string]any`, open metadata maps, interface values, floats, or arbitrary-key persisted objects. Put families in focused files: `enums.go`, `run.go`, `assertion.go`, `entity.go`, `path.go`, `check.go`, `observation.go`, `visibility.go`, and `derived.go`.

The run-level structs are:

```go
type Producer struct { Name, Version, Build string }
type Target struct { Scheme, Hostname string; EffectivePort uint16; Path PathSummary }
type PathSummary struct { Present, IsRoot bool; SegmentCount uint64; TrailingSlash, QueryPresent bool }
type Goal struct { Kind GoalKind; ExpectationAssertionID *AssertionID }
type RequestedScope struct { Kind ScopeKind } // CLIENT_ONLY or LOCAL_ORIGIN
type Policy struct { CoherenceWindowNS int64 }
type Capability struct { CapabilityID CapabilityID; Kind CapabilityKind; State CapabilityState; ReasonCode string }
type Limitation struct { LimitationID LimitationID; Code LimitationCode; Scope LimitationScope }
```

`ReasonCode` is normalized, bounded, non-sensitive snake case; it is not an OS error. `LimitationScope` is a closed union of `RUN`, `VANTAGE`, `OBSERVATION`, `VISIBILITY`, and `FINDING`, with the matching optional typed target ID. Required top-level collections are non-nil, even when empty. Times are `time.Time` and durations are signed `time.Duration` but validation rejects negative duration fields.

Model the architecture concepts exactly:

- `VantagePoint` has ID, `VantageKind`, `VantageRole`, sanitized display label, a closed `VantageIdentity`, optional parent ID, `VantageEstablishment`, and embedded `[]Limitation`. Identity cases are `ClientNetworkIdentity{Label}`, `HostNamespaceIdentity{NamespaceInode uint64}`, `ContainerNamespaceIdentity{DaemonID, ContainerID string}`, and `UnknownNamespaceIdentity{ReasonCode}`. Kind and identity kind must agree. Limitation IDs remain globally unique; nested records are not duplicated in the top-level limitations collection.
- `OperatorAssertion` has ID, closed `AssertionKind`, closed `AssertionParameters`, `EstablishedAt`, and `AssertionSource`. Payload structs are exactly `LocalOriginParticipation`, `ExpectedPathEdge`, `HTTPExpectation`, `ConfigSourceSelection`, and `PrivateRedirectTransitionAllowed`, with the fields and conditional requirements in section 7.4. Represent the payload as a struct containing a discriminant plus one optional typed case pointer; validate exactly one matching case. No arrays or generic parameters.
- `Entity` has ID, closed `EntityKind`, sanitized `DisplayLabel`, and a matching closed `EntityIdentity`. Cases retain only minimal identities: URL target marker; normalized hostname; IP address using `net/netip.Addr`; socket/upstream endpoint using address plus port and transport; TLS peer fingerprint label; HTTP exchange ordinal; proxy instance/route opaque synthetic ID; listener endpoint; process numeric ID; container runtime/container ID; namespace identity. Never include raw URL, path, query, certificate, headers, environment, config, or credentials.
- `ServicePath` contains nodes, edges, and branches. `PathNode` has `EntityID`. `PathEdge` has ID/from/to/relation/provenance/evidence refs. `Branch` has ID, optional parent ID, semantic `OrderedEdgeIDs`, and goal. Edge support permits only observation/assertion refs; `OPERATOR_ASSERTED` requires an assertion and other provenance requires an observation.
- `CheckDefinition` has ID, `CheckKind`, positive semantic version, closed `CheckInputs`, dependency IDs, required capability IDs, `ExecutionPolicy`, and closed `ExpectedCondition`. Provide cases for each initial observation/check family; inputs identify only typed entities/vantages/assertions, never transient URL data. `CheckExecution` uses the architecture fields and lifecycle/verdict enums.
- `Observation` has ID/kind/subject IDs/optional vantage/time/closed payload/acquisition/source/sensitivity/embedded limitations. Payload cases are `SystemResolutionResult`, `TCPConnectionResult`, `TLSTransportResult`, `TLSPeerSummary`, `CertificateVerificationResult`, `HTTPResult`, `ActiveProxyRouteSummary`, `ConfiguredProxyRouteSummary`, `UpstreamSelectionSummary`, `ListenerInventoryEntry`, `ProcessOwnershipEntry`, `DockerRuntimeSummary`, and `CapabilityPermissionResult`. Each is array-free. Repeated addresses, SAN summary types, failure reasons, routes, upstreams, listeners, and Docker facts are separate observations. Define only allowlisted scalar fields needed by section 9 and fixtures: typed entity/vantage references, family/protocol, normalized result enums, integer timing/status/counts, booleans, UTC times, fingerprint, matcher result, runtime state, and sanitized `PathSummary`. No raw source/error fields.
- `VisibilityAssessment` has ID, `VisibilitySubjectKind`, vantage ID, closed `VisibilityScope`, level, basis observation IDs, embedded limitations, and assessed time. The initial `ListenerVisibilityScope` contains namespace entity ID, protocol, address family, bind semantics, inclusive port start/end, and `ProcessOwnershipRequired`; scope kind and subject kind must match.
- `EvidenceRef` is `{Kind EvidenceKind; ObservationID *ObservationID; ClaimID *ClaimID; VisibilityID *VisibilityID; AssertionID *AssertionID}` in memory, with constructors `ObservationRef`, `ClaimRef`, `VisibilityRef`, and `AssertionRef`. Exactly one typed target matching `Kind` is required. The wire form remains `{kind,id}`.
- `Claim` and `Finding` use the architecture fields. `ClaimParameters` and `MissingEvidenceRequirement` are closed discriminated unions selected by statement/requirement code. Include exact cases needed by the three exemplar rules: hostname verification mismatch; TCP refusal at endpoint/vantage/time; and listener absence for scope. Active/configured route conflict remains base observations in its fixture because Milestone 0 has no fourth rule to derive a conflict claim/finding. `PathPosition` is a struct, never a map. `Evaluation.OrderedRuleIDs` is persisted and sorted unique.

Closed enums must include every token named in sections 6–15 and only the initial observation/check/payload tokens above. Unknown tokens fail in the wire layer with the dedicated enum/union code. Do not invent extra diagnostic rules.

### Closed V1 payload inventory

Freeze the following field inventory in Task 2 so schema/codec/rules do not improvise incompatible shapes. Fields named `*ID` use the matching typed ID, times use `time.Time`, durations serialize from `time.Duration` to integer nanoseconds, IPs use `netip.Addr`, and optional fields use pointers. Every case begins on the wire with its `kind` discriminant.

| Union case | Scalar fields after `kind` |
|---|---|
| `ClientNetworkIdentity` | `label` |
| `HostNamespaceIdentity` | `namespace_inode` |
| `ContainerNamespaceIdentity` | `daemon_id`, `container_id` |
| `UnknownNamespaceIdentity` | `reason_code` |
| `LocalOriginParticipation` | `url_target_entity_id`, `host_vantage_id` |
| `ExpectedPathEdge` | `from_entity_id`, `to_entity_id`, `relation` |
| `HTTPExpectation` | `expectation_kind`, optional `status_min`, optional `status_max`, optional normalized `header_name` |
| `ConfigSourceSelection` | `component_kind`, `source_kind` |
| `PrivateRedirectTransitionAllowed` | `from_address_scope`, `to_address_scope` |
| `SystemResolutionResult` | `hostname_entity_id`, optional `address_entity_id`, `address_family`, `result` |
| `TCPConnectionResult` | `endpoint_entity_id`, `result`, `duration_ns`, `deadline_part_of_expected_condition` |
| `TLSTransportResult` | `peer_entity_id`, `result`, `protocol_version`, `cipher_suite`, `negotiated_alpn`, `sni_sent`, optional `alert_code`, `duration_ns` |
| `TLSPeerSummary` | `peer_entity_id`, `certificate_count`, `leaf_sha256`, `not_before`, `not_after`, `san_type`, `san_count` |
| `CertificateVerificationResult` | `peer_entity_id`, `verified_hostname`, `verification_time`, `trust_source`, `result`, optional `failure_reason` |
| `HTTPResult` | `exchange_entity_id`, `result_kind`, `status_code`, optional `redirect_target_entity_id`, optional `redirect_target` sanitized `Target` |
| `ActiveProxyRouteSummary` | `proxy_route_entity_id`, optional `upstream_entity_id`, `matcher_kind`, `match_result` |
| `ConfiguredProxyRouteSummary` | `proxy_route_entity_id`, optional `upstream_entity_id`, `matcher_kind`, `match_result` |
| `UpstreamSelectionSummary` | `proxy_route_entity_id`, optional `upstream_entity_id`, `result` |
| `ListenerInventoryEntry` | `listener_entity_id`, `namespace_entity_id`, `protocol`, `address_family`, `bind_semantics`, `port` |
| `ProcessOwnershipEntry` | `listener_entity_id`, optional `process_entity_id`, `result` |
| `DockerRuntimeSummary` | `fact_kind`, `container_entity_id`, optional `namespace_entity_id`, optional `endpoint_entity_id`, `runtime_state` |
| `CapabilityPermissionResult` | `capability_id`, `result`, `reason_code` |
| `ListenerVisibilityScope` | `namespace_entity_id`, `protocol`, `address_family`, `bind_semantics`, `port_start`, `port_end`, `process_ownership_required` |
| `HostnameMismatchClaimParameters` | `peer_entity_id`, `hostname`, `verification_time`, `trust_source` |
| `TCPRefusedClaimParameters` | `endpoint_entity_id`, `vantage_id`, `observed_at` |
| `ListenerAbsentClaimParameters` | `namespace_entity_id`, `vantage_id`, `protocol`, `address_family`, `bind_semantics`, `port` |

The associated closed result enums are: address family `IPV4|IPV6`; resolution `RESOLVED|NO_RESULT|FAILED`; TCP `ACCEPTED|REFUSED|TIMED_OUT|FAILED`; TLS transport `COMPLETED|FAILED|TIMED_OUT`; certificate verification `VERIFIED|HOSTNAME_MISMATCH|EXPIRED|NOT_YET_VALID|UNTRUSTED_ISSUER|INVALID_USAGE|VERIFIER_UNAVAILABLE`; HTTP result `RESPONSE|REDIRECT`; matcher result `MATCHED|NOT_MATCHED|UNKNOWN`; upstream selection `SELECTED|AMBIGUOUS|UNAVAILABLE`; ownership `OWNED|UNRESOLVED`; Docker fact `CONTAINER_STATE|NETWORK_MEMBERSHIP|PUBLISHED_PORT`, with runtime state `RUNNING|STOPPED|UNKNOWN`; capability result `AVAILABLE|UNAVAILABLE|DENIED|UNKNOWN`; bind semantics `EXACT|WILDCARD|LOOPBACK`; transport `TCP|UDP`; SAN type `DNS|IP|OTHER`; and trust source `SYSTEM|EXPLICIT|UNKNOWN`. A payload's `failure_reason` uses the certificate-verification enum rather than a free string.

Path relations are closed to `RESOLVES_TO`, `CONNECTS_TO`, `NEGOTIATES_TLS_WITH`, `VERIFIES`, `REQUESTS_HTTP_FROM`, `REDIRECTS_TO`, `ROUTES_TO`, `SELECTS_UPSTREAM`, `LISTENS_ON`, `OWNED_BY`, and `ASSOCIATED_WITH`. Acquisition is `DIRECT_PROBE|ACTIVE_RUNTIME_API|CONFIGURED_INTENT_SOURCE|SYSTEM_INSPECTION|SYNTHETIC_FIXTURE`; source component is `SYSTEM_RESOLVER|TCP_PROBE|TLS_PROBE|CERTIFICATE_VERIFIER|HTTP_PROBE|CADDY_ADAPTER|SOCKET_INSPECTOR|PROCESS_INSPECTOR|DOCKER_ADAPTER|SYNTHETIC_FIXTURE`; sensitivity is `PUBLIC|SANITIZED_DERIVED`. These are report vocabulary only; defining a token does not implement the named future collector.

Check kinds mirror the 13 observation families. Each `CheckInputs` case contains only the subject entity ID, required vantage ID when network-relevant, and optional assertion ID needed to define expected intent. Each matching `ExpectedCondition` case contains a result enum plus only the scalar target needed for comparison (family, port, hostname, status range, matcher result, or capability state). `ExecutionPolicy` is a closed struct of `DeadlineNS`, `DependencyFailureReasonCode`, and `DeadlineIsExpectedCondition`; no command, URL, endpoint source, or arbitrary option is persisted.

Claim statement codes are exactly `TLS_CERTIFICATE_HOSTNAME_MISMATCH`, `TCP_CONNECTION_REFUSED`, and `NO_MATCHING_LISTENER_VISIBLE` for rule-derived Milestone 0 data. Missing-evidence requirement kinds are exactly `OBSERVATION_REQUIRED`, `VISIBILITY_REQUIRED`, and `VANTAGE_REQUIRED`, each carrying only the relevant observation kind, visibility subject/scope, or vantage ID. Finding title codes mirror the three statement codes. Stored fixtures that demonstrate topology, assertions, runtime/configured-intent precedence, PathSummary, or sanitized evidence do so through base records/check rendering unless one of these three rules legitimately applies.

### Rules, selection, codec, and rendering

In `internal/rules/ruleapi/rule.go`, define the contracts; in `internal/rules/rule.go`, expose internal aliases so callers use the parent-package vocabulary:

```go
type Rule interface {
    ID() model.RuleID
    Evaluate(model.ValidatedEvidenceRun) []RuleCandidate
}
type RuleCandidate struct {
    CandidateKey string
    Claims []ClaimTemplate       // topological, rule-local LocalKey references
    Findings []FindingTemplate   // deterministic authored order, claim LocalKeys
}
type Registry struct{ /* immutable sorted rules */ }
func NewRegistry(...Rule) (Registry, model.ValidationIssues)
func DefaultRegistry() Registry // exactly the three exemplar rules, sorted by ID
type Evaluator struct{ registry Registry }
func NewEvaluator(Registry) Evaluator
func (e Evaluator) Evaluate(model.ValidatedEvidenceRun, time.Time) (model.ValidatedEvaluatedRun, model.ValidationIssues)
func (e Evaluator) Reevaluate(model.ValidatedEvaluatedRun, time.Time) (model.ValidatedEvaluatedRun, model.ValidationIssues)
```

`NewRegistry` sorts by `RuleID` and rejects duplicate registry IDs as `rule.registry_duplicate`; it is an internal test/construction helper, not external registration or a plugin API. `rule.unlisted_provenance` remains reserved for a stored claim/finding whose rule is not present exactly once in the evaluation rule list. `DefaultRegistry` is compiled, immutable, and contains exactly the three architecture rules. Candidate keys are sanitized rule-local ordering tokens and may not contain target paths/query/source secrets. Evaluation sorts by rule ID then candidate-key bytes, rejects duplicate keys as `rule.duplicate_candidate_key`, allocates all claim IDs before all finding IDs, rewrites only local references, calls selection, canonicalizes, and fully validates. No goroutines are needed in Milestone 0.

In `internal/selection/selection.go` expose `func Apply(model.EvaluatedRun) (model.EvaluatedRun, model.ValidationIssues)`. It resets all selection fields, selects confirmed blockers independently by branch using section 10, preserves co-primary non-equivalent blockers, and promotes an existing single global finding only under the pre-split/all-branch coverage rule. It never creates, merges, or widens findings.

In `internal/schema/v1/codec.go`:

```go
type Operation uint8 // ReadRender, ReadExplain, ReadValidate, CanonicalJSON, Reevaluate
type DecodedReport struct { Run model.EvaluatedRun; Version model.SchemaVersion; Exact bool; Warnings model.ValidationIssues }
func Decode([]byte, Operation) (DecodedReport, model.ValidationIssues)
func EncodeCanonical(model.ValidatedEvaluatedRun) ([]byte, model.ValidationIssues)
```

`Decode` first parses the top-level version without accepting duplicate JSON member names, then uses closed wire structs/custom union decoders. Exact 1.0.0 rejects unknown fields at every depth. Same-major newer minor ignores unknown members only for `ReadRender`, `ReadExplain`, and `ReadValidate`, emits one warning per ignored JSON Pointer in canonical pointer order, and never stores ignored data. Newer patch accepts only known fields/values for those read-only operations. Unsupported major, missing required fields, unknown enums/unions, and exact-version-required operations use the specified stable codes. Decode preserves all known array order. It does not canonicalize and never runs rules.

`EncodeCanonical` accepts only the opaque validated exact-version wrapper, rechecks exact 1.0.0 and canonical ordering, and refuses invalid/noncanonical input. It writes closed declaration-ordered structs/custom unions with `json.Encoder.SetEscapeHTML(false)`, compact output, valid UTF-8 checks, integer-only fields, UTC `RFC3339Nano`, durations as integer nanoseconds, omitted optionals, required empty arrays, U+2028/U+2029 standard escaping, and exactly one LF. It never uses a map or sorts during serialization.

In `internal/render`, expose:

```go
type Options struct { Verbose bool }
func Report(io.Writer, model.ValidatedEvaluatedRun, Options) error
func Explain(io.Writer, model.ValidatedEvaluatedRun, model.FindingID, Options) error
type Explanation struct { Finding model.Finding; Claims []model.Claim; Evidence []ResolvedEvidence }
func BuildExplanation(model.ValidatedEvaluatedRun, model.FindingID) (Explanation, error)
```

Traversal is stored finding -> cited claims -> backward supporting/contradicting claim refs -> base evidence, with visited claim IDs and deterministic stored/canonical order. It does not consult the rule registry. Concise output groups by vantage and canonical branch, names primaries/check results/skips/limitations, and omits evidence internals. Verbose adds level, rule ID, branch/path position, typed evidence links, contradictions, and limitations. Color is absent in Milestone 0, guaranteeing stable goldens.

## Implementation tasks

Each task starts from the previous task's committed state. Run commands from the repository root. The failure command is run immediately after adding the listed test(s), before production changes; preserve the failure in the implementation notes or commit body. Unless a narrower command is specified, the final verification is `go test ./...` followed by `go vet ./...`. Required test commands must set `GOTOOLCHAIN=go1.26.5` and require no public network after `go mod download` has populated the module cache.

### Task 1: Bootstrap the pinned module and typed primitives

**Files:** create `go.mod`, `internal/model/ids.go`, `internal/model/enums.go`, `internal/model/version.go`, `internal/model/validation.go`, and corresponding `_test.go` files.

**Failing tests first:** table-test every typed-ID prefix/empty/control-character rule, generated claim/finding numeric parsing above and below six digits, schema-version strict parsing, every enum's accepted tokens, invalid UTF-8, and deterministic issue ordering. Include compile-time examples showing typed ID domains are not interchangeable.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/model -run 'Test(ID|GeneratedID|SchemaVersion|Enums|ValidationIssueOrder)'` must initially fail because the types/functions do not exist.

**Implement:** add the exact `go 1.26`/`toolchain go1.26.5` bootstrap and the primitive APIs above. Centralize generated sequence parsing/comparison for later canonical ordering. Define all architecture validation-code constants, including codes not exercised until later tasks. Reject invalid UTF-8 and non-normalized control-bearing scalar labels without trying to normalize Unicode.

**Produces/consumes:** produces typed IDs, closed enum helpers, schema version, generated-ID utilities, and common validation results; consumes standard library only.

**Verify:** targeted test, then `GOTOOLCHAIN=go1.26.5 go test ./...` and `GOTOOLCHAIN=go1.26.5 go vet ./...`.

**Commit:** `build: bootstrap Go 1.26 diagnostic model primitives`

### Task 2: Define base evidence, closed unions, and phase separation

**Files:** create `internal/model/run.go`, `assertion.go`, `entity.go`, `path.go`, `check.go`, `observation.go`, `visibility.go`, `evidence_ref.go`, `model_shape_test.go`, and `sensitive_shape_test.go`.

**Failing tests first:** construct one minimal valid `EvidenceRun` plus table cases for every assertion payload, vantage identity, entity identity, check-input/expected-condition union, observation payload family, visibility scope, and evidence-ref constructor. Reflection tests must fail if persisted structs expose a map, `any`, float, raw URL/path/query/header/config/certificate/environment field, or an array inside any initial union payload.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/model -run 'Test(BaseModelShape|ClosedUnionShape|EvidenceRefConstructors|SensitiveFieldAllowlist|EvidenceAndEvaluatedAreDistinct)'`.

**Implement:** create the complete typed base model described above. Keep `EvidenceRun` free of evaluation/claims/findings/selections. Keep raw transient request data out of all types. Use `net/netip`, `time`, integers, fixed structs, enums, and typed IDs only.

**Produces/consumes:** produces all base-evidence concepts and constructors; consumes Task 1 primitives.

**Verify:** targeted tests plus package/all-repo tests and vet.

**Commit:** `feat(model): define typed base evidence contract`

### Task 3: Define evaluated state and canonical collection transforms

**Files:** create `internal/model/derived.go`, `canonicalize.go`, `canonicalize_test.go`, and `evaluated_shape_test.go`.

**Failing tests first:** cover `Claim`, `Finding`, `Evaluation`, all closed parameters/requirements, and `PathPosition`; randomize every `SET` collection and assert canonical sorting by the complete section 15.3.2 table. Assert parent-before-descendant branch ordering, numeric (not lexical) generated-ID sorting, EvidenceKind enum order, requirement scalar ordering, preservation of branch edge order/rule order/suggested-experiment order, required empty slices remaining non-nil, and idempotence.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/model -run 'Test(EvaluatedModelShape|Canonicalize|CanonicalizeRandomInsertion|OrderedArraysPreserved)'`.

**Implement:** add evaluated types and a copy-returning internal canonicalizer. Detect branch parent cycles/missing parents as validation issues instead of choosing an arbitrary sort. Never sort `ORDERED` arrays. Do not yet grant the validated wrapper; full validation comes in Tasks 4–5.

**Produces/consumes:** produces complete evaluated data shape and deterministic construction ordering; consumes Tasks 1–2.

**Verify:** targeted tests, all tests, vet.

**Commit:** `feat(model): add evaluated state and canonical ordering`

### Task 4: Validate base evidence semantics

**Files:** create `internal/model/validate_evidence.go`, `validate_ids.go`, `validate_references.go`, `validate_execution.go`, `validate_vantage.go`, `validate_visibility.go`, `validate_sensitive.go`, and focused/table-driven tests for each.

**Failing tests first:** cover required fields and required non-nil arrays; duplicate IDs per typed domain; missing/kind-mismatched refs; assertion source/payload/conditional-field validity; edge provenance/support; entity/union discriminator agreement; check dependency references and DAG; every lifecycle/verdict combination including timed-out deadline semantics; network-observation vantage required; subject/vantage/entity existence; exact vantage mismatch; visibility basis/scope/vantage matching; complete-for-scope requirements; UTC/time ordering/duration bounds; `PathSummary` consistency; and sensitive/minimization rejection. Every case asserts exact stable code and pointer, and multi-error cases assert deterministic order.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/model -run 'TestValidateEvidence'`.

**Implement:** implement `ValidateEvidenceRun` and the opaque validated evidence wrapper. Validation is pure and non-mutating. `CanonicalizeAndValidateEvidenceRun` copies, canonicalizes `SET`s, then validates. Network-relevant observation kinds are an explicit allowlist. Visibility completeness checks all listener scope dimensions, not just vantage. Do not treat denied/unavailable/empty inventory as absence.

**Produces/consumes:** produces validated evidence accepted by rules; consumes the complete base model and canonicalizer.

**Verify:** targeted test, `go test ./internal/model`, all tests, vet.

**Commit:** `feat(model): enforce base evidence invariants`

### Task 5: Validate evaluated provenance, justification, IDs, and selection

**Files:** create `internal/model/validate_evaluated.go`, `validate_justification.go`, `validate_selection.go`, and corresponding tests.

**Failing tests first:** table-test mandatory claim/finding rule IDs; evaluation rule list sorted/unique; unlisted provenance; missing finding claims; claim/finding rule mismatch; evidence kind/target mismatch; supporting paths; `OBSERVED` sole-claim support rejection; `SUSPECTED` missing requirements and no confirmed use; forward, cyclic, and cross-rule claim refs; contradictions retained but not treated as support; generated claim/finding sequence with gaps/duplicates/bad padding; branch/path-position validity; canonical array ordering; branch/global selection invariants; and multiple simultaneous errors in stable pointer/code order.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/model -run 'TestValidate(Evaluated|Justification|GeneratedSequence|Selection)'`.

**Implement:** implement iterative, typed claim ancestry traversal directly over claims—no generic graph abstraction. Every finding reaches admissible base evidence only through one or more same-rule claims. Validate loaded cycles even though forward-reference rejection normally suffices. Implement `ValidatePersistedEvaluatedRun` without repair and `CanonicalizeAndValidateEvaluatedRun` with copy/sort then full validation. Grant the opaque wrapper only on zero issues.

**Produces/consumes:** produces the serializer/render/evaluator input contract; consumes Task 4 evidence validation.

**Verify:** targeted test, all model tests, all tests, vet.

**Commit:** `feat(model): validate evaluated justification and provenance`

### Task 6: Specify JSON Schema 1.0.0 and prove structural conformance

**Files:** create `schema/report/v1.0.0/schema.json`, `internal/schema/v1/schema_test.go`, update `go.mod`, and create `go.sum`.

**Failing tests first:** load the schema locally, assert `$schema` is Draft 2020-12, every object has `additionalProperties: false` and exact `x-routedoc-member-order`, every array has `x-routedoc-array-kind`, every `SET` has `x-routedoc-sort-key`, no undeclared array exists, top-level required/member order is exact, integers exclude floats, and all unions/enums are closed. Compile with `jsonschema/v6` using `Draft2020` and validate a minimal hand-authored valid instance plus invalid unknown-field/missing-field/enum/union cases.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/schema/v1 -run TestSchemaContract`.

**Implement:** encode the complete flattened persisted `EvaluatedRun` shape and model union cases. Use local `$defs`/`$ref` only so compilation and tests never fetch remote resources; keep the canonical `$schema` URI as metadata. Pin v6.0.2. Do not call the schema validator in production code.

**Produces/consumes:** produces the normative machine-readable closed wire shape and test-only independent structural oracle; consumes model field/member ordering.

**Verify:** targeted test with an empty network cache after dependencies are downloaded, `go mod verify`, all tests, vet; inspect `go list -deps ./cmd/routedoc` later to ensure validator absence.

**Commit:** `feat(schema): define report schema 1.0.0`

### Task 7: Implement strict and compatible decoding

**Files:** create `internal/schema/v1/wire.go`, `decode.go`, `union_decode.go`, `compat.go`, `decode_test.go`, and `compat_test.go`.

**Failing tests first:** cover exact 1.0.0; duplicate members; unknown fields at top-level and nested exact objects; missing required fields; unsupported major; newer minor with multiple nested ignored fields and canonical JSON Pointer warning order; newer minor allowed only for human render/explain/known validate; newer patch known-only read-only; exact-version-required rejection for canonical JSON/re-evaluation; unknown enum and union values for exact/minor/patch; no coercion/defaulting; and preservation of persisted known-array order. Assert ignored fields do not survive in `DecodedReport`.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/schema/v1 -run 'TestDecode|TestCompatibility'`.

**Implement:** write declaration-ordered wire structs and explicit union decoders. Use a token-level object reader to detect duplicates and capture unknown-member JSON Pointers; do not rely solely on `DisallowUnknownFields`, whose errors are insufficiently typed. Parse numbers with `UseNumber`, require integer lexical forms/ranges, require UTC RFC3339Nano timestamps, reject invalid UTF-8, and convert to model types. `Decode` performs wire compatibility only; tests/CLI then call model validation. Never canonicalize or evaluate.

**Produces/consumes:** produces stored-report decoding plus compatibility warnings; consumes model and schema contract.

**Verify:** targeted tests, package tests, all tests, vet.

**Commit:** `feat(schema): decode strict and compatible reports`

### Task 8: Implement Canonical JSON Profile 1 encoding

**Files:** create `internal/schema/v1/encode.go`, `union_encode.go`, `encode_test.go`, and `testdata/canonical_profile/` cases inside `internal/schema/v1`.

**Failing tests first:** byte-test exact top-level/nested member order, compact UTF-8, `<>&` unescaped, quote/backslash/control escapes, U+2028/U+2029 escaped, other Unicode unnormalized, invalid UTF-8 refusal, integer lexical form including large integers/zero, UTC `RFC3339Nano`, integer-nanosecond durations, omitted optionals, required empty arrays, union `kind` first, exactly one trailing LF, all collection sort keys, and `ORDERED` preservation. Assert direct encoding of invalid, noncanonical, or non-exact runs fails and does not emit bytes.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/schema/v1 -run TestCanonicalEncode`.

**Implement:** convert the opaque model wrapper to fixed-order wire structs; custom-marshal unions without maps. Re-run exact-version and canonical-validation guards before encoding. Configure standard `encoding/json` with HTML escaping disabled and ensure one encoder-produced LF. Serialization must not call canonicalization.

**Produces/consumes:** produces byte-exact archival output; consumes validated canonical exact-version model only.

**Verify:** targeted tests repeated (`-count=100` for deterministic bytes), all tests, vet.

**Commit:** `feat(schema): implement Canonical JSON Profile 1`

### Task 9: Implement branch blockers and conservative global selection

**Files:** create `internal/selection/selection.go` and `selection_test.go`.

**Failing tests first:** suspected exclusion; earliest path position; observed-over-inferred only for same statement/goal; rule/finding tie breaks only for semantic equivalents; co-primary non-equivalent blockers; independent branches; pre-split single global promotion; one existing aggregate finding covering all relevant branches; unexplored branch preventing global; mixed IPv4 success/IPv6 failure; no synthetic merge; idempotent reset/reselection; and validation of malicious stored global selection.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/selection -run 'Test(Branch|Global|Selection)'`.

**Implement:** derive canonical branch ancestry/path position from service path, classify semantic equivalence from finding kind/title/goal/coverage, and mutate only copied `Selection` fields. Return issues for inconsistent candidate paths instead of guessing. This task uses hand-authored evaluated values and has no dependency on the not-yet-created evaluator.

**Produces/consumes:** produces deterministic selection; consumes model only and will be consumed by evaluator, never renderer.

**Verify:** targeted tests with randomized input and `-count=100`, all tests, vet.

**Commit:** `feat(selection): select branch and global primary findings`

### Task 10: Build the deterministic rule registry and evaluator

**Files:** create `internal/rules/ruleapi/rule.go`, `internal/rules/rule.go`, `candidate.go`, `registry.go`, `evaluate.go`, `ids.go`, and package tests with synthetic fake rules. Do not create `default_registry.go` until all three exemplars exist in Task 12.

**Failing tests first:** registry sorting/duplicate IDs; rule consumption of only `ValidatedEvidenceRun`; randomized rule/candidate insertion; candidate-key duplication; claim bundle local forward/cycle/cross-candidate references; finding-to-local-claim resolution; all claims allocated before findings; sequential IDs past 999999 via allocator unit test; required rule provenance overwritten from the executing rule rather than trusted from templates; explicit evaluated time normalized to UTC; selection invocation; and identical output for repeated runs. Include a package-boundary test proving candidates cannot accept evaluated claims/findings and the parent/subpackages form no import cycle.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/rules/... -run 'Test(Registry|Evaluate|Candidate|GeneratedIDs|PackageBoundary)'`.

**Implement:** immutable sorted registry, ruleapi templates with rule-local keys, parent-package aliases, deterministic two-pass allocation, and `Evaluator.Evaluate`. Reject rather than tie-break duplicate candidate keys. Rules run once each and only over base evidence; no result feeds another rule and no fixpoint loop exists. Call Task 9 selection, canonicalize, and fully validate before returning. Tests use fake rules from an external `_test` package; no production placeholder/stub registry is needed.

**Produces/consumes:** produces deterministic derived state and opaque validated evaluated reports; consumes validated base evidence and selection.

**Verify:** targeted tests with `-count=100`, all tests, vet.

**Commit:** `feat(rules): add deterministic registry and evaluation`

### Task 11: Implement TLS and TCP exemplar rules

**Files:** create `internal/rules/tls/hostname_mismatch.go`, `hostname_mismatch_test.go`, `internal/rules/tcp/connection_refused.go`, and `connection_refused_test.go`.

**Failing tests first:** TLS transport success remains distinct from peer and verification; hostname mismatch fires only from completed verifier failure with normalized mismatch reason/hostname/time/trust source; skipped HTTP with `tls_peer_unverified` is retained but not used to claim transport failure; TCP refusal requires exact endpoint and vantage; timeout/error/other-vantage do not become refusal; relevant contradicting success is attached or suppresses/reduces the candidate; stable non-sensitive candidate keys; rule-local topological claims; exact rule IDs and finding provenance; and deterministic multi-branch candidate order.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/rules/tls ./internal/rules/tcp`.

**Implement:** ordinary stateless rule values exposing constructors `NewHostnameMismatch() ruleapi.Rule` and `NewConnectionRefused() ruleapi.Rule`. Emit only evidence-entitled claims/findings from base observations. The TCP wording is strictly “endpoint refused from this vantage at this time,” never listener absence. Candidate keys use typed branch/entity/observation IDs only.

**Produces/consumes:** produces two architecture exemplar rules; consumes rule interface and validated base model.

**Verify:** targeted package tests, evaluator integration test with both rules and randomized evidence ordering, all tests, vet.

**Commit:** `feat(rules): add TLS and TCP exemplar evidence contracts`

### Task 12: Implement scoped listener-absence exemplar rule

**Files:** create `internal/rules/listener/no_matching_listener.go`, `no_matching_listener_test.go`, `internal/rules/default_registry.go`, and `default_registry_test.go`.

**Failing tests first:** complete matching scope fires; empty inventory without visibility does not; partial/unknown/not-applicable visibility does not; denied/unavailable collection does not; namespace/vantage/protocol/family/bind/port/process-ownership scope mismatch does not; wrong-vantage TCP result does not supplement visibility; a positive matching listener contradicts/suppresses absence; exact rule ID, mandatory same-rule claims, visibility reference, and deterministic key. Include complete and partial fixture-shaped cases. Assert `DefaultRegistry()` contains exactly the three exemplar IDs once each in ascending order.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/rules/listener`.

**Implement:** `NewNoMatchingListenerVisible() ruleapi.Rule`; require matching `COMPLETE_FOR_SCOPE`, compatible basis observations in the exact vantage/namespace, and no positive matching listener. The support path includes the visibility assessment and its basis observations; it never infers process state, firewall state, or historical cause. Assemble the immutable parent-package `DefaultRegistry` now that all subpackages exist; no init-time mutable registration is allowed.

**Produces/consumes:** produces the third and final Milestone 0 rule; consumes rules/model. Add no other rules.

**Verify:** targeted package/evaluator integration tests, all tests, vet.

**Commit:** `feat(rules): add scoped listener absence exemplar`

### Task 13: Implement exact-version re-evaluation replacement

**Files:** update `internal/rules/evaluate.go`; create `internal/rules/reevaluate_test.go`; add test helpers for the exact three-rule registry.

**Failing tests first:** the decode-plus-model-validation integration rejects a fully invalid stored report before it can obtain the wrapper accepted by `Reevaluate`; exact version required; base evidence is extracted unchanged; prior evaluation time/rule list/claims/findings/selections are discarded; evaluation occurs exactly once with explicit clock; removed-rule findings disappear; no duplicate derived records; sequential IDs restart at one; current registry list replaces stored list; and repeated re-evaluation with same evidence/registry/clock is byte-equivalent after canonical encode.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/rules -run TestReevaluate`.

**Implement:** `Evaluator.Reevaluate` accepts only a fully validated exact-version wrapper, copies its `Evidence`, and delegates once to `Evaluate`. It never appends or consults stored derived state. Compatibility-projected reports cannot obtain the exact wrapper for this operation.

**Produces/consumes:** produces recomputational replacement semantics; consumes model validation, evaluator, and canonical encoder in integration tests only.

**Verify:** targeted tests with `-count=100`, all tests, vet.

**Commit:** `feat(rules): replace derived state during re-evaluation`

### Task 14: Render concise/verbose reports and stored explanations

**Files:** create `internal/render/report.go`, `concise.go`, `verbose.go`, `explain.go`, `format.go`, and focused tests/goldens under `internal/render/testdata/`.

**Failing tests first:** deterministic vantage/branch grouping; global primary omission when unjustified; co-primary branch findings; levels and exact rule IDs in verbose output; TLS transport/peer/verification/HTTP separation; skips and limitations; no “root cause” overclaim; stored graph traversal including multi-claim ancestry, contradiction, observation/visibility/assertion leaves; no current-registry lookup; missing finding error; cycle defense even though validated input normally prevents it; PathSummary-only target display; and redaction tokens absent. Run goldens with color disabled (there is no color path).

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/render`.

**Implement:** pure deterministic formatting over validated stored reports. `BuildExplanation` walks only typed stored references, de-duplicates visited claims/evidence, and orders output canonically. Concise and verbose share semantic labels. `Explain(..., Options{Verbose:false})` is human concise explanation; JSON explanation will be handled by the CLI with a closed response struct and canonical compact JSON rules, not by serializing a hidden graph.

**Produces/consumes:** produces human rendering/explanation; consumes validated model only, not selection or rules.

**Verify:** targeted goldens twice and with `-count=20`, all tests, vet.

**Commit:** `feat(render): add deterministic report and explanation output`

### Task 15: Add the exact non-network CLI surface

**Files:** create `cmd/routedoc/main.go`, `app.go`, `flags.go`, `json_output.go`, `version.go`, and CLI tests under `cmd/routedoc/`.

**Failing tests first:** exact forms `render REPORT [--verbose] [--json]`, `explain REPORT FINDING_ID [--json]`, `validate REPORT [--json]`, and `version [--json]`; reject URL-like positional invocations, `diagnose`, unknown commands/flags, and invalid arity; stdin is not implicitly read; render/explain/validate decode and validate stored reports without evaluating; `render --json` exact-only canonical report bytes; newer-minor human render/explain/validate warning behavior; explain JSON closed deterministic response; validate JSON stable ordered issues/warnings; version human/JSON fields; usage/data/internal exit behavior; and a source/import test prohibiting network/runtime packages and rule evaluation from CLI code.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./cmd/routedoc`.

**Implement:** keep `main.go` to exit-code dispatch. `app.go` accepts injected args/stdin/stdout/stderr/file reader for tests, orchestrates schema decode -> model persisted validation -> render, and never constructs an evaluator. `validate` never rewrites/fixes ordering. JSON diagnostics use closed structs, stable member/issue order, compact UTF-8, HTML escaping off, and one LF. Report compatibility warnings deterministically on the command's diagnostic channel/JSON response. Embed producer/version/build values via constants or link flags without runtime discovery.

**Produces/consumes:** produces the only Milestone 0 executable; consumes schema/model/render. No CLI domain logic and no public Go API.

**Verify:** CLI tests, build binary, run all four commands against seed fixtures, `go list -deps ./cmd/routedoc` audit for forbidden/test-only packages, all tests, vet.

**Commit:** `feat(cli): add stored-report diagnostic commands`

### Task 16: Add the complete synthetic fixture and golden contract suite

**Files:** create fixture directories/files under `testdata/reports/v1/`; create `internal/schema/v1/fixtures_test.go`, `internal/render/fixtures_test.go`, `cmd/routedoc/fixtures_test.go`, and `testdata/reports/v1/README.md` manifest.

Use immutable case directories. Every exact valid case has canonical `report.json`, `concise.txt`, `verbose.txt`, and each applicable `explain-<finding-id>.txt`; every invalid case has its original `report.json`, human `validate.txt`, and machine `validate.json`; compatibility cases additionally have the applicable render/explain/validate human and JSON warning goldens. Thus every fixture has both a JSON golden and at least one human-output golden. Add these named cases (a case may cover multiple requirements, but the manifest maps every requirement explicitly):

1. `valid-multibranch-no-global`
2. `ipv4-success-ipv6-refused-partial`
3. `tls-hostname-mismatch-http-skipped`
4. `caddy-active-over-configured-intent`
5. `upstream-refused-wrong-vantage`
6. `listener-absent-complete-scope`
7. `listener-absent-partial-scope`
8. `two-proxy-upstreams-no-global`
9. `operator-asserted-expected-path`
10. `multiclaim-acyclic`
11. `claim-forward-invalid`
12. `claim-cycle-invalid`
13. `provenance-missing-invalid`
14. `provenance-recoverable-stored`
15. `reevaluation-replacement-before` plus `reevaluation-replacement-after`
16. `path-summary-only`
17. `sensitive-derived-only`
18. `exact-unknown-field-invalid`
19. `newer-minor-ignored-fields`
20. `newer-patch-known-readonly`
21. `unknown-enum-invalid`
22. `unknown-union-invalid`
23. `missing-required-field-invalid`
24. `unsupported-major-invalid`

**Failing tests first:** manifest completeness test; every valid report strict-decodes, validates, conforms to Draft 2020-12, round-trips byte-identically, renders to both human goldens, and yields expected explanations; every invalid report yields the exact ordered code/pointer list; newer-minor warning list/order and exact-operation failure; newer-patch read-only/exact-operation behavior; randomized construction canonicalizes to the same report; rule evaluation from each applicable base evidence fixture reproduces stored derived state; and re-evaluation reproduces the `after` golden without duplicates.

Add explicit semantic assertions: all network observations have vantages; TLS peer evidence survives mismatch and HTTP is skipped; active Caddy-derived state outranks but does not erase configured intent; wrong-vantage/partial visibility produces no prohibited finding; no global primary for independent branches; assertion refs remain assertions; `PathSummary` persists; every rule provenance is stored/explainable even when absent from a supplied registry. Scan all fixture/golden bytes for forbidden raw user info, query values, raw path segments/redirect paths, Caddy matcher values/raw JSON, credentials, any HTTP header/value, Docker environment, secrets, PEM/DER/certificate chains, and captured production data.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/schema/v1 ./internal/render ./internal/rules ./cmd/routedoc -run Fixture`.

**Implement:** create sanitized hand-authored synthetic data and byte-exact goldens. Do not “update goldens” blindly; review diffs. Golden corrections after release add a new fixture and document replacement in the manifest. Add a repository fixture command as `GOTOOLCHAIN=go1.26.5 go test ./... -run 'Fixture|Golden|SchemaContract'`; do not add a task runner dependency merely for this alias.

**Produces/consumes:** produces the full acceptance corpus; consumes every prior subsystem and the test-only schema validator.

**Verify:** fixture command, `go test ./... -count=2`, vet, test-only dependency audit, and an offline run with a prefilled module cache.

**Commit:** `test: add Milestone 0 report and rendering contract fixtures`

### Task 17: Add fuzzing, internal-rule documentation, and final acceptance enforcement

**Files:** create/update `internal/schema/v1/fuzz_test.go`, `internal/model/fuzz_ids_test.go`, `internal/model/fuzz_justification_test.go`, `docs/internal-rules.md`, `README.md`, and optionally `.github/workflows/ci.yml` only if repository CI convention is established during implementation; otherwise document commands without inventing deployment infrastructure.

**Failing tests first:** seed decoder fuzzing with every valid/invalid fixture and assert no panic, bounded deterministic issues, and valid results only after semantic validation; fuzz typed ID/reference substitutions and assert no cross-domain acceptance/panic; fuzz claim order/reference graphs and assert forward/cycle/cross-rule rejection without recursion exhaustion. Add a documentation contract test that checks the guide names all three rule IDs and required invariants.

**Observe failure:** `GOTOOLCHAIN=go1.26.5 go test ./internal/schema/v1 ./internal/model -run 'FuzzSeed|InternalRuleGuide'` before adding the fuzz targets/guide, then smoke each target with `-fuzztime=10s`.

**Implement:** bounded fuzz targets with seed corpus and no network. `docs/internal-rules.md` explains ID form/versioning triggers, static internal registration, base-evidence-only input, candidate-key uniqueness/sensitivity ban, topological local claims, mandatory rule provenance, evidence/visibility/vantage contracts, deterministic ordering/IDs, same-rule finding citations, testing/golden requirements, and explicitly states “this is not a plugin API.” Update README status/commands to Milestone 0 without advertising live diagnosis.

**Produces/consumes:** produces robustness tests and contributor contract; consumes completed APIs and fixtures.

**Verify:**

```text
GOTOOLCHAIN=go1.26.5 go test ./...
GOTOOLCHAIN=go1.26.5 go vet ./...
GOTOOLCHAIN=go1.26.5 go test ./... -run 'Fixture|Golden|SchemaContract'
GOTOOLCHAIN=go1.26.5 go test ./internal/schema/v1 -run=^$ -fuzz=FuzzDecode -fuzztime=30s
GOTOOLCHAIN=go1.26.5 go test ./internal/model -run=^$ -fuzz=FuzzIDReferences -fuzztime=30s
GOTOOLCHAIN=go1.26.5 go test ./internal/model -run=^$ -fuzz=FuzzJustification -fuzztime=30s
GOTOOLCHAIN=go1.26.5 go list -deps ./cmd/routedoc
git diff --check
```

The dependency audit must show no JSON Schema validator in the CLI graph and no forbidden integration packages. Run CLI smoke tests for every command against exact, newer-minor, and invalid fixtures with outbound network disabled.

**Commit:** `docs: finalize Milestone 0 rule and verification contract`

## Expected implementation sequence

Implement Tasks 1–17 in order. Tasks 1–5 freeze the in-memory contract and semantic validator before wire code. Tasks 6–8 independently fix the schema and canonical protocol. Tasks 9–13 add deterministic evaluation, selection, the three—and only three—rules, and recomputation. Tasks 14–15 add read-only presentation/orchestration. Tasks 16–17 close the cross-package fixture, golden, compatibility, fuzz, dependency, and documentation acceptance loop.

Do not parallelize changes that alter shared model or schema vocabulary. Once Task 8 lands, any wire-shape change must update model, schema annotations, codec, conformance tests, and goldens together and be reviewed as a protocol change.

## Final acceptance review checklist

Before declaring Milestone 0 implemented, the implementation agent and reviewer must check each item explicitly:

- **Coverage:** all 24 fixture cases and the manifest map every section 19.1 deliverable and 19.4 acceptance criterion; every stable code in 19.2 has at least one direct unit/fixture assertion.
- **Architecture boundary:** repository search finds no probe, network call, Caddy/Docker client, socket/process inspection, namespace operation, runtime discovery, repair, plugin, or future-milestone integration. CLI has exactly four command families and never evaluates.
- **Type consistency:** later packages use the exact wrappers, rule interfaces, codec operations, renderer APIs, IDs, and issue representation defined above; no alternate error or generic union representation appears.
- **Determinism:** registry/candidates/issues/SET collections/generated IDs/branch selection are explicitly ordered; ORDERED arrays are preserved; no map iteration or goroutine completion affects output; repeat/randomized tests pass.
- **Canonical protocol:** object order and schema annotations agree; exact escaping/numbers/time/durations/omission/empty arrays/LF behavior is byte-tested; persisted noncanonical input is rejected, not repaired; serializer accepts only exact canonical validated evaluated state.
- **Evaluation:** rules see base evidence only; all candidates are sorted before allocation; claims precede findings; all derived state and selections are replaced on re-evaluation with an explicit clock; no append/fixpoint behavior exists.
- **Justification/provenance:** every claim/finding has its rule in the stored ordered list; finding claims are same-rule and nonempty; claim refs are typed, backward, same-rule, resolvable, and acyclic to admissible base evidence; suspected support cannot establish confirmed findings.
- **Selection:** earliest blockers are branch-local; co-primary semantics are preserved; no global is synthesized/merged from branch findings; incomplete/unexplored branches prevent improper global coverage.
- **Compatibility:** exact unknown fields reject; newer-minor ignored warnings are exhaustive and pointer-sorted only for read-only operations; newer patch known-only read behavior works; exact-only operations reject both; unknown enum/union and missing required fields never degrade/default.
- **Security/minimization:** model reflection and fixture scanning prove no raw URL path/query/user info, redirect path, headers, credentials, cookies, Caddy source/matcher value, Docker environment, secret, OS error, or raw certificate material can persist. Candidate keys and IDs contain none of these values.
- **Dependency/toolchain:** `go 1.26`, `toolchain go1.26.5`, production standard-library-only, validator pinned test-only with Apache-2.0/maintenance record, and no validator in CLI dependency graph.
- **Verification:** all unit/table/integration/schema/fixture/golden/fuzz-smoke tests, `go vet`, dependency audit, `git diff --check`, and offline CLI smoke tests pass.

No architecture issue currently blocks implementation. The principal implementation risks are keeping three representations synchronized (typed model, schema, and ordered wire structs), distinguishing persisted-order validation from construction canonicalization, enforcing newer-minor warning completeness without retaining ignored data, and preventing subtle vantage/visibility or branch-coverage overclaims. Treat any proposed shortcut in those areas as a contract change requiring review, not an implementation convenience.
