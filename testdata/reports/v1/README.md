# Milestone 0 report fixture manifest

These are immutable, synthetic, sanitized report-contract fixtures. No case
contains production captures, raw URLs, request paths, query values, headers,
credentials, Caddy source, Docker environment, or certificate material.

| Case | Contract coverage |
|---|---|
| `valid-multibranch-no-global` | valid report shape; no unjustified global |
| `ipv4-success-ipv6-refused-partial` | dual-family branch separation |
| `tls-hostname-mismatch-http-skipped` | TLS transport/peer/verification and skipped HTTP |
| `caddy-active-over-configured-intent` | active/configured provenance distinction |
| `upstream-refused-wrong-vantage` | exact-vantage refusal |
| `listener-absent-complete-scope` | complete listener visibility |
| `listener-absent-partial-scope` | partial visibility cannot prove absence |
| `two-proxy-upstreams-no-global` | independent upstream branches |
| `operator-asserted-expected-path` | assertion remains assertion |
| `multiclaim-acyclic` | multi-claim ancestry |
| `claim-forward-invalid` | forward claim rejection |
| `claim-cycle-invalid` | cyclic claim rejection |
| `provenance-missing-invalid` | missing rule provenance |
| `provenance-recoverable-stored` | stored provenance remains explainable without registry |
| `reevaluation-replacement-before` / `after` | recomputational replacement and IDs |
| `path-summary-only` | sanitized PathSummary |
| `sensitive-derived-only` | minimized typed derived evidence |
| `exact-unknown-field-invalid` | strict exact decoding |
| `newer-minor-ignored-fields` | read-only compatibility warnings |
| `newer-patch-known-readonly` | known newer-patch read-only compatibility |
| `unknown-enum-invalid` | closed enum rejection |
| `unknown-union-invalid` | closed union rejection |
| `missing-required-field-invalid` | required-field rejection |
| `unsupported-major-invalid` | unsupported-major rejection |

Exact valid cases contain `report.json`, `concise.txt`, and `verbose.txt`.
Invalid cases retain the original report plus human and machine validation
outputs. Compatibility cases retain their read-only warning outputs. The
fixture tests perform the repository-wide contract command:

```text
GOTOOLCHAIN=go1.26.5 go test ./... -run 'Fixture|Golden|SchemaContract'
```
