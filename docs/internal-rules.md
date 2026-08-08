# Internal rule contract

Milestone 0 rules are statically registered, deterministic internal packages.
The only exemplar rule IDs are:

- `tls.certificate_hostname_mismatch/v1`
- `tcp.connection_refused/v1`
- `listener.no_matching_listener_visible/v1`

Rule IDs use a namespaced name plus `/vN` version. A rule is added to the
static registry and tested as part of the repository; there is no runtime
registration or discovery path.

Rules consume validated base evidence only. They do not consume claims,
findings, selections, or another rule's derived output. Every candidate key is
deterministic, unique within its rule, and contains no URL, path, query,
credential, header, certificate, environment, or other sensitive value.

Claims are emitted in deterministic local topological order. A claim may cite
only backward, same-rule claims and typed base evidence references. Every
claim and finding carries mandatory rule provenance. A finding cites nonempty
claims from that same producing rule, and its support path must reach
admissible base evidence. Network-shaped evidence must retain its exact
vantage; visibility is not interchangeable with a different namespace or
vantage, and incomplete visibility cannot establish absence.

The registry, candidate allocation, collection ordering, generated IDs, and
selection results are deterministic. Re-evaluation replaces all derived
claims, findings, evaluation metadata, and selections using an explicit clock.
Tests cover invalid references, provenance, candidate-key sensitivity,
vantage/visibility scope, repeated evaluation, and byte-stable fixtures and
goldens. This is an internal contributor contract; this is not a plugin API.
