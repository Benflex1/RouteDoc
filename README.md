# RouteDoctor

RouteDoctor is a planned, deterministic diagnostic CLI for answering:

> Why can’t I reach this self-hosted service, and where along the expected
> service path does observed behavior first diverge?

Milestone 0 implements the frozen diagnostic contract: typed synthetic
evidence, strict schema decoding, canonical JSON, deterministic evaluation
and re-evaluation, selection, rendering, explanations, and the stored-report
CLI. It contains no production probes, collectors, integrations, or runtime
discovery.

The available command surface is:

```text
routedoc render REPORT.json [--verbose] [--json]
routedoc explain REPORT.json FINDING_ID [--json]
routedoc validate REPORT.json [--json]
routedoc version [--json]
```

Milestone 0 does not diagnose URLs or perform live network/runtime access.

The authoritative V1 design is [docs/architecture.md](docs/architecture.md).
It defines RouteDoctor's scope, evidence semantics, privilege boundaries,
report model, testing requirements, and Milestone 0 contract.

`RouteDoctor` is a provisional working name pending proper naming clearance.
