# RouteDoctor

RouteDoctor is a planned, deterministic diagnostic CLI for answering:

> Why can’t I reach this self-hosted service, and where along the expected
> service path does observed behavior first diverge?

Milestone 1 adds a bounded black-box client probe. The URL shorthand performs
system resolution, one ordinary hostname attempt, and at most one pinned IPv4
and one pinned IPv6 attempt from the current client network. It records typed
TCP, TLS, certificate-verification, and bounded HTTP GET evidence.

The available command surface is:

```text
routedoc render REPORT.json [--verbose] [--json]
routedoc explain REPORT.json FINDING_ID [--json]
routedoc validate REPORT.json [--json]
routedoc version [--json]
routedoc URL [--verbose] [--json]
```

The URL command rejects credentials, sends no cookies or authentication, uses
the direct path even when proxy environment variables are configured, and
does not follow redirects. Redirect responses are observed with a sanitized
target only. Each strategy owns one connection and one GET; a run can issue
at most three GETs. Response headers and bodies are bounded and transient.

Exit status for the URL command is `0` when a relevant branch has an HTTP response, `1`
when existing rule-produced blockers cover every relevant branch, `2` when
the evidence is incomplete or indeterminate, `3` for invalid invocation or
URL, and `4` for an internal RouteDoctor failure.

The authoritative V1 design is [docs/architecture.md](docs/architecture.md).
It defines RouteDoctor's scope, evidence semantics, privilege boundaries,
report model, testing requirements, and Milestone 0 contract.

`RouteDoctor` is a provisional working name pending proper naming clearance.
