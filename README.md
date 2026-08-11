# RouteDoctor

RouteDoctor is a small CLI for diagnosing why an HTTP/HTTPS service is unreachable or behaving unexpectedly.

## Quick start

```bash
routedoc https://example.com
```

RouteDoctor checks the client-side path from the machine where it runs:

```text
system resolution → TCP → TLS/certificate → HTTP
```

The probe is bounded and does not claim exhaustive Internet-path analysis.

### What it can currently tell you

- whether the hostname resolves from this machine;
- whether a TCP endpoint accepts, refuses, or times out;
- TLS handshake and certificate-verification problems;
- HTTP reachability and status;
- redirects and their sanitized destinations; and
- IPv4/IPv6 differences among the bounded attempts it actually makes.

RouteDoctor does not follow redirects. It records a safe, minimized redirect destination instead. Proxy environment settings are detected and ignored; the probe uses a direct path.

## Installation

### Download a release binary

Download the file for your operating system and architecture from the [GitHub Releases](https://github.com/Benflex1/RouteDoc/releases) page. For example, on Linux:

```bash
VERSION=0.1.0
curl -LO "https://github.com/Benflex1/RouteDoc/releases/download/v${VERSION}/routedoc_${VERSION}_linux_amd64"
chmod +x "routedoc_${VERSION}_linux_amd64"
sudo install "routedoc_${VERSION}_linux_amd64" /usr/local/bin/routedoc
```

### Install from a checkout

From the repository root:

```bash
go install ./cmd/routedoc
```

Ensure your Go binary directory is on `PATH`.

### Build from source

```bash
go build -o routedoc ./cmd/routedoc
```

## Usage

The URL diagnosis command is the primary interface:

```text
routedoc URL [--verbose] [--json]
```

For saved reports:

```text
routedoc render REPORT.json [--verbose] [--json]
routedoc explain REPORT.json FINDING_ID [--json]
routedoc validate REPORT.json [--json]
routedoc version [--json]
```

Use `--verbose` for additional evidence context. Use `--json` when another tool will consume the result.

## Exit status and codes

- `0` — a relevant branch has an HTTP response;
- `1` — rule-produced blockers cover every relevant branch;
- `2` — evidence is incomplete or indeterminate;
- `3` — invalid invocation or URL; and
- `4` — internal RouteDoctor failure.

## Current scope

RouteDoctor diagnoses from the machine where it is run. It intentionally is not traceroute, packet capture, a vulnerability scanner, or an exhaustive network-analysis framework.

Contributors who need the detailed model and design constraints can read [docs/architecture.md](docs/architecture.md).

## License

RouteDoctor is licensed under the [MIT License](LICENSE).
