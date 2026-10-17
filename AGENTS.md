## Project

`mapr` (working name) is a local CLI that takes a hostname, CNAME, IP or CIDR and maps how a request flows to its destination across cloud providers. It starts with credential-free discovery (DNS, IP range matching, CDN/LB fingerprinting) and deepens the trace using the developer's own provider credentials, which never leave their machine.

The real goals are diagnosis ("why is this request slow or failing?") and change-impact analysis ("what points at this resource?"). Drawing maps is the commodity feature, not the product.

## Stack

- Rust (stable toolchain, pinned in `rust-toolchain.toml`), edition 2021 or later
- CLI: `clap` (derive API)
- Async runtime: `tokio`
- HTTP and TLS: `reqwest` with `rustls` (no OpenSSL, so static musl builds stay easy)
- DNS: `hickory-resolver`
- TLS certificate inspection: `rustls` plus `x509-parser`
- CIDR and IP range matching: `ipnet`
- AWS: official `aws-sdk-rust`, per-service crates only, with `aws-config` for the standard credential chain
- Serialization: `serde` and `serde_json`
- JSON Schema generation: `schemars`
- Errors: `thiserror` in library crates, `anyhow` in the binary only
- Tests: built-in test harness, `insta` for snapshots, `cargo-nextest` optional
- Distribution: `cargo install` first, then prebuilt static binaries via GitHub releases (`cargo-dist`)

Change any of the above only with a stated reason.

## Commands

```
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo run -- discover example.com    # run the CLI from source
```

Run `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test` before declaring work done.

## Repository layout

Cargo workspace with three crates:

```
crates/
  mapr-schema/    output types, confidence and evidence enums, schema version,
                  JSON Schema generation. No I/O. Depended on by everything.
  mapr-core/      trace engine, stages, renderers, credential discovery
    src/
      engine/       graph building, path derivation, gap handling
      stages/
        dns/          CNAME chain, A/AAAA resolution
        fingerprint/  IP range matching, headers, TLS cert inspection
        aws/          provider API stages (cloudfront, elbv2, ecs, apigw, ...)
      render/       text, mermaid, dot, html renderers (pure functions of a trace)
      auth/         profile detection and permission manifests (no storage)
  mapr-cli/       the binary: clap definitions, flag handling, output wiring only
tests/
  fixtures/       recorded provider API responses and DNS answers
```

Rules for the layout:

- `mapr-cli` contains no business logic. It parses input, calls `mapr-core`, and hands the result to a renderer.
- `render` takes a trace and returns a `String`. No network, no credentials, no side effects.
- `mapr-schema` stays free of I/O and heavy dependencies so other tools and agents can depend on the types alone.
- Each provider lives in its own module under `stages/` and implements the shared `Stage` trait. Adding a provider must not require touching other providers.

## Command surface

v1 scope: `discover`, `trace` (AWS only), `probe`, `schema`, `render`.

Deferred until the JSON schema has survived real use: `reverse`, `diff`, `mcp`. Azure and GCP are out of scope for v1. `coverage` must say so honestly.

| Command | Question it answers |
|---|---|
| `trace <target>` | What is the full path, using available credentials? |
| `reverse <resource>` | What points at this resource? (deferred) |
| `diff <a> <b>` | What changed between two traces? (deferred) |
| `auth status` | Which providers can I reach, and with what access? |
| `auth <set/rm>` | sets auth creds |
| `render <trace.json>` | Turn a saved trace into text, mermaid, dot or html |
| `mcp` | Run as an MCP server (deferred) |

If a new command cannot be phrased as a question the user is asking, do not add it.

### Global flags (must behave identically on every command)

```
--output json|text|mermaid|dot|html   default: text on a TTY, json when piped
--no-prompt                           never ask interactively
--offline                             no network beyond what is explicitly needed
--redact                              mask account IDs, ARNs and IPs in output
--timeout <dur>
--verbose / --quiet
--save <file>
```

Define these once in a shared clap `Args` struct flattened into every subcommand, so they cannot drift.

### Exit codes

```
0  complete trace
1  error
2  partial trace (gaps present)
3  diff found changes (with --exit-code)
4  probe reached target but a hop reported failure
```

Never change an exit code's meaning once released. Scripts depend on them. Keep them as a single enum in one place.

## Output contract

The JSON output is the product. Treat it as a public API.

- A trace is a graph: `nodes`, `edges`, `gaps`, and a derived `paths` array. `paths` is computed from the graph and never hand-built.
- Every edge carries `confidence`: `verified` (confirmed via provider API), `observed` (seen on the wire: DNS, headers, TLS) or `inferred` (heuristic). Never upgrade confidence without new evidence.
- Every node and edge carries structured `evidence` (source, detail, observed_at). If you cannot cite evidence, you cannot add the node.
- `gaps` is first class. When the trace stops, record where and why (`no_credentials`, `access_denied`, `unsupported_service`, `timeout`). Never silently stop and never guess past a gap.
- `kind` is a small closed enum plus `unknown`. `service` is a free-form string. `attributes` is an open `serde_json::Map` per node.
- Public enums in `mapr-schema` are `#[non_exhaustive]` and serialize in `snake_case`, so adding a variant is not a breaking change for consumers.
- `identifier` is the real provider ID (ARN, resource ID) wherever one exists. Do not generate synthetic IDs for things that have real ones, because `diff` depends on stable identifiers.
- `schema_version` is present from day one. Any breaking change bumps it. Additive changes do not.
- The JSON Schema is generated from the Rust types with `schemars`. Never hand-edit it. A test must fail if the committed schema differs from the generated one.
- A map that is confidently wrong is worse than no map. When unsure, emit a gap or lower the confidence.

## Credentials and security (non-negotiable)

- Never store, cache, log or transmit credentials. Use the standard provider chains only (`aws-config` default chain for AWS, `az login`, gcloud ADC for later providers).
- Interactive prompting means "which profile do you want to use?", never "paste a key".
- Every provider call must be read-only. Do not add any API call that creates, modifies or deletes anything. List the exact IAM actions each stage needs in its permission manifest, since `auth needs` is generated from these.
- No telemetry and no network calls to anything other than the target and the provider APIs the user authorized. Published IP range files may be fetched, and must be cacheable for `--offline`.
- Redaction (`--redact`) applies at the render layer to all output formats, including errors and verbose logs.
- Never put credentials, tokens, or full response bodies in fixtures, logs or error messages. Do not derive `Debug` on types that hold secrets, or implement it manually to redact.

## Output and UX conventions

- Machine output (JSON) goes to stdout. Progress, warnings and prompts go to stderr, so pipes and agents parse cleanly.
- `--no-prompt` is mandatory behavior for CI and agents. With it set, missing access becomes a gap, never a blocking prompt.
- Default to the human-readable renderer on a TTY (`std::io::IsTerminal`) and JSON when piped.
- Error messages say what failed, why, and what the user can do next.
- Do not use em-dashes in any user-facing text, docs, comments or commit messages. Use commas, colons or parentheses.

## Code conventions

- `#![forbid(unsafe_code)]` in every crate.
- No `unwrap()` or `expect()` in non-test code. Enforce with `clippy::unwrap_used` and `clippy::expect_used` set to deny at the workspace level.
- Library crates return typed errors (`thiserror`). Only `mapr-cli` uses `anyhow`, at the top level.
- Prefer small pure functions. Side effects (DNS, HTTP, provider SDK calls) live behind trait boundaries so they can be faked in tests.
- Stages are independent and composable: a stage takes the current graph and a context, and returns additions and gaps. A stage never mutates the graph in place.
- Parse all external data (DNS answers, headers, certificates, provider responses) defensively at the boundary into the schema types. Provider APIs return surprises, so treat missing or unexpected fields as a gap, not a panic.
- Handle partial failure per stage. One failing stage must not abort the trace.
- Respect rate limits and pagination on every provider call. Set explicit timeouts on every network operation.
- Keep dependencies minimal and audit new ones (`cargo deny`, `cargo audit`). Justify any new dependency, especially anything that pulls in native libraries or slows builds noticeably.
- Watch compile times. AWS SDK crates are large, so enable only the service crates actually used, and keep provider code behind Cargo features if build time becomes a problem.

## Testing

- Unit-test every stage against recorded fixtures in `tests/fixtures/`. No live cloud calls in the default test run.
- Use the SDK's replay or mocking utilities for AWS calls, and a fake resolver behind a trait for DNS.
- Snapshot-test renderers against saved traces with `insta`.
- Contract-test the JSON output against the generated JSON Schema.
- Every bug fix gets a regression fixture.
- Fixtures must be sanitized: fake account IDs, fake domains (`example.com`), RFC 5737 IP ranges, no real ARNs.
- Live integration tests, if any, are opt-in behind an env var or `#[ignore]` and never run in CI by default.

## Scope discipline

The risk in this project is the long tail of services and a wide maintenance surface. Hold the line:

- AWS only for v1, and only the path hostname, DNS, CDN, load balancer, target.
- Prefer an honest `unsupported_service` gap over a half-working integration.
- Keep `coverage` output accurate. Update it in the same change that adds or alters service support.
- Do not add a feature to make a demo look better if it lowers accuracy.
- Do not build hosting, accounts or shared state. If a team feature is needed, discuss it first because it conflicts with the local-credentials promise.

## When making changes

- Read the relevant schema types and the `Stage` trait before editing.
- Adding a service: add the stage, its permission manifest, fixtures, a `coverage` entry and tests together.
- Changing the output schema: update the Rust types, regenerate the JSON Schema, bump `schema_version` if breaking, and update renderers, snapshots and fixtures.
- Ask before adding a new top-level command, a new global flag, or a new dependency.
