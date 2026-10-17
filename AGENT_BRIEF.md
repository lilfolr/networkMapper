# Agent brief: mapr discovery milestone (M1)

## How to use this file

1. Put `CLAUDE.md` in the repo root first. It holds the conventions and non-negotiables, and the agent must read it before anything else.
2. Give the agent the **Master prompt** once at the start of a session.
3. Then give it **one phase at a time**. Review the diff and run the checks between phases. Do not hand over all phases at once; the agent will cut corners to finish.
4. Review Phase 1 (schema) harder than any other. Everything else depends on it, and it is the one thing that is expensive to change later.

Checks to run after every phase:

```
cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test
```

---

## Master prompt

```
You are building `mapr`, a local Rust CLI that maps how a request flows from a
hostname, IP or CIDR to its destination across cloud providers.

Read CLAUDE.md and AGENT_BRIEF.md fully before writing code. CLAUDE.md is
authoritative for conventions, security rules, scope and the output contract.
AGENT_BRIEF.md defines the data model and the phases.

Working rules:
- Work on one phase at a time. Do not start the next phase until told.
- Before coding a phase, write a short plan: files you will create or change,
  the public types and traits you will add, and how you will test them. Then
  implement it.
- Do not rely on memory for crate APIs. Add each dependency with `cargo add`,
  then read its docs or source for the exact version you got. Several crates
  here (hickory-resolver, rustls, aws-sdk) have changed APIs across versions.
- No live network calls in tests. Use trait-based fakes and recorded fixtures.
- Every phase ends with: fmt, clippy (warnings denied) and tests all passing,
  and a short summary of what changed, what you decided, and anything you were
  unsure about.
- Stop and ask before: changing the schema after Phase 1, adding a dependency
  not named in CLAUDE.md, adding a command or flag not in the brief, or
  resolving an ambiguity that affects the output format.
- Never use em-dashes in code, comments, docs or commit messages.

Out of scope for this milestone: credentials of any kind, AWS or other provider
APIs, `trace`, `probe`, `reverse`, `diff`, `mcp`, Azure, GCP.
```

---

## Data model (shared definitions)

These are the intended shapes. The agent may adjust field names for idiom, but not the concepts. Any change to the concepts needs approval.

```rust
// mapr-schema

pub struct Trace {
    pub schema_version: String,          // "1"
    pub target: Target,                  // { input, kind }
    pub generated_at: DateTime<Utc>,
    pub stages_run: Vec<String>,
    pub nodes: Vec<Node>,                // sorted by id
    pub edges: Vec<Edge>,                // sorted by (from, to, relation)
    pub gaps: Vec<Gap>,
    pub paths: Vec<Vec<NodeId>>,         // derived, never hand-built
}

pub struct Node {
    pub id: NodeId,                      // derived from canonical key
    pub kind: NodeKind,
    pub provider: Option<Provider>,
    pub service: Option<String>,         // free-form: "cloudfront", "ec2", ...
    pub name: String,
    pub identifier: Option<String>,      // real provider ID (ARN etc.) when known
    pub attributes: serde_json::Map<String, serde_json::Value>,
    pub evidence: Vec<Evidence>,
}

#[non_exhaustive]
pub enum NodeKind { Hostname, Ip, Cidr, Cdn, LoadBalancer, Gateway, Compute, Unknown }

pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub relation: Relation,              // Cname, ResolvesTo, ServedBy, RoutesTo
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
}

#[non_exhaustive]
pub enum Confidence { Verified, Observed, Inferred }

pub struct Evidence {
    pub source: EvidenceSource,          // DnsQuery, IpRange, ReverseDns, Tls, Http, ...
    pub detail: String,
    pub observed_at: DateTime<Utc>,
    pub attributes: serde_json::Map<String, serde_json::Value>, // resolver, ttl, range sync token, ...
}

pub struct Gap {
    pub at: Option<NodeId>,
    pub reason: GapReason,
    pub detail: String,
    pub needs: Option<Needs>,            // provider + permissions, for later phases
}

#[non_exhaustive]
pub enum GapReason {
    NoCredentials, AccessDenied, UnsupportedService, Timeout, BudgetExceeded,
    Nxdomain, DnsFailure, NetworkError, NoRangeData, Private,
}
```

### Node identity (get this right)

`NodeId` is a stable string built from a canonical key, for example `hostname:api.example.com` or `ip:203.0.113.5`. Canonicalization rules:

- **Hostnames:** lowercase, strip the trailing dot, convert IDNA to ASCII (punycode).
- **IPv4:** dotted quad. **IPv6:** compressed, lowercase. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) normalizes to the IPv4 form.
- **CIDR:** normalized to its network address (`10.0.0.5/8` becomes `10.0.0.0/8`).
- **Provider resources:** the real identifier (ARN, resource ID) once known.

The same real-world thing reached by two routes must always produce the same `NodeId`.

### Engine and stage interface

```rust
// mapr-core

pub enum Seed { Hostname(String), Ip(IpAddr), Cidr(IpNet) }

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier { Offline, Network, Credentialed }

#[async_trait]
pub trait Stage: Send + Sync {
    fn name(&self) -> &'static str;
    fn tier(&self) -> Tier;
    fn accepts(&self, node: &Node) -> bool;
    async fn run(&self, cx: &Context, node: &Node) -> StageOutput;
}

pub struct StageOutput {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub evidence: Vec<(NodeId, Evidence)>,
    pub gaps: Vec<Gap>,
}
```

`Context` holds trait objects (DNS client, HTTP client, TLS inspector, clock, range database, config), never concrete types, so the whole engine runs against fakes.

A stage never mutates the graph. It returns additions and the engine merges them.

---

## Phase 0: Workspace scaffold

**Goal:** an empty, building, lint-clean workspace that matches CLAUDE.md.

**Tasks**
- Create the three-crate workspace (`mapr-schema`, `mapr-core`, `mapr-cli`) with the module layout from CLAUDE.md.
- Add `rust-toolchain.toml`, workspace-level lint config (`forbid(unsafe_code)`, deny `clippy::unwrap_used` and `clippy::expect_used`), `rustfmt.toml` if needed, `.gitignore`.
- Add a minimal CI workflow running fmt, clippy and tests.
- `mapr --version` works and exits 0.

**Done when**
- The three checks pass on a clean clone.
- No business logic exists yet.

---

## Phase 1: Schema crate

**Goal:** the public output types, with a generated and contract-tested JSON Schema.

**Tasks**
- Implement the types from "Data model" in `mapr-schema`, with `serde` (snake_case) and `schemars`.
- Implement `NodeId` construction and all canonicalization rules, as pure functions.
- Implement path derivation: given nodes and edges plus a start node, produce the list of root-to-leaf paths. Handle branching (multiple A records) and be safe against cycles.
- Generate the JSON Schema, commit it, and add a test that fails if the committed file differs from the generated one.
- Add a `schema_version` constant.

**Done when**
- Table-driven tests cover canonicalization (mixed-case hostnames, trailing dot, punycode, IPv4-mapped IPv6, non-normalized CIDR).
- Path derivation tests cover a linear chain, a branch, a diamond (two routes to one node) and a cycle.
- Serialized output is deterministic (sorted) and round-trips.
- The crate has no I/O and no async dependencies.

---

## Phase 2: Engine with a fake stage

**Goal:** the frontier loop, proven before any real stage exists.

**Tasks**
- Implement `Seed` parsing (hostname vs IP vs CIDR, with clear errors for invalid input) producing the starting node.
- Implement the engine: frontier queue, visited set, merge of `StageOutput` into the graph, dedupe by `NodeId`, evidence merging on duplicate nodes.
- Budgets: max depth, max nodes, global timeout. Hitting one emits a `BudgetExceeded` gap and returns a partial trace instead of an error.
- Tier gating: the engine takes the maximum allowed `Tier` and skips stages above it. `--offline` caps at `Offline`.
- Run all stages that accept a node concurrently, with a semaphore bounding total parallelism.
- A stage that panics or returns an error becomes a gap and never aborts the trace.
- Output is sorted and deterministic.

**Done when**
- Tests with fake stages cover: expansion to a fixed point, dedupe when two routes reach one node, loop protection, each budget limit, tier gating, stage failure isolation, and deterministic output across repeated runs.
- No real stage or network code exists in this phase.

---

## Phase 3: Classify stage

**Goal:** the first real stage, pure and offline.

**Tasks**
- Implement `classify`: for `Ip` nodes, detect private (RFC 1918), CGNAT (100.64.0.0/10), loopback, link-local, multicast, unspecified, documentation ranges (RFC 5737, RFC 3849) and IPv6 ULA.
- Private or non-routable addresses get a `Private` gap and stop external stages from running on them.
- For `Cidr` nodes, classify the range as a whole.

**Done when**
- Tests cover every category and boundary (first and last address of each range) for both IPv4 and IPv6.
- Public addresses pass through untouched.

---

## Phase 4: DNS stage

**Goal:** `discover api.example.com` produces a real CNAME-and-IP graph.

**Tasks**
- Define a `DnsClient` trait (lookup a name and record type, returning answers with TTLs and the response code, plus which resolver answered). Implement it with `hickory-resolver`, and a fake for tests.
- Implement the CNAME walk yourself: for each name, query `CNAME` explicitly, follow it, and record each hop as an `Edge` (relation `Cname`, confidence `Observed`) with TTL and resolver in the evidence. Do not let the library flatten the chain. Verify how the library behaves and say what you found.
- At the terminal name, query `A` and `AAAA` separately and emit `Ip` nodes with `ResolvesTo` edges.
- Loop detection and a max chain depth (16 default).
- NXDOMAIN at the end of a chain: keep the chain, add an `Nxdomain` gap at the last node. This is a finding, not an error.
- NODATA, SERVFAIL and timeouts become gaps (`DnsFailure`, `Timeout`) without aborting.
- `--resolver <addr>` support through the client config. Always record the resolver used.
- Apex domains: no special handling, but do not assume a missing CNAME means an A record is the whole story (add a comment explaining why).

**Done when**
- Fake-resolver tests cover: no CNAME, a single CNAME, a long chain, a CNAME loop, a dangling CNAME, multiple A and AAAA records, NODATA, SERVFAIL, timeout.
- A fixture-based test runs the engine end to end from a hostname seed and snapshots the resulting trace with `insta`.

---

## Phase 5: IP range stage

**Goal:** IPs start being classified by provider, service and region. This is the highest-value stage.

**Tasks**
- Define a `RangeSource` trait and an in-memory `RangeDatabase` supporting longest-prefix match over IPv4 and IPv6.
- Parse AWS `ip-ranges.json` (`prefixes` and `ipv6_prefixes`; fields `ip_prefix`/`ipv6_prefix`, `region`, `service`, `network_border_group`) and Cloudflare's published lists. Keep each provider's parser separate and behind the trait so adding GCP, Azure and Fastly later is mechanical.
- Handle overlaps. An AWS IP commonly matches `AMAZON` and `EC2` and sometimes `CLOUDFRONT` or `GLOBALACCELERATOR`. Collect all matching entries, pick the most specific service for the node (specific services win over `EC2`, which wins over `AMAZON`), and keep every match in the evidence.
- Mark anycast and shared-edge services (CloudFront, Global Accelerator, Cloudflare) with an attribute such as `shared_edge: true`, so renderers and later stages know the IP does not identify an origin.
- Emit a classified node (`Cdn`, `Compute`, and so on) linked from the `Ip` node by a `ServedBy` edge, confidence `Observed`.
- Loading: fetch from the official URLs only in the `Network` tier, cache on disk (platform cache directory, 24 hour default TTL), and store the sync token or publish date in the evidence. Under `--offline`, use the cache; if there is none, emit a `NoRangeData` gap.
- Ship a small, sanitized range fixture for tests.

**Done when**
- Tests cover: longest-prefix selection, overlapping services, IPv6, an IP in no range, anycast marking, cache hit, cache expiry, offline with and without cache.
- The engine run from a hostname fixture now produces nodes classified as provider, service and region.

---

## Phase 6: `discover` command and renderers

**Goal:** a usable CLI.

**Tasks**
- Implement `mapr discover <target>` wiring seed parsing, engine, and renderers.
- Global flags shared through one flattened clap `Args` struct: `--output`, `--no-prompt`, `--offline`, `--redact`, `--timeout`, `--verbose`, `--quiet`, `--save`, plus `--resolver`.
- Renderers as pure functions in `mapr-core/render`: `json` (the schema), `text` (readable path view with confidence markers and a gaps section) and `mermaid`. Defer `dot` and `html` unless trivial.
- `--output` defaults to text on a TTY and JSON when piped.
- JSON to stdout, progress and warnings to stderr.
- Exit codes as an enum in one place: 0 complete, 1 error, 2 partial (any gaps present).
- `--redact`: mask IP addresses and account-like identifiers consistently in every output format, including verbose logs and errors.
- `mapr schema` prints the JSON Schema.

**Done when**
- Snapshot tests cover each renderer against saved traces.
- CLI tests (for example `assert_cmd`) cover exit codes, TTY vs piped default, `--save`, `--redact` and invalid input errors.
- No network in tests. The engine is run with fakes injected at construction.

---

## Phase 7: Reverse DNS

**Tasks**
- A stage accepting `Ip` nodes: PTR lookup, then forward-confirm (resolve the returned name and check that it includes the original IP).
- Confirmed PTR: attach as evidence with `Observed`. Unconfirmed: attach with `Inferred` and say so in the detail. Never create a trusted `Hostname` node from an unconfirmed PTR.
- Skip for `Private` nodes.

**Done when**
- Fake-resolver tests cover confirmed, unconfirmed, missing and failing PTR.

---

## Phase 8: TLS inspection

**Tasks**
- A `TlsInspector` trait with a `rustls`-based implementation and a fake. Accept `Ip` nodes (and `Hostname` nodes that resolved to them).
- Perform up to two handshakes on port 443: without SNI, and with SNI when a hostname is known on the path.
- Capture only metadata: protocol version, ALPN, certificate chain, subject, issuer, SANs, validity dates. Parse with `x509-parser`.
- Use a deliberately permissive certificate verifier for inspection. Put it in one clearly named module, document that it is for inspection only, never reuse it for any real request, and add a test asserting that module is the only place it is referenced.
- Strict timeouts. Connection refused or timeout becomes a gap, not an error.
- Emit evidence on the `Ip` node, and add SAN hostnames as attributes (not as trusted nodes).

**Done when**
- Tests run against generated test certificates, with no real network.
- Expired, mismatched-SAN and self-signed certificates are all handled and recorded.

---

## Phase 9: HTTP fingerprinting and the signature engine

**Tasks**
- An `HttpProbe` trait with a `reqwest` implementation and a fake. Send `HEAD`, then `GET /` if needed, to the IP with and without a `Host` header. Do not follow redirects automatically; record the redirect chain instead.
- Capture status, a header allowlist (`Server`, `Via`, `X-Cache`, `X-Amz-Cf-Id`, `X-Amz-Cf-Pop`, `CF-Ray`, `X-Served-By`, and similar), and a small default-error-page signature. Never store response bodies beyond what signature matching needs, and never log them.
- Build the signature engine: signatures are **data**, embedded from a TOML or JSON file via `include_str!`, each with matchers (header present or equal, header regex, certificate issuer or SAN pattern) and a result (provider, service, node kind, confidence). Adding a signature must not require code changes.
- The engine combines DNS, range, TLS and HTTP evidence into classified nodes and never raises confidence above `Observed` from fingerprints alone.

**Done when**
- Tests cover each signature against fixture responses, conflicting signals (range says EC2, headers say CloudFront), and no-match.
- A signature file validation test fails on malformed entries.

---

## After M1

Review the real output of `mapr discover` against a handful of known hostnames you own before writing the next brief. The `trace` brief (credential discovery, permission manifests, Route 53, CloudFront, ELB, ECS stages, gap handling) should be written once the `discover` output has proven the schema, because anything learned here may change it.
