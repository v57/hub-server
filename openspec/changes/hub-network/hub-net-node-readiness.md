# hub-net-node production-readiness audit

Audit date: 2026-07-28  
Decision: **GO after required release workflow gates pass**

## Scope

Review covered source, tests, race detector, vet, native and Linux cross-builds,
container build/runtime, packaging, protocol behavior, WebSocket framing,
ticket trust, resource limits, release automation, and existing Linux
integration evidence.

## Verified

- `go test -race ./...`, `go vet ./...`, native build, and Linux amd64
  cross-build pass.
- Published Go modules resolve without local replacements.
- Direct Docker and Compose builds pass from their documented directories.
- Versioned package and SHA-256 verification pass.
- Strict OpenSpec validation passes.
- Existing Ubuntu acceptance records successful packaging, two-NAT,
  NAT-matrix, WireGuard direct-path, and packet-capture no-relay tests.

## Resolved release blockers

### HN-408: WebSocket frame safety

Frame lengths remain `uint64` until configured-cap and platform-allocation
checks pass. Client masking, reserved bits, opcodes, control fragmentation, and
control payload size are enforced. Raw-frame, process-survival, race, and fuzz
tests cover malformed input.

### HN-409: Observed endpoint delivery

Authenticated UDP probe records source mapping on node UDP port. Node binds
mapping to Hub key, ticket, and agent; matched peer receives it as typed
`observedEndpoint`, distinct from declared candidates. Linux NAT tests configure
WireGuard only from delivered mapping. Observation state is globally/per-source
bounded and expiry-swept.

### HN-410: Open-public abuse boundary

Policy explicitly treats self-contained ticket signature as integrity rather
than Sybil resistance. TCP admission, HTTP parsing, silent upgraded sockets,
replay cache, and UDP observation cache have identity-independent bounds.

### HN-411: Release enforcement

Tagged release publication depends on hosted build/vet/race/security/load/fuzz
and container health/SIGTERM verification plus self-hosted privileged two-NAT
and NAT-matrix jobs. Artifacts receive SHA-256 manifests and GitHub build
provenance.

### HN-412: Ticket replay

Fully validated tickets are atomically consumed in bounded in-memory replay
cache. Entries expire with tickets; reconnect requires fresh ticket. Restart
and replicated-deployment boundaries are documented.

## Go decision

Local implementation verification passes. Production publication remains
conditional on all tag-triggered HN-411 workflow dependencies succeeding,
including privileged Linux NAT acceptance and vulnerability scan.
