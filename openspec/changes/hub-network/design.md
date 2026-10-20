## Context

Hub authenticates WebSocket connections with Ed25519 service identities, registers RPC paths, applies hosting/calling permissions in `hub-pro`. Services like `hub-s3-local` expose TCP endpoints, but URLs contain LAN hostnames — fail outside LAN.

Hub Network adds private IP overlay without changing RPC data path. `hub-pro` stays authoritative control plane. Go `hub-net` agent owns WireGuard interface, exposes approved local ports. Self-hosted or public Go `hub-net-node` helps agents discover endpoints, perform NAT traversal — not on application data path.

System spans Go, Bun services, Swift service library, Apple app, multiple operating systems, manual launches. Cannot depend on Launcher ownership or require WireGuard in every service binary.

Existing `channel-go` provides Channel request/response, streams, subscriptions, cancellation, reconnect, client/server transports, TypeScript interoperability tests. Not yet Hub service SDK — has platform/module-release work. `hub-service-go` will implement, conformance-test on top before Go network execs built.

### Trust boundaries

- **Hub service identity** owns RPC APIs, published network shares.
- **Network profile identity** belongs to `hub-net` agent or app-scoped Hub Network profile — principal authorized to open overlay connections.
- **WireGuard key** identifies tunnel interface, bound to network profile identity by short-lived Hub-signed grant.
- `hub-pro` trusted to authenticate identities, evaluate permissions, sign grants.
- `hub-net` trusted only for local machine/profile it controls — MUST enforce received grants.
- `hub-net-node` not trusted with application data or authorization — observes coordination metadata, public endpoints.
- Service process not assumed launched by `hub-launcher`.

Transparent IP routing cannot reliably identify originating process on every platform. Network access granted to network profile identity, not automatically to each Hub RPC service sharing machine. App-scoped VPN profiles, OS network isolation provide narrower principal where supported.

## Goals / Non-Goals

**Goals:**

- Authenticated service publishes local TCP/UDP port through local `hub-net` agent.
- Authorized network profiles on same Hub use normal sockets, URLs to reach published ports.
- Prefer direct WireGuard peer connections, fail explicitly when no direct path.
- Keep registration, access policy, discovery, revocation, signed grants in `hub-pro`.
- Reuse Hub groups, keep network permissions distinct from RPC permissions.
- Go, Bun, Swift publication APIs behaviorally equivalent.
- Provide reusable Go Hub service SDK with behavior equivalent to Bun/Swift SDKs before building Go agent/node.
- Make `hub-net` installable manually or through Launcher/Store.
- Support stable S3 presigned URLs when local/remote S3 endpoint published into overlay.
- Permit future node capabilities including separately specified `gateway` role without changing project identity or initial protocol envelope.

**Non-Goals:**

- Relaying application traffic through `hub-net-node` in initial release.
- Full-tunnel internet routing, exit nodes, subnet routing, public ingress in this change.
- Making overlay URLs work without active Hub Network profile.
- Identifying arbitrary originating processes inside device-wide VPN.
- Reimplementing WireGuard or carrying file payloads through Hub RPC.
- Propagating network shares across merged Hubs in initial release.
- Requiring `hub-launcher` for identity, publication, connectivity.

## Decisions

### 1. `hub-pro` is authoritative network control plane

Services register network-share metadata through authenticated Hub connection. Hub binds registration to connection identity, keeps live provider record ephemeral. Access policy persisted separately using stable resource identifier derived from owning service key, publisher-supplied stable share name.

Follows existing service registry, permission model — works for manually launched services.

**Alternative:** Make `hub-net` authoritative. Duplicates Hub permissions, prevents consistent management from Hub App.

### 2. Publication requires local-agent attestation

Publishing share is two-sided:

1. Service discovers local agent through well-known Unix socket, named pipe, platform IPC endpoint.
2. Agent sends nonce.
3. Service proves Hub identity by signing nonce.
4. Agent verifies proof, verifies requested target is local, returns short-lived signed attestation binding service key, agent key, share name, protocol, local target.
5. Service includes attestation in Hub share registration.
6. Hub verifies attestation belongs to connected authorized agent before advertising share.

Prevents remote service from claiming port on unrelated agent — doesn't depend on Launcher.

**Alternative:** Trust service-provided `agentId`. Permits remote share claims, accidental exposure of unrelated local ports.

### 3. Network profiles are access principals

Caller in connection grant is authenticated `hub-net` network profile, not inferred RPC service process. "Public" means available to all authenticated network profiles joined to Hub. Group, explicit-key policies apply to network profile keys.

Hub App can use existing Hub identity for app-scoped profile when platform key sharing permits, or explicitly bind dedicated profile key to app identity.

**Alternative:** Attribute every socket to Hub service identity. Not portable for ordinary applications — requires per-process VPN engines or network namespaces.

### 4. API and network permissions remain separate

Each stable network resource has access policy:

- `hub`: all authenticated network profiles on Hub
- `group`: profiles assigned to one named Hub group
- `keys`: explicit set of profile keys
- `private`: owner, Hub owners
- `disabled`: not connectable

Hub groups reused as membership collections. Granting RPC path never grants network resource, vice versa. Owners manage all network policies.

### 5. Go is implementation language for agent and node

`hub-net`, `hub-net-node` SHALL be Go. Share small versioned Go package for Hub Network wire models, grants, tickets, candidates, test fixtures.

Go selected because existing `channel-go` removes main Hub protocol barrier, Go has mature WireGuard control/userspace options, both networking processes benefit from single executable, native UDP support, shared concurrency/runtime.

Apple app-scoped packet tunnels stay Swift with WireGuardKit — execute inside Apple Network Extension. Conform to same wire contracts rather than embedding Go agent.

**Alternative:** Bun/TypeScript for agent/node. Matches `hub-pro` but requires more native routing, TUN, DNS, UDP, platform bridging — wouldn't reuse `channel-go`.

**Alternative:** Rust. Produces efficient binaries but requires new Channel, Hub service stack before network work.

### 6. `channel-go` stabilized before `hub-service-go`

Existing library becomes versioned Go module with canonical repository module path. Before use must pass unit tests, race detection, TypeScript interoperability tests, supported-platform builds; use one documented Go toolchain version; measure binary impact of Sonic versus `encoding/json`.

### 7. `hub-service-go` is reusable prerequisite

`hub-service-go` SHALL be standalone Go SDK layered on `channel-go`, not code hidden inside `hub-net`. Implements persistent Hub identity, authentication headers, profiles, API registration/settings, post/stream/send/values behavior, reconnect registration, network-share publication with local-agent proof, attestation.

`hub-net` consumes `hub-service-go` to register itself, expose control APIs, communicate with `hub-pro`. `hub-net-node` uses shared Hub Network protocol, cryptographic packages — uses `hub-service-go` only if approved runtime design requires Hub RPC.

**Alternative:** Implement minimum Hub client inside `hub-net`. Duplicates SDK behavior, prevents reuse by other Go services, makes conformance harder.

### 8. WireGuard is data plane, one implementation per profile

`hub-net` configures platform WireGuard implementation, routes only overlay prefixes. Ordinary services use normal TCP/UDP — no WireGuard dependency. Apple platforms place WireGuardKit in packet-tunnel extension rather than each embedded service.

Per-resource port enforcement performed by `hub-net`, where available OS firewall rules. WireGuard `AllowedIPs` limits peer addresses — not treated as port authorization system.

### 9. Hubs issue short-lived connection grants

Grant binds:

- protocol version, grant identifier
- authoritative Hub key, network identifier
- caller network profile key, WireGuard public key
- target agent key, WireGuard public key
- stable resource ID, live provider ID
- protocol, overlay destination address, destination port
- issue, expiry, optional revocation generation

Both agents validate Hub signature, all bound fields. Grants short-lived; permission changes prevent renewal, increment resource generation so agents can terminate active flows when immediate revocation requested.

Hub signing uses purpose-separated key or signature domain — authentication tokens cannot replay as network grants.

### 10. `hub-net-node` is untrusted rendezvous service

Agents connect to node using Hub-signed, short-lived rendezvous ticket. Node:

- reports observed UDP endpoints
- exchanges candidates, encrypted coordination messages
- rate-limits sessions
- advertises supported node roles, protocol versions

Initial role set contains only `rendezvous`. Application packets sent directly between agents after WireGuard handshake. If candidate checks, handshake fail before timeout, connection fails — no relay fallback.

Node may accept tickets from self-hosted Hubs without prior registration by validating ticket against Hub key in signed envelope. Agents, not node, establish authorization trust in configured Hub.

**Alternative:** Route packets through node on failure. Creates bandwidth cost, abuse exposure, materially different privacy model.

### 11. Overlay addressing scoped by Hub and agent

Each Hub defines random persistent network identifier, allocates unique overlay addresses to network agents. Live providers receive stable resource names, resolve to selected provider agent address.

Canonical DNS suffix, encoding versioned. Names include stable share label plus collision-resistant owner, Hub components; display names never used as sole identity. Local resolver in `hub-net` answers only reserved Hub Network suffix, forwards/bypasses all other DNS per platform behavior.

Service-instance selection through Hub discovery before connection authorization. Caller can request specific provider; otherwise Hub applies deterministic available-provider policy.

### 12. Protocols versioned independently

Hub control API, local agent IPC, node rendezvous protocol, grant envelope, DNS naming format each carry version. Implementations reject unsupported major versions, ignore unknown optional fields in compatible minor version.

Go `hub-service-go`, Bun `hub-service`, Swift `HubService` expose matching share models, access modes. Platform-specific details behind respective implementations.

### 13. Integrations consume common model

- `hub-s3-local` publishes dynamically selected S3 TCP port, uses returned overlay authority when constructing S3 client, presigned URLs.
- `hub-s3` publishes only endpoints it actually hosts or deliberately gateways; remote AWS/Wasabi public endpoints remain public — not automatically tunneled.
- `hub-launcher` optionally installs, supervises `hub-net` — provides no required trust.
- `hub-store` lists `hub-net` as server installation.
- Hub App manages shares, policies — can later host app-scoped network profile. Full-tunnel gateway UI, behavior deferred.

### 14. Cross-project ownership

- `hub-pro`: registry, persistence, permission evaluation, streams, address allocation, grant signing.
- `channel-go`: compatible Go Channel runtime, transports.
- `hub-service-go`: reusable Go Hub identity, registration, RPC, streaming, share-publication SDK.
- `hub-net`: local IPC, key storage, WireGuard lifecycle, DNS, routing, enforcement, candidate checks.
- `hub-net-node`: rendezvous protocol, abuse controls.
- `hub-service-go` / `hub-service` / `HubService`: publication API, local attestation exchange, matching data models.
- Hub App: administration, platform profile integration.
- Launcher / Store: optional distribution, lifecycle.
- S3 services: endpoint publication, URL integration.

## Risks / Trade-offs

- **[Symmetric NAT or restrictive firewall prevents direct path]** → Candidate attempts time out with clear diagnostic; no traffic relay silently introduced.
- **[Device-wide profile grants all routed local processes same network identity]** → Document boundary, support app-scoped profiles where available, recommend OS isolation for stronger separation.
- **[Malicious local process attempts to expose another localhost port]** → Require signed service proof, local-agent attestation, loopback/local target validation, explicit publication in Hub.
- **[Rendezvous node observes membership timing, public endpoints]** → Minimize retained metadata, use short-lived opaque session identifiers, encrypt peer coordination payloads, document remaining metadata.
- **[Permission revocation races with cached grants]** → Keep grants short-lived, propagate generation updates to connected agents for immediate termination where configured.
- **[Stable DNS authorities make S3 signatures sensitive to naming changes]** → Version, freeze canonical authority format before S3 migration.
- **[Large peer meshes increase WireGuard peer state]** → Configure peers on demand, remove idle peer state after bounded lifetime.
- **[Cross-platform routing behavior differs]** → Keep common conformance suite, define platform-specific adapters rather than weakening shared semantics.
- **[`channel-go` not verified in current workspace]** → Pin Go toolchain, run unit/race/interop tests, repair platform gaps, release before `hub-service-go`.
- **[Go networking dependencies increase agent binary]** → Measure stripped builds, compare Sonic with `encoding/json`, use kernel WireGuard where available, keep Go code out of ordinary service binaries.
- **[Public rendezvous service abused for signaling]** → Require valid Hub tickets, impose rate/size limits, never accept/forward application payloads.
- **[Self-contained tickets permit unlimited self-issued Hub and agent identities]** → Treat signature as integrity and binding, not operator trust or Sybil resistance; explicitly select trusted-Hub admission or open-public mode, and enforce global/per-source pre-auth resource bounds in either mode.
- **[Valid rendezvous ticket replay opens repeated sessions]** → Validate all cryptographic and temporal fields before atomically consuming `TicketID` in a bounded in-memory cache until `ExpiresAt`; require fresh ticket for reconnect. Document restart boundary; use shared replay state only for replicated or strict cross-restart deployments.
- **[Malformed WebSocket length crashes public node]** → Validate unsigned frame length against configured cap and platform allocation range before conversion/allocation; fuzz raw frame parser and require process-survival release test.
- **[Observed endpoint retained but omitted from wire response]** → Include typed observed address and port in shared protocol separately from declared candidates; pin with cross-project fixtures and real NAT acceptance.
- **[Hub compromise authorizes network access]** → Separate signing domains, retain agent-side target restrictions, support key rotation, make Hub trust assumption explicit.

## Migration Plan

1. Add versioned network data models, disabled-by-default Hub APIs without changing existing RPC behavior.
2. Stabilize, release `channel-go`.
3. Implement, conformance-test `hub-service-go`.
4. Implement two-agent Go `hub-net` prototype, Go `hub-net-node` rendezvous protocol against development Hub.
5. Add Bun, Swift publication APIs, local attestation.
6. Add Hub App administration, optional Launcher/Store distribution.
7. Integrate `hub-s3-local`, first behind explicit Hub Network setting — verify existing LAN/public behavior remains available for rollback.
8. Integrate applicable `hub-s3` configurations.
9. Enable network sharing per Hub only after owner opts in.

Rollback disables network registration, stops agents. Existing Hub RPC APIs, non-overlay S3 endpoints continue operating.

## Open Questions

- Final reserved DNS suffix, exact collision-resistant hostname encoding.
- Whether immediate revocation terminates all established TCP flows by default or explicit policy option.
- Initial Go agent desktop platform matrix, whether Apple packet-tunnel work ships in first implementation milestone.
- Canonical repository/module locations for `channel-go`, `hub-service-go`, shared Go Hub Network protocol package.
- Which NAT candidate discovery mechanism implemented directly by `hub-net-node` versus delegated to standard STUN service.
- Whether one `hub-net` process may host multiple isolated Hub network profiles in first release.
