## Context

Hub currently authenticates long-lived WebSocket connections with Ed25519 service identities, registers RPC paths on those connections, and applies hosting and calling permissions in `hub-pro`. Services such as `hub-s3-local` also expose ordinary TCP endpoints, but URLs for those endpoints contain a LAN hostname and therefore fail when the consumer is outside that LAN.

Hub Network adds a private IP overlay without changing the existing RPC data path. `hub-pro` remains the authoritative control plane. A separately installed Go `hub-net` agent owns the local WireGuard interface and exposes approved local ports. A self-hosted or public Go `hub-net-node` helps agents discover endpoints and perform NAT traversal but is not on the application data path.

The system spans Go and Bun services, a Swift service library, an Apple app, several operating systems, and services that may be launched manually. It therefore cannot depend on Launcher ownership or require a WireGuard implementation in every service binary.

An existing `channel-go` implementation provides Channel request/response, streams, subscriptions, cancellation, reconnect behavior, client/server transports, and TypeScript interoperability tests. It is not yet a Hub service SDK and currently has platform and module-release work to complete. `hub-service-go` will be implemented and conformance-tested on top of it before either Go network executable is built.

### Trust boundaries

- A **Hub service identity** owns RPC APIs and published network shares.
- A **network profile identity** belongs to a `hub-net` agent or an app-scoped Hub Network profile and is the principal authorized to open overlay connections.
- A **WireGuard key** identifies one tunnel interface and is bound to a network profile identity by a short-lived Hub-signed grant.
- `hub-pro` is trusted to authenticate identities, evaluate permissions, and sign grants.
- `hub-net` is trusted only for the local machine/profile it controls and MUST enforce the grants it receives.
- `hub-net-node` is not trusted with application data or authorization decisions. It can observe coordination metadata and public endpoints.
- A service process is not assumed to have been launched by `hub-launcher`.

Transparent IP routing cannot reliably identify which ordinary process originated a packet on every supported platform. Network access is therefore granted to a network profile identity, not automatically to each Hub RPC service sharing a machine. App-scoped VPN profiles and OS network isolation can provide a narrower principal where supported.

## Goals / Non-Goals

**Goals:**

- Allow an authenticated service to publish a local TCP or UDP port through its local `hub-net` agent.
- Allow authorized network profiles on the same Hub to use normal sockets and URLs to reach published ports.
- Prefer direct WireGuard peer connections and fail explicitly when no direct path exists.
- Keep registration, access policy, discovery, revocation, and signed grants in `hub-pro`.
- Reuse Hub groups while keeping network permissions distinct from RPC permissions.
- Keep Go, Bun, and Swift publication APIs behaviorally equivalent.
- Provide a reusable Go Hub service SDK with behavior equivalent to the Bun and Swift SDKs before building the Go agent and node.
- Make `hub-net` installable manually or through Launcher and Store.
- Support stable S3 presigned URLs when a local or remote S3 endpoint is published into the overlay.
- Permit future node capabilities, including a separately specified `gateway` role, without changing project identity or the initial protocol envelope.

**Non-Goals:**

- Relaying application traffic through `hub-net-node` in the initial release.
- Full-tunnel internet routing, exit nodes, subnet routing, or public ingress in this change.
- Making overlay URLs work without an active Hub Network profile.
- Identifying arbitrary originating processes inside a device-wide VPN.
- Reimplementing WireGuard or carrying file payloads through Hub RPC.
- Propagating network shares across merged Hubs in the initial release.
- Requiring `hub-launcher` for identity, publication, or connectivity.

## Decisions

### 1. `hub-pro` is the authoritative network control plane

Services register network-share metadata through their authenticated Hub connection. Hub binds each registration to the connection identity and keeps the live provider record ephemeral. Access policy is persisted separately using a stable resource identifier derived from the owning service key and a publisher-supplied stable share name.

This follows the existing service registry and permission model and works for manually launched services.

**Alternative considered:** Make `hub-net` authoritative. This would duplicate Hub permissions and prevent consistent management from Hub App.

### 2. Publication requires local-agent attestation

Publishing a share is a two-sided operation:

1. The service discovers the local agent through a well-known Unix socket, named pipe, or platform IPC endpoint.
2. The agent sends a nonce.
3. The service proves its Hub identity by signing the nonce.
4. The agent verifies the proof, verifies that the requested target is local, and returns a short-lived signed attestation binding the service key, agent key, share name, protocol, and local target.
5. The service includes that attestation in its Hub share registration.
6. Hub verifies that the attestation belongs to a connected authorized agent before advertising the share.

This prevents a remote service from claiming a port on an unrelated agent and does not depend on Launcher.

**Alternative considered:** Trust a service-provided `agentId`. This permits remote share claims and accidental exposure of unrelated local ports.

### 3. Network profiles are access principals

The caller in a connection grant is the authenticated `hub-net` network profile, not an inferred RPC service process. “Public” means available to all authenticated network profiles joined to that Hub. Group and explicit-key policies apply to network profile keys.

The Hub App can use its existing Hub identity for an app-scoped profile when platform key sharing permits it, or explicitly bind a dedicated profile key to the app identity.

**Alternative considered:** Attribute every socket to a Hub service identity. This is not portable for ordinary applications and would require per-process VPN engines or network namespaces.

### 4. API and network permissions remain separate

Each stable network resource has an access policy:

- `hub`: all authenticated network profiles on the Hub
- `group`: profiles assigned to one named Hub group
- `keys`: an explicit set of profile keys
- `private`: the owner and Hub owners
- `disabled`: not connectable

Hub groups are reused as membership collections, but granting an RPC path never grants a network resource and vice versa. Owners can manage all network policies.

### 5. Go is the implementation language for the agent and node

`hub-net` and `hub-net-node` SHALL be implemented in Go. They share a small versioned Go package for Hub Network wire models, grants, tickets, candidates, and test fixtures.

Go is selected because the existing `channel-go` removes the main Hub protocol barrier, Go has mature WireGuard control and userspace implementation options, and both networking processes benefit from a single executable, native UDP support, and shared concurrency/runtime behavior.

Apple app-scoped packet tunnels remain Swift with WireGuardKit because they execute inside an Apple Network Extension. They conform to the same wire contracts rather than embedding the Go agent.

**Alternative considered:** Bun/TypeScript for the agent and node. This matches `hub-pro` but would require more native routing, TUN, DNS, UDP, and platform bridging and would not reuse `channel-go`.

**Alternative considered:** Rust. It can produce efficient binaries but would require a new Channel and Hub service stack before network work.

### 6. `channel-go` is stabilized before `hub-service-go`

The existing library becomes a versioned Go module with a canonical repository module path. Before use it must pass unit tests, race detection, current TypeScript interoperability tests, and supported-platform builds; use one documented Go toolchain version; and measure the binary impact of Sonic versus `encoding/json`.

### 7. `hub-service-go` is a reusable prerequisite

`hub-service-go` SHALL be a standalone Go SDK layered on `channel-go`, not code hidden inside `hub-net`. It implements persistent Hub identity, authentication headers, profiles, API registration and settings, post/stream/send/values behavior, reconnect registration, and network-share publication with local-agent proof and attestation.

`hub-net` consumes `hub-service-go` to register itself, expose control APIs, and communicate with `hub-pro`. `hub-net-node` uses the shared Hub Network protocol and cryptographic packages; it uses `hub-service-go` only if its approved runtime design requires Hub RPC.

**Alternative considered:** Implement only the minimum Hub client inside `hub-net`. This duplicates SDK behavior, prevents reuse by other Go services, and makes conformance harder.

### 8. WireGuard is the data plane, with one implementation per profile

`hub-net` configures the platform WireGuard implementation and routes only overlay prefixes. Ordinary services use normal TCP/UDP and contain no WireGuard dependency. Apple platforms place WireGuardKit in a packet-tunnel extension rather than each embedded service.

Per-resource port enforcement is performed by `hub-net` and, where available, OS firewall rules. WireGuard `AllowedIPs` limits peer addresses but is not treated as a port authorization system.

### 9. Hubs issue short-lived connection grants

A grant binds:

- protocol version and grant identifier
- authoritative Hub key and network identifier
- caller network profile key and WireGuard public key
- target agent key and WireGuard public key
- stable resource ID and live provider ID
- protocol, overlay destination address, and destination port
- issue, expiry, and optional revocation generation

Both agents validate the Hub signature and all bound fields. Grants are short-lived; permission changes prevent renewal and increment a resource generation so agents can terminate active flows when immediate revocation is requested.

Hub signing uses a purpose-separated key or signature domain so authentication tokens cannot be replayed as network grants.

### 10. `hub-net-node` is an untrusted rendezvous service

Agents connect to a node using a Hub-signed, short-lived rendezvous ticket. The node:

- reports observed UDP endpoints,
- exchanges candidates and encrypted coordination messages,
- rate-limits sessions,
- advertises supported node roles and protocol versions.

The initial role set contains only `rendezvous`. Application packets are sent directly between agents after a WireGuard handshake. If candidate checks and the handshake fail before the timeout, the connection fails; there is no relay fallback.

The node may accept tickets from self-hosted Hubs without prior registration by validating the ticket against the Hub key carried in the signed envelope. Agents, not the node, establish authorization trust in their configured Hub.

**Alternative considered:** Route packets through the node on failure. This creates bandwidth cost, abuse exposure, and a materially different privacy model.

### 11. Overlay addressing is scoped by Hub and agent

Each Hub defines a random persistent network identifier and allocates unique overlay addresses to network agents. Live providers receive stable resource names but resolve to the selected provider agent address.

The canonical DNS suffix and encoding will be versioned. Names include a stable share label plus collision-resistant owner and Hub components; display names are never used as the sole identity. A local resolver in `hub-net` answers only the reserved Hub Network suffix and forwards or bypasses all other DNS according to platform behavior.

Service-instance selection occurs through Hub discovery before connection authorization. A caller can request a specific provider; otherwise Hub applies a deterministic available-provider policy.

### 12. Protocols are versioned independently

The Hub control API, local agent IPC, node rendezvous protocol, grant envelope, and DNS naming format each carry a version. Implementations reject unsupported major versions and ignore unknown optional fields in a compatible minor version.

Go `hub-service-go`, Bun `hub-service`, and Swift `HubService` expose matching share models and access modes. Platform-specific details remain behind their respective implementations.

### 13. Integrations consume the common model

- `hub-s3-local` publishes its dynamically selected S3 TCP port and uses the returned overlay authority when constructing its S3 client and presigned URLs.
- `hub-s3` publishes only endpoints it actually hosts or deliberately gateways; remote AWS/Wasabi public endpoints remain public and are not automatically tunneled.
- `hub-launcher` optionally installs and supervises `hub-net` but provides no required trust.
- `hub-store` lists `hub-net` as a server installation.
- Hub App manages shares and policies and can later host an app-scoped network profile. Full-tunnel gateway UI and behavior are deferred.

### 14. Cross-project ownership

- `hub-pro`: registry, persistence, permission evaluation, streams, address allocation, grant signing.
- `channel-go`: compatible Go Channel runtime and transports.
- `hub-service-go`: reusable Go Hub identity, registration, RPC, streaming, and share-publication SDK.
- `hub-net`: local IPC, key storage, WireGuard lifecycle, DNS, routing, enforcement, candidate checks.
- `hub-net-node`: rendezvous protocol and abuse controls.
- `hub-service-go` / `hub-service` / `HubService`: publication API, local attestation exchange, matching data models.
- Hub App: administration and platform profile integration.
- Launcher / Store: optional distribution and lifecycle.
- S3 services: endpoint publication and URL integration.

## Risks / Trade-offs

- **[Symmetric NAT or restrictive firewall prevents a direct path]** → Candidate attempts time out with a clear diagnostic; no traffic relay is silently introduced.
- **[A device-wide profile grants all routed local processes the same network identity]** → Document the boundary, support app-scoped profiles where available, and recommend OS isolation for stronger separation.
- **[A malicious local process attempts to expose another localhost port]** → Require signed service proof, local-agent attestation, loopback/local target validation, and explicit publication in Hub.
- **[The rendezvous node observes membership timing and public endpoints]** → Minimize retained metadata, use short-lived opaque session identifiers, encrypt peer coordination payloads, and document remaining metadata.
- **[Permission revocation races with cached grants]** → Keep grants short-lived and propagate generation updates to connected agents for immediate termination where configured.
- **[Stable DNS authorities make S3 signatures sensitive to naming changes]** → Version and freeze the canonical authority format before S3 migration.
- **[Large peer meshes increase WireGuard peer state]** → Configure peers on demand and remove idle peer state after a bounded lifetime.
- **[Cross-platform routing behavior differs]** → Keep a common conformance suite and define platform-specific adapters rather than weakening shared semantics.
- **[`channel-go` has not been verified in the current workspace]** → Pin the Go toolchain, run unit/race/interop tests, repair platform gaps, and release it before `hub-service-go`.
- **[Go networking dependencies increase the agent binary]** → Measure stripped builds, compare Sonic with `encoding/json`, use kernel WireGuard where available, and keep Go code out of ordinary service binaries.
- **[A public rendezvous service is abused for signaling]** → Require valid Hub tickets, impose rate and size limits, and never accept or forward application payloads.
- **[Hub compromise authorizes network access]** → Separate signing domains, retain agent-side target restrictions, support key rotation, and make the Hub trust assumption explicit.

## Migration Plan

1. Add versioned network data models and disabled-by-default Hub APIs without changing existing RPC behavior.
2. Stabilize and release `channel-go`.
3. Implement and conformance-test `hub-service-go`.
4. Implement a two-agent Go `hub-net` prototype and Go `hub-net-node` rendezvous protocol against a development Hub.
5. Add Bun and Swift publication APIs and local attestation.
6. Add Hub App administration and optional Launcher/Store distribution.
7. Integrate `hub-s3-local`, first behind an explicit Hub Network setting, and verify existing LAN/public behavior remains available for rollback.
8. Integrate applicable `hub-s3` configurations.
9. Enable network sharing per Hub only after an owner opts in.

Rollback disables network registration and stops agents. Existing Hub RPC APIs and non-overlay S3 endpoints continue to operate.

## Open Questions

- Final reserved DNS suffix and exact collision-resistant hostname encoding.
- Whether immediate revocation terminates all established TCP flows by default or is an explicit policy option.
- Initial Go agent desktop platform matrix and whether Apple packet-tunnel work ships in the first implementation milestone.
- Canonical repository/module locations for `channel-go`, `hub-service-go`, and the shared Go Hub Network protocol package.
- Which NAT candidate discovery mechanism is implemented directly by `hub-net-node` versus delegated to a standard STUN service.
- Whether one `hub-net` process may host multiple isolated Hub network profiles in the first release.
