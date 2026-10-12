## 1. Protocol Foundations

- [x] 1.1 HN-001 `[hub-pro]` Resolve and document the canonical DNS suffix, authority encoding, stable resource ID, and overlay address ranges with collision test vectors.
- [x] 1.2 HN-002 `[hub-pro]` Define versioned TypeScript wire models for shares, policies, agent profiles, attestations, grants, node tickets, candidates, status, and errors.
- [x] 1.3 HN-003 `[hub-service-go]` Define matching Go wire models and shared cross-language JSON fixtures with exact round-trip expectations.
- [x] 1.4 HN-004 `[HubService]` Review the wire models for Swift `Codable` compatibility and verify the shared fixtures.
- [x] 1.5 HN-005 `[hub-net]` Document the initial Go platform/WireGuard integration matrix, privilege requirements, local IPC endpoints, and supported operating systems.
- [x] 1.6 HN-006 `[hub-net-node]` Define the versioned Go rendezvous protocol, capability advertisement, session limits, candidate lifecycle, and no-payload invariant.
- [x] 1.7 HN-007 `[hub-pro]` Add signature-domain and cryptographic test vectors for local attestations, profile bindings, connection grants, and rendezvous tickets.

## 2. Go Channel Stabilization

- [x] 2.1 HN-050 `[channel-go]` Move the existing library to its canonical repository/module path and remove committed build and coverage artifacts.
- [x] 2.2 HN-051 `[channel-go]` Pin and document one supported Go toolchain version consistently in `go.mod`, CI, and README.
- [x] 2.3 HN-052 `[channel-go]` Run and repair unit tests, `go vet`, and the race detector on Linux and Darwin.
- [x] 2.4 HN-053 `[channel-go]` Run current Go-to-TypeScript interoperability tests for requests, streams, subscriptions, cancellation, headers, context, and reconnect replay.
- [ ] 2.5 HN-054 `[channel-go]` Add supported-platform build checks and implement or replace the missing Windows poller path before claiming Windows support.
- [x] 2.6 HN-055 `[channel-go]` Measure stripped binary and dependency impact with Sonic and `encoding/json`, then make the selected codec policy explicit.
- [ ] 2.7 HN-056 `[channel-go]` Tag a conformance-tested module version consumable by `hub-service-go`.

## 3. Go Hub Service SDK

- [ ] 3.1 HN-070 `[hub-service-go]` Scaffold the standalone module against the released `channel-go` version and shared protocol fixtures.
- [ ] 3.2 HN-071 `[hub-service-go]` Implement persistent Ed25519 identity, public-key access, short-lived Hub authentication headers, and key storage controls.
- [ ] 3.3 HN-072 `[hub-service-go]` Implement Hub address/profile options, connection lifecycle, reconnect registration, and clean shutdown.
- [ ] 3.4 HN-073 `[hub-service-go]` Implement post, stream, send, values, cancellation, typed helpers, and context forwarding on top of `channel-go`.
- [ ] 3.5 HN-074 `[hub-service-go]` Implement service headers, API permissions, group defaults, limits, profile metadata, and atomic service registration.
- [ ] 3.6 HN-075 `[hub-service-go]` Implement network-share declarations, local-agent challenge proof, attestation refresh, runtime port updates, and reconnect republishing.
- [ ] 3.7 HN-076 `[hub-service-go]` Add conformance tests against Bun `hub-service`, Swift `HubService`, and a current `hub-pro` instance.
- [ ] 3.8 HN-077 `[hub-service-go]` Document the public API, supported platforms, key-storage behavior, and minimal service examples.
- [ ] 3.9 HN-078 `[hub-service-go]` Tag the first conformance-tested release required by `hub-net`.

## 4. Hub Control Plane

- [ ] 4.1 HN-100 `[hub-pro]` Add persistent Hub network identity, overlay allocation storage, schema migration, and uniqueness tests.
- [ ] 4.2 HN-101 `[hub-pro]` Add ephemeral agent-profile registration tied to authenticated connections, including WireGuard key binding and cleanup on disconnect.
- [ ] 4.3 HN-102 `[hub-pro]` Add stable network-resource and live-provider models with deterministic IDs and separate persistence lifecycles.
- [ ] 4.4 HN-103 `[hub-pro]` Accept atomic network-share replacement in service registration and validate connected-agent attestations.
- [ ] 4.5 HN-104 `[hub-pro]` Implement `hub`, `group`, `keys`, `private`, and `disabled` network policy evaluation independently from RPC permissions.
- [ ] 4.6 HN-105 `[hub-pro]` Add owner-authorized APIs for viewing and changing network policies and resource revocation generations.
- [ ] 4.7 HN-106 `[hub-pro]` Add permission-filtered streams for resources, providers, agents, connection status, and diagnostics.
- [ ] 4.8 HN-107 `[hub-pro]` Implement live-provider selection, including optional specific-provider requests and unavailable-provider behavior.
- [ ] 4.9 HN-108 `[hub-pro]` Implement purpose-separated, short-lived connection grants and rendezvous tickets with expiry, generation, and replay validation.
- [ ] 4.10 HN-109 `[hub-pro]` Propagate immediate revocation events to connected agents and reject all later grant issuance or renewal.
- [ ] 4.11 HN-110 `[hub-pro]` Add unit and integration tests for ownership spoofing, invalid attestations, policy isolation, disconnect cleanup, grant expiry, and revocation.

## 5. Bun Service SDK

- [ ] 5.1 HN-200 `[hub-service]` Add public network-share, protocol, policy, and publication-result types matching the approved wire fixtures.
- [ ] 5.2 HN-201 `[hub-service]` Add a chainable share-publication API that supports runtime-selected ports and republishes shares on Hub reconnect.
- [ ] 5.3 HN-202 `[hub-service]` Extend key handling to prove service identity to a local agent challenge without exposing private key material.
- [ ] 5.4 HN-203 `[hub-service]` Implement platform local-agent discovery, IPC negotiation, attestation refresh, and diagnosable agent-unavailable behavior.
- [ ] 5.5 HN-204 `[hub-service]` Add tests for share serialization, reconnect replacement, dynamic ports, challenge signing, and absence of WireGuard dependencies.

## 6. Swift Service SDK

- [ ] 6.1 HN-220 `[HubService]` Add Swift network-share, protocol, policy, and publication-result models that pass the shared JSON fixtures.
- [ ] 6.2 HN-221 `[HubService]` Add Swift service APIs equivalent to Bun share publication, update, removal, and reconnect behavior.
- [ ] 6.3 HN-222 `[HubService]` Add service-key challenge proof using existing KeyChain identity material without exposing private keys.
- [ ] 6.4 HN-223 `[HubService]` Implement Apple local-agent IPC and attestation refresh with equivalent error semantics.
- [ ] 6.5 HN-224 `[HubService]` Add parity tests that consume the shared protocol fixtures and verify no WireGuard dependency enters the core library.

## 7. Local Network Agent

- [ ] 7.1 HN-300 `[hub-net]` Scaffold the Go agent against released `hub-service-go`, shared protocol models, configuration, secure key storage, and structured logging.
- [ ] 7.2 HN-301 `[hub-net]` Implement local profile registration, persistent profile identity, separate WireGuard key lifecycle, and Hub reconnect behavior.
- [ ] 7.3 HN-302 `[hub-net]` Implement the secured local IPC server, nonce challenge, service-proof verification, local-target checks, and signed attestations.
- [ ] 7.4 HN-303 `[hub-net]` Implement the initial platform WireGuard adapter behind a portable interface with deterministic configuration tests.
- [ ] 7.5 HN-304 `[hub-net]` Implement overlay address assignment, scoped route installation, rollback, and prevention of an initial default internet route.
- [ ] 7.6 HN-305 `[hub-net]` Implement the reserved-suffix DNS resolver, canonical resource lookup, ordinary-DNS preservation, and resolver teardown.
- [ ] 7.7 HN-306 `[hub-net]` Implement grant verification and on-demand WireGuard peer configuration bound to the authorized peer keys and overlay addresses.
- [ ] 7.8 HN-307 `[hub-net]` Implement per-resource TCP/UDP enforcement, unshared-port rejection, generation revocation, and active-flow termination.
- [ ] 7.9 HN-308 `[hub-net]` Implement provider connection orchestration, candidate checks, handshake timeout, idle peer cleanup, and direct-connect diagnostics.
- [ ] 7.10 HN-309 `[hub-net]` Expose permission-controlled Hub APIs and streams for profile, peers, shares, node configuration, health, and diagnostics.
- [ ] 7.11 HN-310 `[hub-net]` Add an end-to-end local test harness using two isolated agents, an authorized TCP share, an authorized UDP share, and blocked ports.
- [ ] 7.12 HN-311 `[hub-net]` Add packaging and privilege checks for each initial supported platform, including safe failure when tunnel setup is unavailable.

## 8. Rendezvous Node

- [ ] 8.1 HN-400 `[hub-net-node]` Scaffold the self-hostable Go node with shared protocol models, configuration, health reporting, protocol versioning, and advertised `rendezvous` role.
- [ ] 8.2 HN-401 `[hub-net-node]` Validate Hub-signed rendezvous tickets without requiring prior registration of self-hosted Hubs.
- [ ] 8.3 HN-402 `[hub-net-node]` Implement observed-endpoint reporting, bounded candidate exchange, session expiry, and opaque session identifiers.
- [ ] 8.4 HN-403 `[hub-net-node]` Implement rate, size, connection, and retention limits with operational abuse diagnostics.
- [ ] 8.5 HN-404 `[hub-net-node]` Add tests proving application payloads cannot be submitted or forwarded through a rendezvous-only node.
- [ ] 8.6 HN-405 `[hub-net-node]` Add container and standalone deployment assets for public and private self-hosting.
- [ ] 8.7 HN-406 `[hub-net-node]` Add two-NAT integration tests that verify successful direct WireGuard traffic never traverses the node.

## 9. Storage Integrations

- [ ] 9.1 HN-500 `[hub-s3-local]` Publish the actual dynamically selected S3 TCP port through the Bun share API.
- [ ] 9.2 HN-501 `[hub-s3-local]` Construct the S3 client authority and presigned URLs from the canonical overlay publication result when Hub Network is enabled.
- [ ] 9.3 HN-502 `[hub-s3-local]` Add upload/download tests across two agents and verify API permission and network permission remain independent.
- [ ] 9.4 HN-510 `[hub-s3]` Classify configured endpoints as public remote endpoints or explicitly publishable local/custom endpoints.
- [ ] 9.5 HN-511 `[hub-s3]` Preserve AWS/Wasabi public URLs by default and add explicit overlay publication for eligible custom endpoints.
- [ ] 9.6 HN-512 `[hub-s3]` Add regression tests for public-provider URLs and overlay-enabled custom-provider URLs.

## 10. App, Launcher, and Store

- [ ] 10.1 HN-600 `[Hub App]` Add decodable network resource, policy, agent, provider, and diagnostic models matching Hub streams.
- [ ] 10.2 HN-601 `[Hub App]` Add permission-aware views for share availability, owners, policies, agents, and direct-connect failures.
- [ ] 10.3 HN-602 `[Hub App]` Add owner actions for public/group/key/private/disabled policy changes and immediate revocation.
- [ ] 10.4 HN-603 `[Hub App]` Create the Apple packet-tunnel extension boundary, entitlement plan, shared configuration, and WireGuard dependency isolation for supported platforms.
- [ ] 10.5 HN-604 `[Hub App]` Prove that a built-in encoder can use an overlay S3 URL through an active app-scoped profile without encoder networking changes.
- [ ] 10.6 HN-620 `[hub-launcher]` Add optional install, configuration, supervision, update, and uninstall support for `hub-net` without making Launcher part of trust.
- [ ] 10.7 HN-621 `[hub-launcher]` Surface agent privilege/setup failures and preserve manual-install compatibility.
- [ ] 10.8 HN-630 `[hub-store]` Add the `hub-net` server entry with valid Launcher setup, platform notes, and one-click installation metadata.

## 11. System Verification and Release

- [ ] 11.1 HN-700 `[hub-pro]` Run shared contract fixtures against `hub-pro`, `channel-go`, `hub-service-go`, `hub-service`, `HubService`, `hub-net`, and `hub-net-node` and resolve all version mismatches.
- [ ] 11.2 HN-701 `[hub-net]` Run direct-connect tests across representative NAT combinations and document unsupported cases with no-relay failure behavior.
- [ ] 11.3 HN-702 `[hub-pro]` Run adversarial tests for forged service ownership, forged agent bindings, replayed grants, endpoint substitution, DNS spoofing, and revoked groups.
- [ ] 11.4 HN-703 `[hub-net-node]` Verify with packet capture and automated assertions that the node sees coordination traffic only and no application payload traffic.
- [ ] 11.5 HN-704 `[hub-pro]` Document upgrade, opt-in enablement, rollback, key rotation, network reset, and recovery procedures.
- [ ] 11.6 HN-705 `[hub-net]` Publish supported-platform packages and checksums after conformance, security, and binary-size verification.
- [ ] 11.7 HN-706 `[hub-pro]` Complete an end-to-end release scenario covering manual services, Launcher-installed agents, S3 transfer, TCP game sharing, UDP sharing, permission revocation, and reconnect recovery.
