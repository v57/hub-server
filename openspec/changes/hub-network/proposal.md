## Why

Hub services discover/call RPC APIs across Hub, but TCP/UDP endpoints (local S3, game servers) only reachable on shared physical network or VPN. Hub Network adds identity-aware private overlay — apps use published ports through direct encrypted peer connections, no networking code in services.

## What Changes

- Register network shares on Hub — authenticated services publish local TCP/UDP ports regardless of launch method.
- Network permissions independent from RPC — Hub-wide, permission-group, selected-key, private, disabled access.
- Stable private addressing, local name resolution for published services and instances.
- `hub-net` — separate local agent managing WireGuard, routing, DNS, peer establishment, enforcement. WireGuard stays out of service binaries.
- `hub-net-node` — self-hostable rendezvous node for endpoint exchange and NAT-traversal. Initial node does not forward application traffic.
- `hub-net` and `hub-net-node` implemented in Go — share versioned Hub Network protocol and crypto models.
- Stabilize `channel-go`, implement `hub-service-go` before agent development — Go services get same identity, registration, RPC, streaming, network publication as Bun/Swift.
- Add port-publication APIs to Bun `hub-service` and Swift `HubService` libraries.
- Integrate Hub Network with Hub App, `hub-launcher`, `hub-store`, `hub-s3-local`, `hub-s3`.
- Reserve `gateway` node role for future full-tunnel VPN. Initial release supports only `rendezvous` role.

## Capabilities

### New Capabilities

- `network-shares`: Registration, lifecycle, discovery, ownership of TCP/UDP ports published by authenticated services.
- `network-permissions`: Independent authorization of network shares using Hub identities, groups, explicit keys, public/private access modes.
- `overlay-addressing`: Stable private addresses, names, local resolution, service-instance selection, routing boundaries.
- `network-agent`: Local `hub-net` behavior — WireGuard interfaces, forwarding, enforcement, status, service integration.
- `peer-coordination`: Direct peer establishment through `hub-net-node` — endpoint exchange, signed grants, NAT traversal, failure behavior without traffic relay.
- `network-integrations`: Behavior required from Go, Bun, Swift SDKs, S3 services, Launcher, Store, Hub App.

### Modified Capabilities

None. No existing OpenSpec capabilities.

## Impact

- `hub-pro`: new persistent network registry, permission APIs, streams, signed grants, connection cleanup.
- `hub-net`: new cross-platform local agent, Hub service.
- `hub-net-node`: new self-hostable rendezvous service.
- `channel-go`: stabilize, version existing Go Channel for supported agent platforms.
- `hub-service-go`: new Go Hub service SDK — completed before `hub-net`, `hub-net-node` implementation.
- `hub-service` and `HubService`: matching share-publication models, APIs.
- Hub App: network-share management, future-capable Apple VPN extension boundary.
- `hub-launcher`, `hub-store`: optional installation, lifecycle management for `hub-net`.
- `hub-s3-local`, `hub-s3`: overlay-compatible endpoints, presigned URLs.
- WireGuard/platform networking confined to `hub-net`, platform-specific app extensions — not in ordinary services.