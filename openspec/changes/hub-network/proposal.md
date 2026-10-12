## Why

Hub services can discover and call RPC APIs across a Hub, but ordinary TCP and UDP endpoints such as local S3 servers and game servers remain reachable only when participants already share a physical network or an external VPN. Hub Network adds an identity-aware private overlay so existing applications can use published ports through direct encrypted peer connections without embedding networking code in every service.

## What Changes

- Add network-share registration to Hub so any authenticated service can publish a local TCP or UDP port, regardless of how the service was launched.
- Add network permissions that are independent from RPC permissions and support Hub-wide, permission-group, selected-key, private, and disabled access.
- Add stable private addressing and local name resolution for published services and service instances.
- Add `hub-net`, a separately installed local agent that manages WireGuard, routing, DNS, peer establishment, and enforcement while keeping WireGuard out of service binaries.
- Add `hub-net-node`, a self-hostable rendezvous node for endpoint exchange and NAT-traversal coordination. The initial node does not forward application traffic.
- Implement `hub-net` and `hub-net-node` in Go, sharing versioned Hub Network protocol and cryptographic models.
- Stabilize `channel-go` and implement `hub-service-go` before agent development so Go services receive the same identity, registration, RPC, streaming, and network-publication behavior as Bun and Swift services.
- Add equivalent port-publication APIs to the Bun `hub-service` and Swift `HubService` libraries.
- Integrate Hub Network with Hub App, `hub-launcher`, `hub-store`, `hub-s3-local`, and `hub-s3`.
- Reserve a capability-negotiated `gateway` node role for a separate future full-tunnel VPN change; the initial release supports only the `rendezvous` role.

## Capabilities

### New Capabilities

- `network-shares`: Registration, lifecycle, discovery, and ownership of TCP/UDP ports published by authenticated services.
- `network-permissions`: Independent authorization of network shares using Hub identities, groups, explicit keys, and public/private access modes.
- `overlay-addressing`: Stable private addresses and names, local resolution, service-instance selection, and routing boundaries.
- `network-agent`: Local `hub-net` behavior for WireGuard interfaces, forwarding, enforcement, status, and service integration.
- `peer-coordination`: Direct peer establishment through `hub-net-node`, including endpoint exchange, signed grants, NAT traversal, and failure behavior without traffic relay.
- `network-integrations`: Behavior required from Go, Bun, and Swift SDKs, S3 services, Launcher, Store, and Hub App.

### Modified Capabilities

No existing OpenSpec capabilities are present.

## Impact

- `hub-pro`: new persistent network registry, permission APIs, streams, signed grants, and connection cleanup.
- `hub-net`: new cross-platform local agent and Hub service.
- `hub-net-node`: new self-hostable rendezvous service.
- `channel-go`: stabilize and version the existing Go Channel implementation for supported agent platforms.
- `hub-service-go`: new Go Hub service SDK, completed before `hub-net` and `hub-net-node` implementation.
- `hub-service` and `HubService`: matching share-publication models and APIs.
- Hub App: network-share management plus a future-capable Apple VPN extension boundary.
- `hub-launcher` and `hub-store`: optional installation and lifecycle management for `hub-net`.
- `hub-s3-local` and `hub-s3`: overlay-compatible endpoints and presigned URLs.
- WireGuard/platform networking dependencies are confined to `hub-net` and platform-specific app extensions, not ordinary services.
