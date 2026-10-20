## Why

Hub App can activate an app-scoped Hub Network VPN profile, but hub-pro still
reports its local agent as unbound and refuses to issue invitations. Requiring a
separate `hub-net` process makes the native macOS path incomplete: production
`hub-net` is not supported on macOS, while Hub App already owns the platform
WireGuard interface and identity needed to perform the local-agent role.

## What Changes

- Make an active Hub App VPN profile an explicit app-scoped local agent for its
  current Hub, with `invitation-bootstrap-v1` capability.
- Add authenticated app-agent bind, heartbeat/status, and unbind APIs. Binding
  is owner-authorized, tied to the Hub App connection and registered profile,
  and available only while the packet tunnel confirms it is active.
- Extend the packet-tunnel extension with invitation bootstrap rendezvous,
  temporary peer installation, bounded Hub enrollment routing, and deterministic
  teardown.
- Let hub-pro issue invitations against either a connected machine-local
  `hub-net` agent or a connected app-scoped Hub App agent without weakening the
  existing Unix-socket proof requirement for `hub-net`.
- Make Hub App maintain app-agent availability across tunnel start, stop,
  reconnect, sleep/wake, profile replacement, and process termination.
- Keep `hub-net-node` rendezvous/signaling-only. It exchanges candidates and
  authorizes invitation bootstrap sessions; it never relays application or
  enrollment traffic. Gateway behavior remains separate and unchanged.
- Remove the user-visible state where `Share Network` is active while Invite
  Code says `Local agent: Not bound`; active app membership shall report an
  available app-scoped local agent after bootstrap readiness is confirmed.
- Fail closed: no invitation is issued until the extension proves readiness,
  and loss of the app connection or tunnel immediately makes the binding
  unavailable and expires temporary bootstrap state.

## Capabilities

### New Capabilities

- `apple-app-agent`: App-scoped local-agent binding, readiness, lifecycle, and
  invitation-bootstrap behavior implemented by Hub App and its packet tunnel.

### Modified Capabilities

- `network-integrations`: Active Share Network membership also supplies the
  macOS local-agent role and exposes accurate invitation readiness.
- `network-invitations`: Invitation issuance accepts a ready app-scoped local
  agent and bootstrap joins can terminate at the Apple packet tunnel.
- `network-agent`: Local-agent semantics support an app-scoped Apple
  implementation without relaxing machine-local `hub-net` proof.
- `peer-coordination`: Invitation bootstrap sessions support the Apple
  app-agent while preserving direct-only rendezvous and bounded teardown.

## Impact

- `hub-pro`: app-agent registration, connection-bound lifecycle, invitation
  agent selection, status streams, authorization, and audit behavior.
- Hub App: Share Network state coordination, app-agent control messages,
  reconnect and sleep/wake handling, and invitation readiness UI.
- PacketTunnelExtension: direct bootstrap rendezvous client, temporary
  WireGuard peer configuration, enrollment-only routing, health reporting, and
  cleanup.
- `hub-net-node`: compatible bootstrap-session handling and conformance tests;
  no traffic relay or gateway responsibility.
- Shared Hub Network protocol: versioned app-agent bind/readiness and bootstrap
  messages plus Bun/Go/Swift compatibility fixtures.
- Existing `hub-net` agents and invitations remain compatible. No default
  route, gateway serving, or broad RPC permission is granted by app-agent
  activation.
