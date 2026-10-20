## Why

Current Hub Network agent starts with one configured Hub, one service identity,
one WireGuard profile, one interface, and one overlay route set. This prevents a
device from belonging to independent Hubs, makes Hub Network installation depend
on an already-known Hub address, and provides no safe onboarding flow.

Users need a short invitation that bootstraps a private connection without
publishing hub-pro, persistent isolated membership in several Hubs, and optional
full-tunnel internet access through an explicitly enabled peer.

## What Changes

- Add persistent Hub header with hostname-derived default and public read,
  owner-only update APIs.
- Add owner-created, signed, single-use, ten-minute Hub Network invitations.
- Bind each Hub to an explicitly registered machine-local `hub-net`; never infer
  locality from connection order.
- Bootstrap joins through `hub-net-node` and inviting `hub-net`, then reach
  `hub-pro` only through Hub Network.
- Redesign `hub-net` as disconnected-by-default daemon managing isolated,
  persistent per-Hub sessions.
- Add `join`, `leave`, `list`, `open`, `close`, `vpn allow`, `vpn remove`, and
  `removeAll` CLI commands.
- Isolate overlapping Hub address spaces through per-Hub interfaces and
  deterministic local address translation.
- Add Hub App controls for local network participation, invitation copy,
  code-based join, gateway serving, and full-tunnel gateway selection.
- Add peer gateway role. Gateway traffic passes through opted-in `hub-net` or
  Hub App peer, never through rendezvous-only `hub-net-node`.
- Supersede prior `hub-network` exclusions of multi-profile agents and
  full-tunnel routing only where this change defines replacement behavior.

## Capabilities

### New Capabilities

- `hub-header`: Persistent extensible Hub metadata and access rules.
- `network-invitations`: Invitation creation, encoding, bootstrap authorization,
  one-time consumption, and join transaction.
- `network-gateway`: Peer gateway advertisement, serving, selection, full-tunnel
  routing, DNS, kill switch, and revocation.

### Modified Capabilities

- `network-agent`: Multiple independent Hub sessions, disconnected startup,
  command surface, persistent publications, and reset behavior.
- `peer-coordination`: Join bootstrap coordination and per-Hub node ownership.
- `overlay-addressing`: Per-Hub interfaces, translated local address spaces,
  local aliases, and DNS isolation.
- `network-integrations`: Hub App onboarding, invitation, and VPN controls.

## Impact

- `hub-pro`: Hub header persistence; local-agent binding; invitation issuance,
  consumption, cleanup, and authorization.
- `hub-net`: new supervisor/session architecture, local command IPC, persistent
  membership/publication state, address translation, gateway forwarding.
- `hub-net-node`: scoped bootstrap sessions and invitation authorization checks;
  remains rendezvous/signaling only.
- shared Hub Network protocol: invitation and bootstrap envelopes, gateway
  capability/status models, conformance fixtures.
- `HubService`, `hub-service-go`, `hub-service`: header/invitation models where
  consumed by clients; share behavior remains compatible.
- Hub App and packet-tunnel extension: local join, deep link, multiple Hub
  profiles, gateway serving, full-tunnel routing, and kill switch.

## Compatibility

Existing single-Hub installations require migration into one per-Hub session.
Stored profile identity, WireGuard key, Hub address, and publications move
without rotation. Existing network share, grant, permission, and rendezvous
contracts remain valid within that session.

Old clients ignore new APIs and gateway advertisements. Gateway serving and
selection default disabled. No migration installs a default route.
