## Why

Hub App's Join Network UI validates invitation links but delegates joining to an
externally installed `/usr/local/bin/hub-net`. This fails on clean macOS systems
and cannot work on iOS. Apple users expect accepting an invitation to install
and enable Hub's embedded VPN profile without a separate daemon or CLI.

## What Changes

- Add `try await HubNets.main.join(link: String) -> Hub` as the native Apple
  invitation-join entry point.
- Move Apple joining from the external `hub-net join` process into Hub App and
  PacketTunnelExtension while preserving the existing invitation transaction.
- Generate and retain App profile, WireGuard, readiness, and transaction
  identities in Keychain/shared profile storage.
- Establish invitation-scoped direct bootstrap through the signed rendezvous
  node and selected machine or Apple inviting agent, without relay.
- Claim and consume the invitation, enroll one Hub profile, read the public Hub
  header, persist the Hub, install `NETunnelProviderManager`, and activate the
  VPN before returning the joined `Hub`.
- Roll back local profile, VPN, peer, node session, and remote claim on every
  pre-commit failure; make retries resume one transaction after remote commit.
- Remove the installed `hub-net` prerequisite from Hub App Join Network UI on
  macOS and iOS. Existing `hub-net join` remains supported for daemon clients.

## Capabilities

### Modified Capabilities

- `network-integrations`: Native Apple invitation join API, automatic profile
  installation/activation, Hub persistence, UI behavior, and platform parity.
- `network-invitations`: Apple joiner identity, direct bootstrap, enrollment,
  atomic commit, idempotent retry, and cleanup requirements.
- `peer-coordination`: PacketTunnelExtension participates as invitation joiner
  and installs only transaction-scoped bootstrap peer/routes.

## Impact

- Hub App: `HubNets.join`, Home Join Network flow, Hub persistence, transaction
  storage, Keychain identities, and user-facing progress/errors.
- PacketTunnelExtension: joiner-side rendezvous, temporary bootstrap peer and
  routes, transition to committed membership configuration, and cleanup.
- HubService/shared wire: typed claim/enroll/header and join transaction models.
- hub-pro and hub-net-node: compatibility tests for native Apple joiners; wire
  behavior remains compatible with existing Go joiners.
- Signing: macOS and iOS App/extension profiles require existing Network
  Extension, App Group, and shared Keychain entitlements.

## Compatibility

Existing Hub records, installed VPN profiles, invitation issuers, and
`hub-net join` remain valid. Native joining is additive at protocol level.
Invitation validation remains strict and no migration enables gateway, default
routes, forwarding, NAT, or resource access.
