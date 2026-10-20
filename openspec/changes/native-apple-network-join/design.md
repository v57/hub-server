## Context

`HubNetworkInvitationJoiner.live` currently launches an external `hub-net`
binary. Hub App already embeds PacketTunnelExtension and can install a
`NETunnelProviderManager`, but its extension implements only the inviting-agent
side of invitation bootstrap. Native joining must preserve the existing direct,
single-use, least-privilege transaction without moving WireGuard into Hub App.

## Goals / Non-Goals

Goals:

- One public async API: `try await HubNets.main.join(link: String) -> Hub`.
- Work on macOS and iOS without external executables.
- Install, enable, and start the embedded VPN profile as part of successful join.
- Return only after Hub persistence, tunnel activation, and authenticated Hub
  connection are usable.
- Preserve direct-path-only transport, strict invitation validation, Keychain
  isolation, atomic persistence, idempotent retry, and complete cleanup.

Non-goals:

- Embedding Go or installing a privileged `hub-net` daemon.
- Relaying enrollment traffic through hub-net-node.
- Enabling gateway serving, full-tunnel defaults, port shares, or ordinary
  resource routes during join.
- Replacing daemon-side joining on Linux or other machine-agent platforms.

## Decisions

### 1. `HubNets.join` owns one serialized native transaction

`HubNets` SHALL serialize joins because Hub currently has one Apple packet
tunnel manager and one shared profile file. It validates the canonical link
before mutation, derives the stable transaction ID from the invitation token,
loads or creates staged Keychain identities, and rejects a concurrent different
join. Repeating the same link resumes the staged transaction.

The function returns the persisted `Hub`, not a presentation-only join result:

```swift
@MainActor
func join(link: String) async throws -> Hub
```

### 2. PacketTunnelExtension owns join bootstrap networking

Hub App sends a versioned join command containing canonical invitation,
transaction identity, and public joiner keys. PacketTunnelExtension validates
the same signed invitation, opens the node session, exchanges direct candidates,
and installs only the signed inviting-agent and hub-pro bootstrap host routes.
It reports bounded state through provider messages. Private WireGuard bytes stay
in shared Keychain and never cross provider messages.

### 3. Enrollment uses a temporary invitation-scoped control client

After bootstrap reports direct connectivity, Hub App opens a temporary Channel
client to signed `hubProHost` through the packet tunnel. That client exposes
only invitation claim, profile enrollment, public header, consume, and release
operations. It MUST NOT inherit owner permissions or expose normal Hub APIs.

The enrollment response supplies canonical Hub address/identity, Hub network
ID, allocated overlay IPv4/IPv6 addresses, and any membership grant required by
PacketTunnelExtension. Hub App verifies every returned identity against the
signed invitation and Hub key before persistence.

### 4. Commit order prevents unusable Hub records

Order:

1. validate invitation;
2. stage transaction and Keychain identities;
3. install/start bootstrap VPN profile;
4. establish direct peer and claim invitation;
5. enroll profile and read Hub header;
6. durably record enrollment in staged state;
7. replace bootstrap profile with committed membership profile and verify
   tunnel connected;
8. insert/update `Hubs.main`, wait for authenticated Hub connection, consume
   invitation, then mark local transaction committed;
9. close node/bootstrap peer and erase staged secrets no longer needed.

If remote enrollment succeeds before local completion, staged enrollment is
retained. Retry uses the same transaction and identities and MUST recover the
same membership rather than enroll another profile.

### 5. Rollback is explicit and bounded

Before remote enrollment commit, any cancellation, expiry, network failure,
signature mismatch, VPN denial, or app termination triggers best-effort remote
release plus deterministic removal of temporary peers/routes, node session,
bootstrap manager/profile, staged file, and staged Keychain items. Cleanup uses
bounded independent timeouts and does not hide the original error.

After remote enrollment commit, cleanup preserves staged recovery data but
still removes transient peer/node state. A user cancellation after commit is a
recoverable incomplete join, not silent remote membership deletion.

### 6. UI calls only the native API

Home Join Network calls `HubNets.main.join(link:)`, selects returned Hub, and
shows typed progress/errors. No `Process`, filesystem executable lookup, shell,
or CLI output parsing remains in Apple builds.

### 7. Inviting peer readiness cannot depend on overlay claim

Invitation bootstrap has a strict dependency boundary: the joiner cannot reach
`hubProHost` until rendezvous has produced a direct WireGuard peer, so preparing
the selected inviting agent for rendezvous MUST NOT require a claim sent through
that not-yet-established overlay path. Invitation issuance or another
pre-overlay mechanism SHALL arm the exact invitation-selected Apple agent with
enough transaction-scoped state to enter rendezvous. A later claim still owns
single-use enrollment state and MUST bind to the same staged joiner identity.

The implementation MUST prove this ordering with a real hub-pro-issued Apple
invitation. A fixture that independently pre-arms the inviting peer does not
cover this dependency.

### 8. Join errors preserve a safe actionable cause

Every failure boundary before and during bootstrap SHALL map its underlying
error into a bounded, single-line, user-actionable message. Sanitization MUST
remove invitation, transaction, profile, and key material, but MUST NOT replace
VPN installation, tunnel start/readiness, provider-message, rendezvous-node, or
timeout failures with the undifferentiated `Hub Network join failed` fallback.

## Risks / Tradeoffs

- Network Extension consent can interrupt join. Transaction staging precedes
  the prompt so retry is deterministic.
- One system packet tunnel conflicts with an active membership. Initial version
  SHALL reject switching from a different active Hub with an actionable error;
  it MUST NOT silently stop that VPN.
- App termination limits immediate remote release. Claim lease expiry and local
  staged recovery preserve safety.
- Pre-arming an invitation consumes bounded inviting-agent/node capacity before
  a claim exists. Expiry, cancellation, disconnect, and failed join MUST reclaim
  it without weakening single-use claim semantics.
- Cross-platform wire drift is mitigated with shared Apple/Go golden fixtures
  and signed-device acceptance.
